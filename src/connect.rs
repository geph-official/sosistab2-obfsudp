use std::{
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::Context;
use smol::{
    channel::{Receiver, Sender},
    future::FutureExt,
    net::UdpSocket,
};
use smol_timeout::TimeoutExt;
use stdcode::StdcodeSerializeExt;

use crate::{
    crypt::{
        dnify_shared_secret, triple_ecdh, upify_shared_secret, ObfsAead, ObfsDecrypter,
        ObfsEncrypter,
    },
    frame::{HandshakeFrame, ObfsUdpFrame},
    ObfsUdpPipe, ObfsUdpPublic,
};

pub async fn client_connect(
    server_addr: SocketAddr,
    server_pk: ObfsUdpPublic,
    metadata: &str,
) -> anyhow::Result<ObfsUdpPipe> {
    let mut timeout = Duration::from_secs(3);
    loop {
        let attempt = async {
            let addr = if server_addr.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            }
            .parse::<SocketAddr>()
            .unwrap();
            let socket = smol::net::UdpSocket::bind(addr)
                .await
                .context("could not bind udp socket")?;

            // do the handshake
            // generate pk-sk pairs for encryption after the session is established
            let my_long_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
            let my_eph_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());
            let cookie = server_pk.as_bytes();
            // construct the ClientHello message
            let client_hello_plain = HandshakeFrame::ClientHello {
                long_pk: (&my_long_sk).into(),
                eph_pk: (&my_eph_sk).into(),
                version: 4,
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            }
            .stdcode();
            // encrypt the ClientHello message
            let init_enc = ObfsAead::new(&blake3::derive_key("sosistab-2-c2s", cookie));
            let client_hello = init_enc.encrypt(&client_hello_plain);
            // send the ClientHello
            socket.send_to(&client_hello, server_addr).await?;

            // wait for the server's response
            let mut ctext_resp = [0u8; 2048];
            let (n, _) = socket
                .recv_from(&mut ctext_resp)
                .await
                .context("can't read response from server")?;
            let ctext_resp = &ctext_resp[..n];
            // decrypt the server's response
            let init_dec = ObfsAead::new(&blake3::derive_key("sosistab-2-s2c", cookie));
            let ptext_resp = init_dec.decrypt(ctext_resp)?;
            let deser_resp: HandshakeFrame = stdcode::deserialize(&ptext_resp)?;
            if let HandshakeFrame::ServerHello {
                long_pk,
                eph_pk,
                resume_token,
                client_commitment,
            } = deser_resp
            {
                if blake3::Hash::from(client_commitment) != blake3::hash(&client_hello_plain) {
                    anyhow::bail!("the two hellos don't match")
                }
                log::trace!("***** server hello received, calculating stuff ******");
                // finish off the handshake
                let client_resp = init_enc.encrypt(
                    &HandshakeFrame::Finalize {
                        resume_token,
                        metadata: metadata.into(),
                    }
                    .stdcode(),
                );
                socket.send_to(&client_resp, server_addr).await?;

                // create a pipe
                let (send_upcoded, recv_upcoded) = smol::channel::bounded(1000);
                let (send_downcoded, recv_downcoded) = smol::channel::bounded(1000);
                let pipe = ObfsUdpPipe::with_custom_transport(
                    recv_downcoded,
                    send_upcoded,
                    server_addr,
                    metadata,
                );

                // start background encrypting/decrypting + forwarding task
                let shared_secret = triple_ecdh(&my_long_sk, &my_eph_sk, &long_pk, &eph_pk);
                log::trace!("CLIENT shared_secret: {:?}", shared_secret);
                let real_sess_key = blake3::keyed_hash(
                    blake3::hash(metadata.as_bytes()).as_bytes(),
                    shared_secret.as_bytes(),
                );
                smolscale::spawn(client_loop(
                    recv_upcoded,
                    send_downcoded,
                    socket,
                    server_addr,
                    real_sess_key,
                ))
                .detach();

                Ok(pipe)
            } else {
                anyhow::bail!("server sent unrecognizable message")
            }
        };

        match attempt.timeout(timeout).await {
            Some(val) => return val,
            None => {
                log::debug!(
                    "connect attempt to {server_addr} timed out after {:?}, retrying!",
                    timeout
                );
                timeout = (timeout * 2).min(Duration::from_secs(600))
            }
        }
    }
}

pub async fn client_loop(
    recv_upcoded: Receiver<ObfsUdpFrame>,
    send_downcoded: Sender<ObfsUdpFrame>,
    socket: UdpSocket,
    server_addr: SocketAddr,
    shared_secret: blake3::Hash,
) -> anyhow::Result<()> {
    let up_key = upify_shared_secret(shared_secret.as_bytes());
    let dn_key = dnify_shared_secret(shared_secret.as_bytes());
    let enc = ObfsEncrypter::new(ObfsAead::new(up_key.as_bytes()));
    let dec = ObfsDecrypter::new(ObfsAead::new(dn_key.as_bytes()));

    let socket_up = socket.clone();
    let up_loop = async move {
        loop {
            let msg = recv_upcoded.recv().await.context("death in UDP up loop")?;

            let enc_msg = enc.encrypt(&msg);
            if let Err(err) = socket_up.send_to(&enc_msg, server_addr).await {
                log::error!("cannot send message: {:?}", err)
            }
        }
    };
    let dn_loop = async move {
        let mut buf = [0u8; 65536];
        loop {
            let frame_fut = async {
                let (n, _) = socket.recv_from(&mut buf).await?;
                log::trace!("got {} bytes from server", n);
                let dn_msg = &buf[..n];
                let dec_msg = dec.decrypt(dn_msg)?;
                anyhow::Ok(dec_msg)
            };
            match frame_fut.await {
                Err(err) => {
                    log::error!("cannot recv message: {:?}", err)
                }
                Ok(deser_msg) => {
                    send_downcoded
                        .send(deser_msg)
                        .await
                        .context("death in UDP down loop")?;
                }
            }
        }
    };

    smolscale::spawn(up_loop)
        .race(smolscale::spawn(dn_loop))
        .await
}
