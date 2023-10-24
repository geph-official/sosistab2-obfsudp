use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime},
};

use super::{listener_table::PipeTable, ObfsUdpSecret};
use crate::{
    crypt::{triple_ecdh, ObfsAead},
    frame::HandshakeFrame,
    recfilter::REPLAY_FILTER,
    ObfsUdpPipe,
};
use async_trait::async_trait;
use bytes::Bytes;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use smol::{
    channel::{Receiver, Sender},
    net::UdpSocket,
};
use sosistab2::{Pipe, PipeListener};

/// A listener for obfuscated UDP pipes.
pub struct ObfsUdpListener {
    recv_new_pipes: Receiver<ObfsUdpPipe>,
    _task: smol::Task<()>,
}

#[async_trait]
impl PipeListener for ObfsUdpListener {
    async fn accept_pipe(&self) -> std::io::Result<Arc<dyn Pipe>> {
        let pipe = self
            .accept()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::BrokenPipe, e.to_string()))?;
        Ok(Arc::new(pipe))
    }
}

impl ObfsUdpListener {
    /// Constructor.
    pub async fn bind(listen: SocketAddr, server_long_sk: ObfsUdpSecret) -> std::io::Result<Self> {
        let socket = UdpSocket::bind(listen).await?;
        let (send_new_pipes, recv_new_pipes) = smol::channel::unbounded();
        let task = smolscale::spawn(async move {
            while let Err(err) = listener_loop(
                socket.clone(),
                send_new_pipes.clone(),
                server_long_sk.clone(),
            )
            .await
            {
                log::error!("Oh no! The listener loop has died with an error {:?}", err);
                smol::Timer::after(Duration::from_secs(1)).await;
            }
        });
        Ok(Self {
            recv_new_pipes,

            _task: task,
        })
    }

    pub async fn accept(&self) -> anyhow::Result<ObfsUdpPipe> {
        let p = self.recv_new_pipes.recv().await?;
        log::debug!("ACCEPTED a pipe");
        Ok(p)
    }
}

async fn listener_loop(
    socket: UdpSocket,
    send_new_pipes: Sender<ObfsUdpPipe>,
    server_long_sk: ObfsUdpSecret,
) -> anyhow::Result<()> {
    let server_long_pk = server_long_sk.to_public();
    let c2s_key = blake3::derive_key("sosistab-2-c2s", server_long_pk.as_bytes());
    let s2c_key = blake3::derive_key("sosistab-2-s2c", server_long_pk.as_bytes());
    let c2s_outer = ObfsAead::new(&c2s_key);
    let s2c_outer = ObfsAead::new(&s2c_key);

    // make table and token key
    let mut table = PipeTable::new(socket.clone());
    let token_key = {
        let mut b = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut b);
        b
    };

    if std::env::var("SOSISTAB2_NO_SLEEP").is_err() {
        log::warn!("sleeping 60 seconds to prevent replays...");
        smol::Timer::after(Duration::from_secs(60)).await;
        log::warn!("finished sleeping 60 seconds to prevent replays!");
    }

    loop {
        let mut buf = [0u8; 2048];
        let (n, client_addr) = socket.recv_from(&mut buf).await?;
        let pkt = &buf[..n];
        log::trace!("received a pkt!");
        if let Err(err) = table.try_forward(pkt, client_addr).await {
            log::debug!("cannot forward packet from {client_addr} to an existing session ({err}), so decrypting as handshake");
            if let Err(err) = handle_server_handshake(
                &socket,
                &send_new_pipes,
                &server_long_sk,
                client_addr,
                &c2s_outer,
                &s2c_outer,
                &token_key,
                pkt,
                &mut table,
            )
            .await
            {
                log::warn!(
                    "could not handle apparent server handshake from {client_addr}: {:?}",
                    err
                )
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_server_handshake(
    socket: &UdpSocket,
    send_new_pipes: &Sender<ObfsUdpPipe>,
    server_long_sk: &ObfsUdpSecret,
    client_addr: SocketAddr,
    c2s_outer: &ObfsAead,
    s2c_outer: &ObfsAead,
    token_key: &[u8; 32],
    pkt: &[u8],
    table: &mut PipeTable,
) -> anyhow::Result<()> {
    // NOTE: we must tread carefully here to avoid responding to replayed messages, because c2s_outer does not protect against any form of replay attack. REPLAY_FILTER only protects against replays that are replayed within 10 minutes or so; beyond that we are on our own.
    // There are three cases here to consider:
    // - If it's a ClientHello, we check that the timestamp is recent. This guarantees that old packets cannot be accepted. Recent packets cannot be replayed because REPLAY_FILTER would have caught them. Note that we respond to ClientHellos with a ServerHello that includes an encrypted token.
    // - We ignore ServerHellos, since we are the server.
    // - If it's a ClientResume, we check that when the token is decrypted, the timestamp we have in the token is recent. This means that it must have been in response to a recent ServerHello, guaranteeing that the ClientResume itself is recent, which prevents replay attacks similar to the logic with ClientHello.
    let ptext = c2s_outer.decrypt(pkt)?;
    log::debug!("it really was a handshake!");
    if REPLAY_FILTER.lock().recently_seen(&ptext) {
        log::warn!("skipping packet catched by the replay filter!");
    }
    let current_timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let msg: HandshakeFrame = stdcode::deserialize(&ptext)?;
    match msg {
        HandshakeFrame::ClientHello {
            long_pk,
            eph_pk,
            version,
            timestamp,
        } => {
            log::debug!(
                "my time {current_timestamp}, their time {timestamp}, diff {}",
                current_timestamp.abs_diff(timestamp)
            );
            if current_timestamp.abs_diff(timestamp) > 60 {
                anyhow::bail!("ClientHello with skewed timestamp received")
            }

            let server_eph_sk = x25519_dalek::StaticSecret::new(rand::thread_rng());

            // make token
            let shared_secret = triple_ecdh(&server_long_sk.0, &server_eph_sk, &long_pk, &eph_pk);

            let token = TokenInfo {
                sess_key: Bytes::copy_from_slice(shared_secret.as_bytes()),
                init_time_ms: timestamp,
                version,
            };
            let encrypted_token = token.encrypt(token_key);
            let resp = HandshakeFrame::ServerHello {
                long_pk: server_long_sk.to_public().0,
                eph_pk: (&server_eph_sk).into(),
                resume_token: encrypted_token,
                client_commitment: blake3::hash(&ptext).into(),
            };
            socket
                .send_to(&s2c_outer.encrypt(&stdcode::serialize(&resp)?), client_addr)
                .await?;
            Ok(())
        }
        HandshakeFrame::ServerHello { .. } => {
            anyhow::bail!("server got server hello")
        }
        HandshakeFrame::ClientResume {
            resume_token,
            metadata,
        } => {
            let token_info = TokenInfo::decrypt(token_key, &resume_token)?;
            if token_info.init_time_ms.abs_diff(current_timestamp) > 60 {
                anyhow::bail!("ClientResume replay detected!")
            }
            let (send_upcoded, recv_upcoded) = smol::channel::unbounded();
            let (send_downcoded, recv_downcoded) = smol::channel::unbounded();
            // mix the metadata with the session key
            let real_session_key = blake3::keyed_hash(
                blake3::hash(metadata.as_bytes()).as_bytes(),
                &token_info.sess_key,
            );
            table.add_entry(
                client_addr,
                recv_upcoded,
                send_downcoded,
                real_session_key.as_bytes(),
            );
            log::debug!(
                "SERVER shared_secret: {:?}",
                hex::encode(token_info.sess_key)
            );
            let pipe = ObfsUdpPipe::with_custom_transport(
                recv_downcoded,
                send_upcoded,
                client_addr,
                &metadata,
            );
            let _ = send_new_pipes.try_send(pipe);
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TokenInfo {
    sess_key: Bytes,
    init_time_ms: u64,
    version: u64,
}

impl TokenInfo {
    fn decrypt(key: &[u8], encrypted: &[u8]) -> anyhow::Result<Self> {
        // first we decrypt
        let crypter = ObfsAead::new(key);
        let plain = crypter.decrypt(encrypted)?;
        let ctext = stdcode::deserialize::<Self>(&plain)?;
        Ok(ctext)
    }

    fn encrypt(&self, key: &[u8]) -> Bytes {
        let crypter = ObfsAead::new(key);
        crypter.encrypt(&stdcode::serialize(self).expect("must serialize"))
    }
}
