use anyhow::Context;

use parking_lot::RwLock;
use smol::{
    channel::{Receiver, Sender},
    net::UdpSocket,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use crate::crypt::{dnify_shared_secret, upify_shared_secret, ObfsAead};

use super::{
    crypt::{CounterDecrypter, CounterEncrypter},
    frame::ObfsUdpFrame,
};

pub struct PipeTable {
    table: Arc<RwLock<HashMap<SocketAddr, PipeBack>>>,
    socket: UdpSocket,
}

#[derive(Clone)]
struct PipeBack {
    send_downcoded: Sender<ObfsUdpFrame>,
    decrypter: CounterDecrypter,

    _task: Arc<smol::Task<anyhow::Result<()>>>,
}

impl PipeTable {
    /// Constructor.
    pub fn new(socket: UdpSocket) -> Self {
        Self {
            table: Default::default(),
            socket,
        }
    }
    /// Adds a new entry to the table.
    pub fn add_entry(
        &mut self,
        client_addr: SocketAddr,
        recv_upcoded: Receiver<ObfsUdpFrame>,
        send_downcoded: Sender<ObfsUdpFrame>,
        sess_key: &[u8],
    ) {
        let up_key = upify_shared_secret(sess_key);
        let dn_key = dnify_shared_secret(sess_key);
        let encrypter = CounterEncrypter::new(ObfsAead::new(dn_key.as_bytes()));
        let decrypter = CounterDecrypter::new(ObfsAead::new(up_key.as_bytes()));

        // start down-forwarding actor
        let task = smolscale::spawn(dn_forward_loop(
            self.table.clone(),
            self.socket.clone(),
            client_addr,
            encrypter,
            recv_upcoded,
        ));

        let pipe_back = PipeBack {
            send_downcoded,
            decrypter,

            _task: Arc::new(task),
        };
        self.table.write().insert(client_addr, pipe_back);
    }

    /// Attempts to decode and forward the packet to an existing pipe. If
    pub fn try_forward(&mut self, pkt: &[u8], client_addr: SocketAddr) -> anyhow::Result<()> {
        let table = self.table.read();
        let back = table
            .get(&client_addr)
            .context("no entry in the table with this client_addr")?;
        if let Ok(msg) = back.decrypter.decrypt(pkt) {
            let _ = back.send_downcoded.try_send(msg);
            Ok(())
        } else {
            anyhow::bail!("cannot decrypt incoming")
        }
    }
}

async fn dn_forward_loop(
    table: Arc<RwLock<HashMap<SocketAddr, PipeBack>>>,
    socket: UdpSocket,
    client_addr: SocketAddr,
    encrypter: CounterEncrypter,
    recv_upcoded: Receiver<ObfsUdpFrame>,
) -> anyhow::Result<()> {
    scopeguard::defer!({
        table.write().remove(&client_addr);
    });
    loop {
        let msg = recv_upcoded.recv().await?;
        let ctext = encrypter.encrypt(&msg);
        let _ = socket.send_to(&ctext, client_addr).await;
    }
}
