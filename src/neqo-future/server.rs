use crate::*;

#[allow(dead_code)]
pub struct ServerConfig {
    pub max_stream_range: usize,

    pub certs: Vec<&'static str>,
    pub alpns: Vec<&'static str>,

    pub send_buf_len: usize,
    pub recv_buf_len: usize,

    // NOTE : WARNING!!! zero-rtt may cause UB if NSPR API is using Connection object on another thread!!
    //        Do not use it before neqo supports Send trait to Connection.
    //        currently, neqo-future does not support zero-rtt server.
    // enable_zero_rtt: bool,
    // anti_replay_k: usize,
    // anti_replay_b: usize,
    // anti_replay_dur: Duration,
    pub version: Version,
}

impl Connection {
    fn configure_server(
        config: &ServerConfig,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        sock_conn: Arc<UdpSocket>,
    ) -> Result<Connection, QuicError> {
        let quic_conn = neqo_transport::Connection::new_server(
            &config.certs,
            &config.alpns,
            Rc::new(RefCell::new(neqo_transport::FixedConnectionIdManager::new(
                config.max_stream_range,
            ))),
            config.version,
        )
        .unwrap();

        let internal = Arc::new(Mutex::new(InternalConnection {
            quic: quic_conn,

            send_op_wakers: Default::default(),
            recv_op_wakers: Default::default(),
        }));

        let (strm_tx, strm_rx) = channel(1);
        let (data_tx, data_rx) = channel(1);
        return Ok(Connection {
            socket: sock_conn.clone(),
            src_addr,
            dst_addr,
            strm_tx,
            strm_rx,
            data_tx,
            data_rx,
            internal,
        });
    }

    // we don't support zero-rtt for now.
    // fn configure_0rtt(&self, config: &ServerConfig, anti_replay: &neqo_crypto::AntiReplay) {
    //     let mut internal = self.internal.try_lock().unwrap();
    //     internal.quic.server_enable_0rtt(anti_replay, neqo_crypto::AllowZeroRtt { }).expect("failed to configure zero-rtt!");
    // }
}

pub struct Listener {
    conn_rx: Receiver<(JoinHandle<Option<u64>>, Connection)>,
    dispatch_task: JoinHandle<()>,
}

impl Listener {
    pub async fn stop(self) {
        self.dispatch_task.cancel().await;
    }
}

impl Listener {
    pub async fn new(bind_addr: SocketAddr, config: ServerConfig) -> Result<Listener, QuicError> {
        let (conn_tx, conn_rx) = channel(1);

        let handle = spawn(dispatch_sock(
            config,
            Arc::new(UdpSocket::bind(bind_addr).await?),
            conn_tx,
        ));
        Ok(Listener {
            conn_rx,
            dispatch_task: handle,
        })
    }

    pub async fn listen(&self) -> Option<(JoinHandle<Option<u64>>, Connection)> {
        if let Ok(v) = self.conn_rx.recv().await {
            return Some(v);
        }

        return None;
    }
}

// This function helps removing connection from table after dispatching task is terminated.
// make sure target task is not canceled.
async fn wait_and_remove(
    handle: JoinHandle<Option<u64>>,
    conn_table: Arc<AsyncMutex<HashMap<SocketAddr, Connection>>>,
    addr: SocketAddr,
) -> Option<u64> {
    let result = handle.await;
    conn_table.lock().await.remove(&addr);

    return result;
}

async fn dispatch_sock(
    config: ServerConfig,
    sock_conn: Arc<UdpSocket>,
    conn_tx: Sender<(JoinHandle<Option<u64>>, Connection)>,
) {
    // reserve receive buffer
    let mut buf = Vec::new();
    buf.resize(config.recv_buf_len, 0);

    // connection table.
    let conn_table = Arc::new(AsyncMutex::new(HashMap::new()));
    while let Ok((len, addr)) = sock_conn.recv_from(&mut buf).await {
        let mut table = conn_table.lock().await;

        if !table.contains_key(&addr) {
            let conn = Connection::configure_server(
                &config,
                sock_conn.local_addr().unwrap(),
                addr,
                sock_conn.clone(),
            )
            .expect("failed to create connection!");

            // we are using spawn_local before neqo supports Send trait for Connection objects
            // the task can be unbiased but still better than single threaded task.
            let handle = spawn(wait_and_remove(
                spawn(dispatch_conn(conn.clone())),
                conn_table.clone(),
                addr,
            ));

            conn_tx.send((handle, conn.clone())).await;
            table.insert(addr, conn);
        }

        table
            .get(&addr)
            .unwrap()
            .send_packet(Some(buf[..len].to_vec()))
            .await;
    }
}
