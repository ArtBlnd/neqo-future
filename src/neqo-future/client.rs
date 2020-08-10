use crate::*;

pub struct ClientConfig {
    pub bind_addr: SocketAddr,

    pub max_stream_range: usize,
    pub send_buf_len: usize,
    pub recv_buf_len: usize,

    pub server_name: String,

    pub certs: Vec<&'static str>,
    pub alpns: Vec<&'static str>,

    pub version: Version,
}

impl Connection {
    fn configure_client(
        config: &ClientConfig,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        sock_conn: Arc<UdpSocket>,
    ) -> Result<Connection, QuicError> {
        let quic_conn = neqo_transport::Connection::new_client(
            &config.server_name,
            &config.alpns,
            Rc::new(RefCell::new(neqo_transport::FixedConnectionIdManager::new(
                config.max_stream_range,
            ))),
            src_addr,
            dst_addr,
            config.version,
        )?;

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
}

async fn dispatch_sock(connection: Connection, config: ClientConfig, socket: Arc<UdpSocket>) {
    // reserve receive buffer
    let mut buf = Vec::new();
    buf.resize(config.recv_buf_len, 0);

    log::info!("neqo-future | start receiving packets from socket!");

    while let Ok(len) = socket.recv(&mut buf).await {
        connection.data_tx.send(Some(buf[..len].to_vec())).await;
    }

    log::info!("neqo-future | stopped receiving packets from socket!");
}

pub async fn connect(
    conn_addr: SocketAddr,
    config: ClientConfig,
) -> Result<(JoinHandle<Option<u64>>, Connection), QuicError> {
    let socket = Arc::new(UdpSocket::bind(config.bind_addr).await?);
    let conn = Connection::configure_client(&config, config.bind_addr, conn_addr, socket.clone())?;

    log::info!("neqo-future | connecting to {}", conn_addr);

    spawn(dispatch_sock(conn.clone(), config, socket));
    return Ok((spawn(dispatch_conn(conn.clone())), conn));
}
