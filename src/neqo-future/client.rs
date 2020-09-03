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

async fn dispatch_sock(conn: Connection, config: ClientConfig) {
    // reserve receive buffer
    let mut buf = Vec::new();
    buf.resize(config.recv_buf_len, 0);

    while let Ok(len) = conn.socket.recv(&mut buf).await {
        conn.data_tx.send(Some(buf[..len].to_vec())).await;
    }
}

pub async fn connect(
    conn_addr: SocketAddr,
    config: ClientConfig,
) -> Result<(ConnectionHandle, Connection), QuicError> {
    let socket = Arc::new(UdpSocket::bind(config.bind_addr).await?);
    let quic_conn =
        Connection::configure_client(&config, config.bind_addr, conn_addr, socket.clone())?;

    log::info!("neqo-future | connecting to {}", conn_addr);

    let sock_task = Some(spawn(dispatch_sock(quic_conn.clone(), config)));

    // wait for established.
    let mut timeout = quic_conn.process(None).await;
    while let Ok(buf) = quic_conn.recv_packet(timeout).await {
        timeout = quic_conn.process(buf).await;
        for event in quic_conn.get_events() {
            dispatch_event(&quic_conn, event).await.unwrap();
        }

        let state = quic_conn.state();
        if state.closed() {
            return Err(QuicError::NeqoError(
                neqo_transport::Error::ConnectionRefused,
            ));
        } else if state.connected() {
            break;
        }
    }

    let quic_task = Some(spawn(dispatch_conn(quic_conn.clone())));
    return Ok((
        ConnectionHandle {
            sock_task,
            quic_task,
        },
        quic_conn,
    ));
}
