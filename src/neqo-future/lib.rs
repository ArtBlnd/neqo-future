use neqo_transport;

use std::time::{ Instant, Duration };

use async_std::net::*;
use async_std::sync::*;
use async_std::io;

pub struct ServerConfig {
    bind_addr: SocketAddr,

    max_stream_range: u64,

    certs: &[&str],
    alpns: &[&str],

    anti_replay_k: usize,
    anti_replay_b: usize,
}

pub struct ClientConfig {
    bind_addr: SocketAddr, 
    conn_addr: SocketAddr,

    max_stream_range: u64,

    certs: &[&str],
    alpns: &[&str],
}

struct Connection {
    quic_conn: neqo_transport::Connection,
}

impl Connection {
    pub async fn establish_server(config: &ServerConfig) -> io::Result<Connection> {
        let anti_replay = neqo_crypto::AntiReplay::new(Instant::now(), Duration::from_secs(10), config.anti_replay_k, config.anti_replay_b);

        let sock_conn = UdpSocket::bind(bind_addr)?;
        let quic_conn = neqo_transport::Connection::new_server(
            config.serts, 
            config.alpns, 
            &anti_replay, 
            neqo_transport::FixedConnectionIdManager::new(config.max_stream_range))?;
    }

    pub async fn establish_client() {

    }

    pub async fn create_stream(stream_id: u64) {
        
    }
    
    pub async fn listen_stream(stream_id: u64) {

    }
}

struct SendStream {
    stream_id: u64,
}

struct RecvStream {
    stream_id: u64,
}