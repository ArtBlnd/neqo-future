use neqo_future::*;

use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;

use async_std::task;
use async_std::sync::Mutex;

use futures::prelude::*;

use simplelog::*;

async fn async_chat_writter(table: Arc<Mutex<HashMap<SocketAddr, QuicSendStream>>>, mut rx: QuicRecvStream, addr: SocketAddr) {
    let mut buf = [0u8; 4096];
    while let Ok(len) = rx.read(&mut buf).await {
        let data_str = format!("{}: {}", addr, std::str::from_utf8(&buf[..len]).unwrap());
        std::print!("{}", data_str);
        let mut senders = table.lock().await;

        let mut should_removed = Vec::new();
        for (tx_addr, tx_strm) in senders.iter_mut() {
            if tx_addr == &addr { continue; }
            if let Err(_) = tx_strm.write_all(data_str.as_bytes()).await {
                should_removed.push(tx_addr.clone());
            }
        }

        for tx_addr in should_removed {
            senders.remove(&tx_addr);
        }
    }
}

fn main() {
    SimpleLogger::init(LevelFilter::Warn, Config::default())
        .expect("failed to init logger!");

    neqo_crypto::init_db("/Users/jujunryoung/Desktop/neqo-future/assets/");

    let alpns = ["neqo-future"].to_vec();
    let certs = ["NeqoFutureCert"].to_vec();

    let config = server::ServerConfig {
        alpns,
        certs,

        max_stream_range: 10,
        recv_buf_len: 1440,
        send_buf_len: 1440,

        version: Version::Draft29
    };

    let write_streams = Arc::new(Mutex::new(HashMap::new()));
    task::block_on(async move{
        let listener = server::Listener::new("0.0.0.0:8888".parse().unwrap(), config).await
            .expect("failed to create quic listener!");

        while let Some((_, connection)) = listener.listen().await {
            let (tx, rx) = connection.listen_stream().await.unwrap();
            write_streams.lock().await.insert(connection.get_dst_addr(), tx);

            task::spawn(async_chat_writter(write_streams.clone(), rx, connection.get_dst_addr()));
        }
    });
}