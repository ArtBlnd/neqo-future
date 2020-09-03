use neqo_future::*;

use async_std::io;
use async_std::task;

use futures::prelude::*;

use simplelog::*;

async fn read_and_print(mut rx: QuicRecvStream) {
    let mut buf = [0u8; 4096];
    while let Ok(len) = rx.read(&mut buf).await {
        std::print!("{}", std::str::from_utf8(&buf[..len]).unwrap());
    }
}

fn main() {
    SimpleLogger::init(LevelFilter::Warn, Config::default()).expect("failed to init logger!");

    neqo_crypto::init_db("/Users/jujunryoung/Desktop/neqo-future/assets/");

    let alpns = ["neqo-future".to_string()].to_vec();
    let certs = ["NeqoFutureCert".to_string()].to_vec();

    let config = client::ClientConfig {
        bind_addr: "0.0.0.0:0".parse().unwrap(),
        server_name: "neqo.future".to_string(),

        alpns,
        certs,

        max_stream_range: 10,
        recv_buf_len: 1440,
        send_buf_len: 1440,

        version: Version::Draft29,
    };

    task::block_on(async {
        let mut line = String::new();

        let stdin = io::stdin();

        std::print!("wait to be connected...");
        let (_, connection) = client::connect("127.0.0.1:8888".parse().unwrap(), config)
            .await
            .expect("failed to connect");
        std::println!("established!");

        let (mut tx, rx) = connection
            .create_stream_full()
            .expect("failed to create stream");

        task::spawn(read_and_print(rx));

        loop {
            stdin
                .read_line(&mut line)
                .await
                .expect("failed to read line");
            tx.write_all(line.as_bytes())
                .await
                .expect("failed to write buffer");
            line.clear();
        }
    });
}
