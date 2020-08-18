pub mod client;
pub mod server;

use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Debug;
use std::io::{Error, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_std::future;
use async_std::net::UdpSocket;
use async_std::sync::Mutex as AsyncMutex;
use async_std::sync::{channel, Receiver, RecvError, Sender};
use async_std::task::*;

use neqo_common::Datagram;
use neqo_transport;

use futures::io::{AsyncRead, AsyncWrite};

pub type Version = neqo_transport::QuicVersion;

#[derive(Debug)]
pub enum QuicError {
    NeqoError(neqo_transport::Error),
    IoError(std::io::Error),
    FatalError(Box<dyn Any + Send>),
}

impl From<std::io::Error> for QuicError {
    fn from(e: std::io::Error) -> Self {
        QuicError::IoError(e)
    }
}

impl From<neqo_transport::Error> for QuicError {
    fn from(e: neqo_transport::Error) -> Self {
        QuicError::NeqoError(e)
    }
}

impl From<Box<dyn Any + Send>> for QuicError {
    fn from(e: Box<dyn Any + Send>) -> Self {
        QuicError::FatalError(e)
    }
}

unsafe impl Send for Connection {}
unsafe impl Sync for Connection {}
unsafe impl Send for InternalConnection {}
unsafe impl Sync for InternalConnection {}

pub struct Connection {
    socket: Arc<UdpSocket>,

    src_addr: SocketAddr,
    dst_addr: SocketAddr,

    data_tx: Sender<Option<Vec<u8>>>,
    data_rx: Receiver<Option<Vec<u8>>>,

    strm_tx: Sender<Option<u64>>,
    strm_rx: Receiver<Option<u64>>,

    internal: Arc<Mutex<InternalConnection>>,
}

impl Clone for Connection {
    fn clone(&self) -> Self {
        Connection {
            socket: self.socket.clone(),
            src_addr: self.src_addr.clone(),
            dst_addr: self.dst_addr.clone(),
            strm_tx: self.strm_tx.clone(),
            strm_rx: self.strm_rx.clone(),
            data_tx: self.data_tx.clone(),
            data_rx: self.data_rx.clone(),
            internal: self.internal.clone(),
        }
    }
}

impl Connection {
    pub fn get_src_addr(&self) -> SocketAddr {
        self.src_addr
    }

    pub fn get_dst_addr(&self) -> SocketAddr {
        self.dst_addr
    }

    pub fn is_established(&self) -> bool {
        let internal = self.internal.lock().unwrap();

        if let neqo_transport::State::Connected = internal.quic.state() {
            return true;
        }
        return false;
    }

    pub fn try_send_packet(&self, packet: Option<Vec<u8>>) -> bool {
        self.data_tx.try_send(packet).is_ok()
    }

    pub async fn send_packet(&self, packet: Option<Vec<u8>>) {
        self.data_tx.send(packet).await;
    }

    pub async fn recv_packet(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Option<Vec<u8>>, RecvError> {
        if let Some(timeout) = timeout {
            if let Ok(result) = future::timeout(timeout, self.data_rx.recv()).await {
                return result;
            }

            return Ok(None);
        } else {
            return self.data_rx.recv().await;
        }
    }

    pub async fn create_stream_half(&self) -> Option<QuicSendStream> {
        if let Ok(stream_id) = self
            .internal
            .lock()
            .unwrap()
            .quic
            .stream_create(neqo_transport::StreamType::UniDi)
        {
            return Some(self.generate_stream(stream_id).0);
        }

        return None;
    }

    pub async fn create_stream_full(&self) -> Option<(QuicSendStream, QuicRecvStream)> {
        if let Ok(stream_id) = self
            .internal
            .lock()
            .unwrap()
            .quic
            .stream_create(neqo_transport::StreamType::BiDi)
        {
            return Some(self.generate_stream(stream_id));
        }

        return None;
    }

    pub async fn listen_stream(&self) -> Option<(QuicSendStream, QuicRecvStream)> {
        if let Ok(Some(stream_id)) = self.strm_rx.recv().await {
            return Some(self.generate_stream(stream_id));
        }

        return None;
    }

    pub fn close(&self, error: u64, msg: &str) {
        let mut internal = self.internal.lock().unwrap();
        internal.quic.close(Instant::now(), error, msg);
    }

    fn auth_ok(&self) {
        let mut internal = self.internal.lock().unwrap();

        assert!(internal.quic.role() != neqo_common::Role::Server);
        internal
            .quic
            .authenticated(neqo_crypto::AuthenticationStatus::Ok, Instant::now());
    }

    fn generate_stream(&self, stream_id: u64) -> (QuicSendStream, QuicRecvStream) {
        let send_strm = QuicSendStream {
            send_closed: false,

            stream_id,
            conn: self.clone(),
            error_code: Default::default(),
        };

        let recv_strm = QuicRecvStream {
            stream_id,
            conn: self.clone(),
            error_code: Default::default(),
        };

        return (send_strm, recv_strm);
    }

    async fn process(&self, packet: Option<Vec<u8>>) -> Option<Duration> {
        let mut outputs = Vec::new();
        let timeout;
        {
            let mut internal = self.internal.lock().unwrap();
            if let Some(packet) = packet {
                internal.quic.process_input(
                    Datagram::new(self.dst_addr, self.src_addr, packet),
                    Instant::now(),
                );
            }

            loop {
                match internal.quic.process_output(Instant::now()) {
                    neqo_transport::Output::None => {
                        timeout = None;
                        break;
                    }

                    neqo_transport::Output::Callback(duration) => {
                        timeout = Some(duration);
                        break;
                    }

                    neqo_transport::Output::Datagram(datagram) => {
                        outputs.push(datagram);
                    }
                }
            }
        }

        for packet in outputs {
            self.socket
                .send_to(&packet, packet.destination())
                .await
                .expect("failed to send packet to socket!");
        }

        return timeout;
    }

    async fn get_events(&self) -> impl Iterator<Item = neqo_transport::ConnectionEvent> {
        let mut internal = self.internal.lock().unwrap();
        internal.quic.events()
    }

    async fn wake_send_stream(&self, stream_id: u64) {
        let mut internal = self.internal.lock().unwrap();
        if let Some(waker) = internal.send_op_wakers.remove(&stream_id) {
            waker.wake();
        }
    }

    async fn wake_recv_stream(&self, stream_id: u64) {
        let mut internal = self.internal.lock().unwrap();
        if let Some(waker) = internal.recv_op_wakers.remove(&stream_id) {
            waker.wake();
        }
    }

    async fn internal_cleanup(&self) {
        let mut internal = self.internal.lock().unwrap();

        for (_, waker) in internal.send_op_wakers.drain() {
            waker.wake();
        }

        for (_, waker) in internal.recv_op_wakers.drain() {
            waker.wake();
        }
    }

    fn stream_send_op(
        &self,
        stream_id: u64,
        waker: Waker,
        buffer: &[u8],
    ) -> Result<usize, std::io::Error> {
        let mut internal = self.internal.lock().unwrap();
        match internal.quic.stream_send(stream_id, buffer) {
            Ok(len) => {
                if len == 0 {
                    internal.send_op_wakers.insert(stream_id, waker);
                    return Err(Error::new(ErrorKind::WouldBlock, "operation would block"));
                }

                self.try_send_packet(None);
                return Ok(len);
            }
            Err(e) => {
                if let neqo_transport::Error::InvalidStreamId
                | neqo_transport::Error::FinalSizeError = e
                {
                    return Err(Error::new(ErrorKind::BrokenPipe, "bad stream id!"));
                }
            }
        }

        unreachable!();
    }

    fn stream_recv_op(
        &self,
        stream_id: u64,
        waker: Waker,
        buffer: &mut [u8],
    ) -> Result<usize, std::io::Error> {
        let mut internal = self.internal.lock().unwrap();
        match internal.quic.stream_recv(stream_id, buffer) {
            Ok((len, _)) => {
                if len == 0 {
                    internal.recv_op_wakers.insert(stream_id, waker);
                    return Err(Error::new(ErrorKind::WouldBlock, "operation would block"));
                }

                self.try_send_packet(None);
                return Ok(len);
            }
            Err(e) => {
                if let neqo_transport::Error::InvalidStreamId | neqo_transport::Error::NoMoreData =
                    e
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "bad stream id!",
                    ));
                }
            }
        }

        unreachable!();
    }

    fn stream_close(&self, stream_id: u64, waker: Waker) {
        let mut internal = self.internal.lock().unwrap();
        if let Err(neqo_transport::Error::InvalidStreamId) =
            internal.quic.stream_close_send(stream_id)
        {
            waker.wake_by_ref();
        }
    }

    fn stream_reset(&self, stream_id: u64, error: u64) {
        let mut internal = self.internal.lock().unwrap();
        internal.quic.stream_reset_send(stream_id, error).unwrap();
    }
}

struct InternalConnection {
    quic: neqo_transport::Connection,

    send_op_wakers: HashMap<u64, Waker>,
    recv_op_wakers: HashMap<u64, Waker>,
}

pub struct QuicSendStream {
    send_closed: bool,

    stream_id: u64,
    conn: Connection,

    error_code: Arc<Mutex<Option<u64>>>,
}

pub struct QuicRecvStream {
    stream_id: u64,
    conn: Connection,

    error_code: Arc<Mutex<Option<u64>>>,
}

impl QuicSendStream {
    pub fn get_stream_id(&self) -> u64 {
        self.stream_id
    }

    pub async fn get_error_code(&self) -> Option<u64> {
        *self.error_code.lock().unwrap()
    }
}

impl AsyncWrite for QuicSendStream {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let result = match self
            .conn
            .stream_send_op(self.stream_id, ctx.waker().clone(), buf)
        {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                return Poll::Pending;
            }

            v => v,
        };

        return Poll::Ready(result);
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Error>> {
        unimplemented!("quic does not implements flush!");
    }

    fn poll_close(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        if self.send_closed {
            return Poll::Ready(Ok(()));
        }

        self.conn.stream_close(self.stream_id, ctx.waker().clone());
        self.get_mut().send_closed = true;

        return Poll::Pending;
    }
}

impl QuicSendStream {
    pub fn reset(&mut self, error: u64) {
        self.send_closed = true;
        self.conn.stream_reset(self.stream_id, error);
    }
}

impl QuicRecvStream {
    pub fn get_stream_id(&self) -> u64 {
        self.stream_id
    }

    pub async fn get_error_code(&self) -> Option<u64> {
        *self.error_code.lock().unwrap()
    }
}

impl AsyncRead for QuicRecvStream {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize, Error>> {
        let result = match self
            .conn
            .stream_recv_op(self.stream_id, ctx.waker().clone(), buf)
        {
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                return Poll::Pending;
            }

            v => v,
        };

        return Poll::Ready(result);
    }
}

impl QuicRecvStream {
    pub fn reset(&mut self, error: u64) {
        self.conn.stream_reset(self.stream_id, error);
    }
}

async fn dispatch_event(
    connection: &Connection,
    event: neqo_transport::ConnectionEvent,
) -> Result<(), Option<u64>> {
    match event {
        neqo_transport::ConnectionEvent::AuthenticationNeeded => {
            connection.auth_ok();
            log::info!("neqo-future | authentication requested");
        }

        // Peer has created new stream.
        neqo_transport::ConnectionEvent::NewStream { stream_id } => {
            let stream_id = stream_id.as_u64();
            connection.strm_tx.send(Some(stream_id)).await;
            log::info!("neqo-future | new stream (stream_id = {})", stream_id);
        }

        // If we have registered waker on table.
        neqo_transport::ConnectionEvent::SendStreamWritable { stream_id } => {
            let stream_id = stream_id.as_u64();

            connection.wake_send_stream(stream_id).await;
            log::info!("neqo-future | stream writable (stream_id = {})", stream_id);
        }
        neqo_transport::ConnectionEvent::RecvStreamReadable { stream_id } => {
            connection.wake_recv_stream(stream_id).await;
            log::info!("neqo-future | stream readable (stream_id = {})", stream_id);
        }

        // We've closed stream and sent all data.
        neqo_transport::ConnectionEvent::SendStreamComplete { stream_id } => {
            connection.wake_send_stream(stream_id).await;
            log::info!("neqo-future | stream complate (stream_id = {})", stream_id);
        }

        // Peer has requested closed.
        neqo_transport::ConnectionEvent::RecvStreamReset { stream_id, .. } => {
            // We have to notify this is closed.
            connection.wake_recv_stream(stream_id).await;
            connection.wake_send_stream(stream_id).await;
            log::info!("neqo-future | stream resetted (stream_id = {})", stream_id);
        }
        neqo_transport::ConnectionEvent::SendStreamStopSending { stream_id, .. } => {
            connection.wake_send_stream(stream_id).await;
            log::info!("neqo-future | stream stop send (stream_id = {})", stream_id);
        }

        neqo_transport::ConnectionEvent::StateChange(state) => {
            log::info!("neqo-future | state changed => {:?}", state);
            if let neqo_transport::State::Closing { .. } = &state {
                // Seems peer has been closed.
                // so we are in closing state do not create more streams.
                connection.strm_tx.send(None).await;
            }

            if let neqo_transport::State::Closed(err) = &state {
                return Err(err.app_code());
            }

            connection.process(None).await;
        }

        _ => {}
    }

    return Ok(());
}

async fn dispatch_conn(connection: Connection) -> Option<u64> {
    let mut timeout = connection.process(None).await;

    let mut result = None;
    'main: while let Ok(buf) = connection.recv_packet(timeout).await {
        timeout = connection.process(buf).await;

        for event in connection.get_events().await {
            if let Err(err_code) = dispatch_event(&connection, event).await {
                result = err_code;
                break 'main;
            }
        }
    }

    // wake all stream wakers and cleans up.
    connection.internal_cleanup().await;
    return result;
}
