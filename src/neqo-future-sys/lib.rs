use neqo_future::*;

use std::cell::RefCell;
use std::ffi::CStr;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::thread::LocalKey;

use async_std::task;

use futures::{AsyncReadExt, AsyncWriteExt};
use libc::c_char;

type ConnectionInfo = (ConnectionHandle, Connection);

pub enum StreamInfo {
    FullStream(QuicSendStream, QuicRecvStream),
    HalfStreamSend(QuicSendStream),
    HalfStreamRecv(QuicRecvStream),
}

pub unsafe fn to_string(p_str: *const c_char) -> String {
    String::from_utf8_unchecked(CStr::from_ptr(p_str).to_bytes().to_vec())
}

// ------------------------------
// ERROR HELPERS
// ------------------------------
#[no_mangle]
unsafe fn qf_last_error() -> &'static LocalKey<RefCell<Option<QuicError>>> {
    thread_local! {
        pub static THREAD_ERROR: RefCell<Option<QuicError>> = RefCell::new(None)
    }

    return &THREAD_ERROR;
}

unsafe fn qf_pop_error() {
    qf_last_error().with(|e| {
        let mut emut = e.borrow_mut();
        *emut = None;
    });
}

unsafe fn qf_set_error(error: QuicError) {
    qf_last_error().with(|e| {
        let mut emut = e.borrow_mut();

        assert!(emut.is_some(), "bad error state!");
        *emut = Some(error);
    });
}

#[no_mangle]
pub unsafe extern "C" fn qf_format_last_error(buf: *mut u8, len: usize) -> usize {
    let mut result = String::new();
    qf_last_error().with(|e| result = format!("error = {:?}", e));

    if result.len() < len {
        return result.len();
    }

    let slice = std::slice::from_raw_parts_mut(buf, len);
    slice[..result.len()].copy_from_slice(result.as_bytes());

    return 0;
}

// ------------------------------
// CONFIG HELPERS
// ------------------------------
#[no_mangle]
pub unsafe extern "C" fn qf_create_client_config(bind_addr: *const c_char) -> Option<Box<client::ClientConfig>> {
    let bind_addr = to_string(bind_addr);

    return match catch_unwind(|| {
        Box::new(client::ClientConfig {
            bind_addr: bind_addr.parse().unwrap(),
            max_stream_range: 1000,
            send_buf_len: 1360,
            recv_buf_len: 1360,
            server_name: "".to_string(),
            certs: Vec::new(),
            alpns: Vec::new(),
            version: Version::Draft29
        })
    }) {
        Ok(v) => Some(v),
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return None;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_set_server_name(config: &mut client::ClientConfig, sni: *const c_char) {
    config.server_name = to_string(sni);
}

#[no_mangle]
pub unsafe extern "C" fn qf_add_cert(config: &mut client::ClientConfig, cert: *const c_char) {
    config.certs.push(to_string(cert));
}

#[no_mangle]
pub unsafe extern "C" fn qf_add_alpn(config: &mut client::ClientConfig, alpn: *const c_char) {
    config.alpns.push(to_string(alpn));
}

#[no_mangle]
pub extern "C" fn qf_free_client_config(_: Option<Box<client::ClientConfig>>) { }

#[no_mangle]
pub extern "C" fn qf_free_server_config(_: Option<Box<server::ServerConfig>>) { }

// ------------------------------
// CRYPTO HELPERS
// ------------------------------
#[no_mangle]
pub unsafe extern "C" fn qf_init(nss_dir: *const c_char) -> bool {
    qf_pop_error();

    return match catch_unwind(|| {
        if nss_dir == std::ptr::null() {
            neqo_crypto::init();
            neqo_crypto::assert_initialized();
            return;
        }

        neqo_crypto::init_db(to_string(nss_dir));
    }) {
        Ok(_) => true,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return false;
        }
    };
}

// ------------------------------
// QUIC WRAPPERS (NONE-ASYNC)
// ------------------------------
#[no_mangle]
pub unsafe extern "C" fn qf_connect(
    conn_addr: *const c_char,
    config: Box<client::ClientConfig>,
) -> Option<Box<ConnectionInfo>> {
    qf_pop_error();

    return match catch_unwind(|| {
        task::block_on(async {
            let conn_addr = to_string(conn_addr);

            let result = client::connect(conn_addr.parse().unwrap(), *config).await;
            if let Err(v) = result {
                qf_set_error(v);
                return None;
            }

            return Some(Box::new(result.unwrap()));
        })
    }) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return None;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_listen(info: &mut ConnectionInfo) -> Option<Box<StreamInfo>> {
    qf_pop_error();

    return match catch_unwind(AssertUnwindSafe(|| {
        if let Some((tx, rx)) = task::block_on(info.1.listen_stream()) {
            return Some(Box::new(StreamInfo::FullStream(tx, rx)));
        }

        return None;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return None;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_create_half(
    info: &mut ConnectionInfo,
) -> Option<Box<StreamInfo>> {
    qf_pop_error();

    return match catch_unwind(AssertUnwindSafe(|| {
        if let Some(v) = info.1.create_stream_half() {
            return Some(Box::new(StreamInfo::HalfStreamSend(v)));
        }

        return None;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return None;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_create_full(
    info: &mut ConnectionInfo,
) -> Option<Box<StreamInfo>> {
    qf_pop_error();

    return match catch_unwind(AssertUnwindSafe(|| {
        if let Some((tx, rx)) = info.1.create_stream_full() {
            return Some(Box::new(StreamInfo::FullStream(tx, rx)));
        }

        return None;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return None;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_send(info: &mut StreamInfo, buf: *mut u8, len: i64) -> i64 {
    qf_pop_error();

    let buffer = std::slice::from_raw_parts(buf, len as usize);
    return match catch_unwind(AssertUnwindSafe(|| {
        let result = task::block_on(async {
            if let StreamInfo::FullStream(tx, _) | StreamInfo::HalfStreamSend(tx) = info {
                return tx.write(buffer).await;
            }

            panic!("bad stream type!");
        });

        if let Err(e) = result {
            qf_set_error(QuicError::IoError(e));
            return -1;
        }

        return result.unwrap() as i64;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return -1;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_send_exact(
    info: &mut StreamInfo,
    buf: *mut u8,
    len: i64,
) -> bool {
    qf_pop_error();

    let buffer = std::slice::from_raw_parts(buf, len as usize);
    return match catch_unwind(AssertUnwindSafe(|| {
        let result = task::block_on(async {
            if let StreamInfo::FullStream(tx, _) | StreamInfo::HalfStreamSend(tx) = info {
                return tx.write_all(buffer).await;
            }

            panic!("bad stream type!");
        });

        if let Err(e) = result {
            qf_set_error(QuicError::IoError(e));
            return false;
        }

        return true;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return false;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_recv(info: &mut StreamInfo, buf: *mut u8, len: i64) -> i64 {
    qf_pop_error();

    let buffer = std::slice::from_raw_parts_mut(buf, len as usize);
    return match catch_unwind(AssertUnwindSafe(|| {
        let result = task::block_on(async {
            if let StreamInfo::FullStream(_, rx) | StreamInfo::HalfStreamRecv(rx) = info {
                return rx.read(buffer).await;
            }

            panic!("bad stream type!");
        });

        if let Err(e) = result {
            qf_set_error(QuicError::IoError(e));
            return -1;
        }

        return result.unwrap() as i64;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return -1;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_recv_exact(
    info: &mut StreamInfo,
    buf: *mut u8,
    len: i64,
) -> bool {
    qf_pop_error();

    let buffer = std::slice::from_raw_parts_mut(buf, len as usize);
    return match catch_unwind(AssertUnwindSafe(|| {
        let result = task::block_on(async {
            if let StreamInfo::FullStream(_, rx) | StreamInfo::HalfStreamRecv(rx) = info {
                return rx.read_exact(buffer).await;
            }

            panic!("bad stream type!");
        });

        if let Err(e) = result {
            qf_set_error(QuicError::IoError(e));
            return false;
        }

        return true;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return false;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_close(info: &mut StreamInfo) -> bool {
    qf_pop_error();

    return match catch_unwind(AssertUnwindSafe(|| {
        let result = task::block_on(async {
            if let StreamInfo::FullStream(tx, _) | StreamInfo::HalfStreamSend(tx) = info {
                return tx.close().await;
            }

            panic!("bad stream type!");
        });

        if let Err(e) = result {
            qf_set_error(QuicError::IoError(e));
            return false;
        }

        return true;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return false;
        }
    };
}

#[no_mangle]
pub unsafe extern "C" fn qf_stream_reset(info: &mut StreamInfo, err: u64) -> bool {
    qf_pop_error();

    return match catch_unwind(AssertUnwindSafe(|| {
        match info {
            StreamInfo::FullStream(tx, _) => tx.reset(err),
            StreamInfo::HalfStreamRecv(tx) => tx.reset(err),
            StreamInfo::HalfStreamSend(rx) => rx.reset(err),
        }

        return true;
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return false;
        }
    };
}


#[no_mangle]
pub unsafe extern "C" fn qf_get_result(mut info: Option<Box<ConnectionInfo>>) -> u64 {
    qf_pop_error();

    return match catch_unwind(AssertUnwindSafe(|| {
        if let Some(info) = info.take() {
            return task::block_on(info.0.stop()).unwrap_or(0);
        }

        0
    })) {
        Ok(v) => v,
        Err(e) => {
            qf_set_error(QuicError::FatalError(e));
            return 0;
        }
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn to_string_trivial() {
        let c_str = b"hello\0";
        unsafe {
            let str = to_string(c_str.as_ptr() as *const c_char);
            assert_eq!(str, "hello");
        }
    }
}
