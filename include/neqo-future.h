#ifndef __NEQO_FUTURE_FFI_H__
#define __NEQO_FUTURE_FFI_H__

#include <cstdint>
#include <cstddef>

typedef QFHandle;
typedef QFHandle* QFConnection;
typedef QFHandle* QFStream;
typedef QFHandle* QFConfig;

extern 'C' {
    // ------------------------------
    // UTILITIES
    // ------------------------------
    bool qf_init(const char* dir = nullptr);

    // formats last error if possible
    // if there is no enough space for formatted string, returns size of buffer that needed.
    // you'll need to reallocate with it.
    size_t qf_format_last_error(char* buf, size_t len);

    // ------------------------------
    // CONFIG HELPERS
    // ------------------------------
    QFConfig qf_create_client_config(const char* bind_addr);
    QFConfig qf_create_server_config(const char* bind_addr);
    void qf_free_client_config(QFConfig config);
    void qf_free_server_config(QFConfig config);

    // client configuration helpers.
    void qf_set_server_name(QFConfig config, const char* sni);
    void qf_add_cert(QFConfig config, const char* cert);
    void qf_add_alpn(QFConfig config, const char* alpn);
    

    // ------------------------------
    // CONNECTION HELPERS
    // ------------------------------
    QFConnection qf_connect(QFConfig config);
    void qf_disconnect(QFConnection);

    // ------------------------------
    // STREAM HELPERS
    // ------------------------------
    QFStream qf_stream_listen(QFConnection connection);
    QFStream qf_stream_create_half(QFConnection connection);
    QFStream qf_stream_create_full(QFConnection connection);

    int64_t qf_stream_send(QFStream stream, char* buf, int64_t len);
    int64_t qf_stream_send_exact(QFStream stream, char* buf, int64_t len);
    int64_t qf_stream_recv(QFStream stream, char* buf, int64_t len);
    int64_t qf_stream_recv_exact(QFStream stream, char* buf, int64_t len);

    bool qf_stream_close(QFStream stream);
    bool qf_stream_reset(QFStream stream, uint64_t err);
};

class QuicStream {
    friend class QuicClient;
    QFStream stream = 0;

protected:
    explicit QuicStream(QFStream stream_id) : stream(stream_id) { }

public:
    int64_t send(char* buf, int64_t len) {
        return qf_stream_send(stream, buf, len);
    }

    int64_t send_exact(char* buf, int64_t len) {
        return qf_stream_send_exact(stream, buf, len);
    }

    int64_t recv(char* buf, int64_t len) {
        return qf_stream_recv(buf, len);
    }

    int64_t recv_exact(char* buf, int64_t len) {
        return qf_stream_recv_exact(buf, len);
    }

    bool close() {
        return qf_stream_close(stream);
    }

    bool reset(uint64_t err = 0) {
        return qf_stream_reset(err);
    }
};

class QuicClient {
    friend class QuicClientconfig;
    QFConnection connection;

protected:
    explicit QuicClient(QFConnection conn) : connection(conn) { }

public:
    QuicStream stream_create_full() {
        return QuicStream(qf_stream_create_full(connection));
    }

    QuicStream stream_create_half() {
        return QuicStream(qf_stream_create_half(connection));
    }
};

class QuicClientConfig {
    QFConfig config = 0;

public:
    QuicClientConfig(const char* bind_addr) : config(qf_create_client_config(bind_addr)) { }

    void set_server_name(const char* sni) {
        qf_set_server_name(config, sni);
    }

    void add_cert(const char* cert) {
        qf_add_cert(config, cert);
    }

    void add_alpn(const char* alpn) {
        qf_add_alpn(config, alpn);
    }

    QuicClient connect(const char* conn_addr) {
        return QuicClient(qf_connect(config));
    }
};


#endif