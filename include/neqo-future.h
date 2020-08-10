#ifndef __NEQO_FUTURE_FFI_H__
#define __NEQO_FUTURE_FFI_H__

#include <cstdint>
#include <cstddef>

typedef QFHandle;
typedef QFHandle* QFConnection;
typedef QFHandle* QFStream;

extern 'C' {
    bool qf_init(const char* dir);
    QFConnection qf_connect(const char* conn_addr);

    size_t qf_format_last_error(char* buf, size_t len);

    QFStream qf_stream_listen(QFConnection connection);
    QFStream qf_stream_create_half(QFConnection connection);
    QFStream qf_stream_create_full(QFConnection connection);

    int64_t qf_stream_send(QFStream stream, const char* buf, int64_t len);
    int64_t qf_stream_send_exact(QFStream stream, const char* buf, int64_t len);
    int64_t qf_stream_recv(QFStream stream, const char* buf, int64_t len);
    int64_t qf_stream_recv_exact(QFStream stream, const char* buf, int64_t len);

    bool qf_stream_close(QFStream stream);
    bool qf_stream_reset(QFStream stream, uint64_t err);
}

#endif