//
//  disk_io.hpp
//  HTTPS Server
//
//  Awaitable for async disk reads.
//  On Linux with io_uring available: IORING_OP_READ via the reactor (non-blocking).
//  Fallback (non-Linux or io_uring unavailable): synchronous pread, always-ready.

#ifndef disk_io_hpp
#define disk_io_hpp

#include <cstdint>
#include <sys/types.h>
#include <unistd.h>
#include <atomic>

#ifdef __linux__

#include "uring_reactor.hpp"
#include "executor.hpp"

struct disk_read_awaitable {
    int      fd   = -1;
    void*    buf  = nullptr;
    uint32_t len  = 0;
    uint64_t offset = 0;
    uring_token token {};
    ssize_t     sync_result = 0;
    bool        m_sync      = false;

    // If io_uring is unavailable, do a synchronous pread here and return true
    // so the coroutine is never suspended and await_suspend is never called.
    bool await_ready() noexcept {
        m_sync = !executor_singleton().m_reactor.uring_ok();
        if (m_sync) sync_result = ::pread(fd, buf, len, static_cast<off_t>(offset));
        return m_sync;
    }
    void await_suspend(std::coroutine_handle<> h) {
        std::atomic_ref<std::coroutine_handle<>>{token.handle}.store(h, std::memory_order_release);
        executor_singleton().m_reactor.submit_read(fd, buf, len, offset, &token);
    }
    ssize_t await_resume() const noexcept {
        return m_sync ? sync_result : token.res;
    }
};

#else // non-Linux: synchronous pread wrapped as an always-ready awaitable

struct disk_read_awaitable {
    int      fd     = -1;
    void*    buf    = nullptr;
    uint32_t len    = 0;
    uint64_t offset = 0;
    ssize_t  result = 0;

    disk_read_awaitable(int fd_, void* buf_, uint32_t len_, uint64_t offset_)
        : fd(fd_), buf(buf_), len(len_), offset(offset_)
        , result(::pread(fd_, buf_, len_, offset_)) {}

    bool    await_ready()                       const noexcept { return true; }
    void    await_suspend(std::coroutine_handle<>) noexcept {}
    ssize_t await_resume()                      const noexcept { return result; }
};

#endif // __linux__

inline disk_read_awaitable disk_read(int fd, void* buf, uint32_t len, uint64_t offset) {
#ifdef __linux__
    disk_read_awaitable a;
    a.fd = fd; a.buf = buf; a.len = len; a.offset = offset;
    return a;
#else
    return { fd, buf, len, offset };
#endif
}

#endif // disk_io_hpp
