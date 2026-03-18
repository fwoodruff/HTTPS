//
//  disk_io.hpp
//  HTTPS Server
//
//  Awaitable for async disk reads.
//  On Linux:     io_uring IORING_OP_READ via the reactor (non-blocking).
//  Otherwise:    synchronous pread (always-ready awaitable).
//

#ifndef disk_io_hpp
#define disk_io_hpp

#include <cstdint>
#include <sys/types.h>
#include <unistd.h>

#ifdef __linux__

#include "uring_reactor.hpp"
#include "executor.hpp"

struct disk_read_awaitable {
    int      fd;
    void*    buf;
    uint32_t len;
    uint64_t offset;
    uring_token token {};

    bool    await_ready() const noexcept { return false; }
    void    await_suspend(std::coroutine_handle<> h) {
        token.handle = h;
        executor_singleton().m_reactor.submit_read(fd, buf, len, offset, &token);
    }
    ssize_t await_resume() const noexcept { return token.res; }
};

#else // non-Linux: synchronous pread wrapped as an always-ready awaitable

struct disk_read_awaitable {
    int      fd;
    void*    buf;
    uint32_t len;
    uint64_t offset;
    ssize_t  result;

    disk_read_awaitable(int fd_, void* buf_, uint32_t len_, uint64_t offset_)
        : fd(fd_), buf(buf_), len(len_), offset(offset_)
        , result(::pread(fd_, buf_, len_, offset_)) {}

    bool    await_ready()                       const noexcept { return true; }
    void    await_suspend(std::coroutine_handle<>) noexcept {}
    ssize_t await_resume()                      const noexcept { return result; }
};

#endif // __linux__

inline disk_read_awaitable disk_read(int fd, void* buf, uint32_t len, uint64_t offset) {
    return { fd, buf, len, offset };
}

#endif // disk_io_hpp
