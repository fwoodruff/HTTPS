//
//  disk_io.hpp
//  HTTPS Server
//
//  Awaitable for async disk reads.
//  On Linux with io_uring available: IORING_OP_READ via the reactor (non-blocking).
//  Fallback (non-Linux or io_uring unavailable): synchronous pread, always-ready.
//

#ifndef disk_io_hpp
#define disk_io_hpp

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "task.hpp"
#include "executor.hpp"

#ifdef __linux__

#include "uring_reactor.hpp"

struct disk_read_awaitable {
    int      fd;
    void*    buf;
    uint32_t len;
    uint64_t offset;
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
        token.handle = h;
        executor_singleton().m_reactor.submit_read(fd, buf, len, offset, &token);
    }
    ssize_t await_resume() const noexcept {
        return m_sync ? sync_result : token.res;
    }
};

// Async open: returns fd >= 0 on success, or negative errno on failure.
struct file_open_awaitable {
    const char* path;
    int         flags;
    mode_t      mode;
    uring_token token {};
    int         sync_result = -1;
    bool        m_sync = false;

    bool await_ready() noexcept {
        m_sync = !executor_singleton().m_reactor.uring_ok();
        if (m_sync) sync_result = ::open(path, flags, static_cast<mode_t>(mode));
        return m_sync;
    }
    void await_suspend(std::coroutine_handle<> h) {
        token.handle = h;
        executor_singleton().m_reactor.submit_openat(URING_AT_FDCWD, path, flags, mode, &token);
    }
    int await_resume() const noexcept { return m_sync ? sync_result : token.res; }
};

// Async close: always succeeds from the caller's perspective (errors are discarded).
struct file_close_awaitable {
    int         fd;
    uring_token token {};
    bool        m_sync = false;

    bool await_ready() noexcept {
        m_sync = !executor_singleton().m_reactor.uring_ok();
        if (m_sync) ::close(fd);
        return m_sync;
    }
    void await_suspend(std::coroutine_handle<> h) {
        token.handle = h;
        executor_singleton().m_reactor.submit_close(fd, &token);
    }
    void await_resume() const noexcept {}
};

// Async write: caller owns the buffer in their coroutine frame; suspends until the CQE fires.
// offset = -1 uses current file position (respects O_APPEND).
struct file_write_awaitable {
    int         fd;
    std::string msg;    // owned here — lives in the coroutine frame
    uring_token token {};
    bool        m_sync = false;

    bool await_ready() noexcept {
        m_sync = !executor_singleton().m_reactor.uring_ok();
        if (m_sync) ::write(fd, msg.data(), static_cast<unsigned>(msg.size()));
        return m_sync;
    }
    void await_suspend(std::coroutine_handle<> h) {
        token.handle = h;
        executor_singleton().m_reactor.submit_write(fd, msg.data(),
                                                     static_cast<unsigned>(msg.size()),
                                                     static_cast<uint64_t>(-1), &token);
    }
    void await_resume() const noexcept {}
};

// Async stat: returns file size >= 0 on success, or negative errno on failure.
struct file_stat_size_awaitable {
    int              fd;
    uring_statx_buf  stx {};
    uring_token      token {};
    ssize_t          sync_result = -1;
    bool             m_sync = false;

    bool await_ready() noexcept {
        m_sync = !executor_singleton().m_reactor.uring_ok();
        if (m_sync) {
            struct ::stat st {};
            if (::fstat(fd, &st) == 0) sync_result = st.st_size;
        }
        return m_sync;
    }
    void await_suspend(std::coroutine_handle<> h) {
        token.handle = h;
        static constexpr char empty[] = "";
        executor_singleton().m_reactor.submit_statx(fd, empty, URING_AT_EMPTY_PATH,
                                                    URING_STATX_SIZE, &stx, &token);
    }
    ssize_t await_resume() const noexcept {
        if (m_sync) return sync_result;
        if (token.res < 0) return static_cast<ssize_t>(token.res);
        return static_cast<ssize_t>(stx.stx_size);
    }
};

#else // non-Linux: synchronous wrappers as always-ready awaitables

struct file_write_awaitable {
    int fd;
    std::string msg;
    file_write_awaitable(int fd_, std::string msg_) : fd(fd_), msg(std::move(msg_)) {
        ::write(fd, msg.data(), msg.size());
    }
    bool await_ready()                       const noexcept { return true; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    void await_resume()                      const noexcept {}
};

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

struct file_open_awaitable {
    int result;
    file_open_awaitable(const char* path, int flags, mode_t mode)
        : result(::open(path, flags, mode)) {}
    bool await_ready()                       const noexcept { return true; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    int  await_resume()                      const noexcept { return result; }
};

struct file_close_awaitable {
    file_close_awaitable(int fd) { ::close(fd); }
    bool await_ready()                       const noexcept { return true; }
    void await_suspend(std::coroutine_handle<>) noexcept {}
    void await_resume()                      const noexcept {}
};

struct file_stat_size_awaitable {
    ssize_t result;
    file_stat_size_awaitable(int fd) {
        struct ::stat st {};
        result = (::fstat(fd, &st) == 0) ? st.st_size : -1;
    }
    bool    await_ready()                       const noexcept { return true; }
    void    await_suspend(std::coroutine_handle<>) noexcept {}
    ssize_t await_resume()                      const noexcept { return result; }
};

#endif // __linux__

inline disk_read_awaitable disk_read(int fd, void* buf, uint32_t len, uint64_t offset) {
    return { fd, buf, len, offset };
}

inline file_open_awaitable file_open(const char* path, int flags, mode_t mode = 0) {
    return { path, flags, mode };
}

inline file_close_awaitable file_close(int fd) {
    return { fd };
}

inline file_stat_size_awaitable file_stat_size(int fd) {
    return { fd };
}

inline file_write_awaitable file_write(int fd, std::string msg) {
    return { fd, std::move(msg) };
}

// Fire-and-forget: opens path, appends msg, closes. Caller does not co_await this.
inline task<void> write_to_file_task(std::string path, std::string msg) {
    int fd = co_await file_open(path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        co_await file_write(fd, std::move(msg));
        co_await file_close(fd);
    }
}

inline void write_to_file(std::string path, std::string msg) {
    async_spawn(write_to_file_task(std::move(path), std::move(msg)));
}

#endif // disk_io_hpp
