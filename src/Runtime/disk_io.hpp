//
//  disk_io.hpp
//  HTTPS Server
//
//  Awaitable for async disk reads.
//  On Linux with io_uring available: IORING_OP_READ via the reactor (non-blocking).
//  Fallback (non-Linux or io_uring unavailable): synchronous pread, always-ready.
//
//  Eager-start pipeline use:
//    auto fut = disk_read(fd, buf, len, off);
//    fut.start();                   // submit SQE now (token must be in stable memory)
//    co_await other_work();         // overlaps with the in-flight read
//    auto n = co_await fut;         // resume immediately if already done, else suspend

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
    bool        m_started   = false;

    // Submit the SQE immediately without suspending.  Must be called when this
    // struct is already in stable memory (i.e. a coroutine-frame local that
    // lives across a co_await boundary).
    void start() {
        if (executor_singleton().m_reactor.uring_ok()) {
            m_started = true;
            executor_singleton().m_reactor.submit_read(fd, buf, len, offset, &token);
        }
        // If io_uring is unavailable we'll do a sync pread in await_ready instead.
    }

    bool await_ready() noexcept {
        if (m_started) {
            // Check whether the CQE has already arrived.
            return std::atomic_ref<bool>{token.completed}.load(std::memory_order_acquire);
        }
        m_sync = !executor_singleton().m_reactor.uring_ok();
        if (m_sync) sync_result = ::pread(fd, buf, len, static_cast<off_t>(offset));
        return m_sync;
    }

    // Returns true  → suspend (reactor will resume us when the CQE arrives).
    // Returns false → already done, resume immediately without suspending.
    bool await_suspend(std::coroutine_handle<> h) {
        if (m_started) {
            // Eager-start race protocol:
            //   Release-store handle so drain_cq can see it.
            //   Acquire-load completed to close the window where drain_cq ran
            //   between our await_ready check and this store.
            std::atomic_ref<std::coroutine_handle<>>{token.handle}.store(h, std::memory_order_release);
            if (std::atomic_ref<bool>{token.completed}.load(std::memory_order_acquire)) {
                // CQE arrived before we registered the handle; drain_cq saw
                // handle==null and skipped us.  Don't suspend — resume immediately.
                return false;
            }
            return true;
        }
        // Normal (non-eager) path: register handle then submit.
        std::atomic_ref<std::coroutine_handle<>>{token.handle}.store(h, std::memory_order_release);
        executor_singleton().m_reactor.submit_read(fd, buf, len, offset, &token);
        return true;
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
    bool     m_started = false;

    void start() {
        m_started = true;
        result = ::pread(fd, buf, len, static_cast<off_t>(offset));
    }

    bool    await_ready() noexcept {
        if (!m_started) start();
        return true;
    }
    bool    await_suspend(std::coroutine_handle<>) noexcept { return true; }
    ssize_t await_resume()                      const noexcept { return result; }
};

#endif // __linux__

inline disk_read_awaitable disk_read(int fd, void* buf, uint32_t len, uint64_t offset) {
    disk_read_awaitable a;
    a.fd = fd; a.buf = buf; a.len = len; a.offset = offset;
    return a;
}

#endif // disk_io_hpp
