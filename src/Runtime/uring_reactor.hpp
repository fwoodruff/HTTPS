//
//  uring_reactor.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 15/03/2026.
//

#ifndef uring_reactor_hpp
#define uring_reactor_hpp

#ifdef __linux__

#include "reactor.hpp"

#include <coroutine>
#include <chrono>
#include <optional>
#include <vector>
#include <mutex>
#include <queue>
#include <cstdint>
#include <atomic>
#include <sys/socket.h>

using namespace std::chrono;

// Kernel-compatible 64-bit timespec (matches struct __kernel_timespec)
struct uring_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

// Completion token stored in the awaitable (coroutine frame).
// user_data in the SQE points here; the reactor writes res on CQE arrival.
struct uring_token {
    std::coroutine_handle<> handle;
    int32_t res = 0;
    uring_timespec ts {};   // stable buffer for an optional linked timeout SQE
};

// Sentinel user_data value - CQEs with this are discarded (timeout SQEs, NOPs)
static constexpr uint64_t URING_IGNORE = UINT64_MAX;

struct io_uring_sqe;
struct io_uring_cqe;

class uring_reactor {
public:
    uring_reactor();
    ~uring_reactor();

    uring_reactor(const uring_reactor&) = delete;
    uring_reactor& operator=(const uring_reactor&) = delete;

    bool uring_ok() const { return m_uring_ok; }

    // Async operations - fill an SQE and return immediately; coroutine suspends.
    // token must remain valid (i.e. live in the coroutine frame) until await_resume().
    void submit_recv   (int fd, void* buf, uint32_t len,
                        uring_token* token, std::optional<milliseconds> timeout = std::nullopt);
    void submit_send   (int fd, const void* buf, uint32_t len,
                        uring_token* token, std::optional<milliseconds> timeout = std::nullopt);
    void submit_accept (int fd, struct sockaddr_storage* addr, socklen_t* addrlen,
                        uring_token* token);
    void submit_connect(int fd, struct sockaddr* addr, socklen_t addrlen,
                        uring_token* token);

    // Poll-reactor fallback: used when io_uring is unavailable
    void add_task(int fd, std::coroutine_handle<> handle, IO_direction rw,
                  std::optional<milliseconds> timeout = std::nullopt);

    // Timer support - same interface as the poll reactor
    void sleep_for  (std::coroutine_handle<> handle, milliseconds dur);
    void sleep_until(std::coroutine_handle<> handle, time_point<steady_clock> when);

    size_t task_count();
    void   notify();

    // Returns coroutines that became ready.
    // noblock=true: non-blocking peek; noblock=false: block until >=1 is ready.
    std::vector<std::coroutine_handle<>> wait(bool noblock = false);

private:
    // SQE helpers
    struct io_uring_sqe* get_sqe_locked();  // must hold m_mut
    void flush_locked(int n);               // must hold m_mut

    std::vector<std::coroutine_handle<>> drain_cq();

    bool m_uring_ok = false;
    reactor m_fallback;     // used when io_uring is unavailable

    int m_ring_fd = -1;

    // SQ ring
    uint32_t* m_sq_head         = nullptr;
    uint32_t* m_sq_tail         = nullptr;  // kernel-visible tail (mmap region)
    uint32_t  m_sq_tail_local   = 0;        // shadow tail; published atomically in flush_locked
    uint32_t  m_sq_ring_mask    = 0;
    uint32_t* m_sq_array        = nullptr;
    struct io_uring_sqe* m_sqes = nullptr;

    // CQ ring
    uint32_t* m_cq_head      = nullptr;
    uint32_t* m_cq_tail      = nullptr;
    uint32_t  m_cq_ring_mask = 0;
    struct io_uring_cqe* m_cqes = nullptr;

    void*  m_ring_ptr = nullptr;
    size_t m_ring_sz  = 0;
    void*  m_sqes_ptr = nullptr;
    size_t m_sqes_sz  = 0;

    // Timer queue for sleep_for / sleep_until
    struct timer_entry {
        time_point<steady_clock> when;
        std::coroutine_handle<> handle;
    };
    struct timer_cmp {
        bool operator()(const timer_entry& a, const timer_entry& b) const noexcept {
            return a.when > b.when;
        }
    };

    std::mutex m_mut;   // serialises all SQ writes and timer-queue access
    std::priority_queue<timer_entry, std::vector<timer_entry>, timer_cmp> m_timers;
    std::atomic<size_t> m_in_flight { 0 };
};

#endif // __linux__
#endif // uring_reactor_hpp
