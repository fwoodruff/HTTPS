//
//  uring_reactor.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 15/03/2026.
//

#ifdef __linux__

#include "uring_reactor.hpp"
#include "uring_defs.hpp"
#include "executor.hpp"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/socket.h>

// Syscall numbers are stable Linux ABI; provide fallbacks for cross-compilers
// that don't ship kernel headers with these defines.
#ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup  425
#  define __NR_io_uring_enter  426
#endif
#include <signal.h>
#include <unistd.h>
#include <cassert>
#include <cstring>
#include <stdexcept>
#include <algorithm>
#include <print>

// Raw io_uring syscall wrappers
static int sys_io_uring_setup(uint32_t entries, struct io_uring_params* p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}
static int sys_io_uring_enter(int fd, uint32_t to_submit, uint32_t min_complete,
                               uint32_t flags) {
    // Last two args: sigset_t* and size_t - pass null/0 for no signal mask change
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags,
                        (sigset_t*)nullptr, (size_t)(_NSIG / 8));
}

// -----------------------------------------------------------------------
// Construction / destruction
// -----------------------------------------------------------------------

uring_reactor::uring_reactor() {
    struct io_uring_params p {};
    m_ring_fd = sys_io_uring_setup(256, &p);
    if (m_ring_fd < 0) {
        std::println(stderr, "io_uring unavailable (errno {}), falling back to poll reactor", errno);
        return;
    }
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)) {
        std::println(stderr, "io_uring lacks IORING_FEAT_SINGLE_MMAP, falling back to poll reactor");
        ::close(m_ring_fd);
        m_ring_fd = -1;
        return;
    }

    // Single mmap for both SQ and CQ rings
    size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    size_t cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    m_ring_sz = std::max(sq_sz, cq_sz);
    m_ring_ptr = ::mmap(nullptr, m_ring_sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, m_ring_fd, IORING_OFF_SQ_RING);
    if (m_ring_ptr == MAP_FAILED) {
        ::close(m_ring_fd);
        m_ring_fd = -1;
        m_ring_ptr = nullptr;
        return;
    }

    // SQE array - separate mmap
    m_sqes_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    m_sqes_ptr = ::mmap(nullptr, m_sqes_sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, m_ring_fd, IORING_OFF_SQES);
    if (m_sqes_ptr == MAP_FAILED) {
        ::munmap(m_ring_ptr, m_ring_sz);
        ::close(m_ring_fd);
        m_ring_fd = -1;
        m_ring_ptr = nullptr;
        m_sqes_ptr = nullptr;
        return;
    }

    auto* ring = static_cast<char*>(m_ring_ptr);
    // Cast mmap'd ring fields to std::atomic<uint32_t>* for acquire/release semantics.
    m_sq_head      = reinterpret_cast<std::atomic<uint32_t>*>(ring + p.sq_off.head);
    m_sq_tail      = reinterpret_cast<std::atomic<uint32_t>*>(ring + p.sq_off.tail);
    m_sq_ring_mask = *reinterpret_cast<uint32_t*>(ring + p.sq_off.ring_mask);
    m_sq_array     = reinterpret_cast<uint32_t*>(ring + p.sq_off.array);
    m_sqes         = static_cast<struct io_uring_sqe*>(m_sqes_ptr);

    m_cq_head      = reinterpret_cast<std::atomic<uint32_t>*>(ring + p.cq_off.head);
    m_cq_tail      = reinterpret_cast<std::atomic<uint32_t>*>(ring + p.cq_off.tail);
    m_cq_ring_mask = *reinterpret_cast<uint32_t*>(ring + p.cq_off.ring_mask);
    m_cqes         = reinterpret_cast<struct io_uring_cqe*>(ring + p.cq_off.cqes);

    m_uring_ok = true;
}

uring_reactor::~uring_reactor() {
    if (m_sqes_ptr && m_sqes_ptr != MAP_FAILED) ::munmap(m_sqes_ptr, m_sqes_sz);
    if (m_ring_ptr && m_ring_ptr != MAP_FAILED) ::munmap(m_ring_ptr, m_ring_sz);
    if (m_ring_fd >= 0) ::close(m_ring_fd);
}

// -----------------------------------------------------------------------
// SQE helpers
// -----------------------------------------------------------------------

struct io_uring_sqe* uring_reactor::get_sqe() {
    // Caller must hold m_sq_mut.  Claim one slot; return nullptr if ring is full.
    uint32_t head = m_sq_head->load(std::memory_order_acquire);
    if (m_sq_tail_local - head > m_sq_ring_mask) {
        return nullptr;
    }
    uint32_t idx = m_sq_tail_local & m_sq_ring_mask;
    m_sq_array[idx] = idx;
    ++m_sq_tail_local;
    return &m_sqes[idx];
}

void uring_reactor::flush(int n) {
    // Caller must hold m_sq_mut.
    // Publish the shadow tail; release ordering ensures all SQE field writes are visible.
    m_sq_tail->store(m_sq_tail_local, std::memory_order_release);
    int r = sys_io_uring_enter(m_ring_fd, n, 0, 0);
    (void)r;
    m_in_flight.fetch_add(n, std::memory_order_relaxed);
}

// -----------------------------------------------------------------------
// Async operation submission
// -----------------------------------------------------------------------

void uring_reactor::submit_recv(int fd, void* buf, uint32_t len,
                                 uring_token* token,
                                 std::optional<milliseconds> timeout) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = get_sqe();
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_recv)");
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_RECV;
    sqe->fd        = fd;
    sqe->addr      = reinterpret_cast<uint64_t>(buf);
    sqe->len       = len;
    sqe->user_data = reinterpret_cast<uint64_t>(token);

    int n = 1;
    if (timeout && timeout->count() > 0) {
        sqe->flags = IOSQE_IO_LINK;
        token->ts.tv_sec  = timeout->count() / 1000;
        token->ts.tv_nsec = (timeout->count() % 1000) * 1'000'000LL;

        auto* tsqe = get_sqe();
        if (!tsqe) throw std::runtime_error("io_uring SQ ring full (submit_recv timeout)");
        std::memset(tsqe, 0, sizeof(*tsqe));
        tsqe->opcode    = IORING_OP_LINK_TIMEOUT;
        tsqe->addr      = reinterpret_cast<uint64_t>(&token->ts);
        tsqe->len       = 1;
        tsqe->user_data = URING_IGNORE;
        n = 2;
    }
    flush(n);
}

void uring_reactor::submit_send(int fd, const void* buf, uint32_t len,
                                 uring_token* token,
                                 std::optional<milliseconds> timeout) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = get_sqe();
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_send)");
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_SEND;
    sqe->fd        = fd;
    sqe->addr      = reinterpret_cast<uint64_t>(buf);
    sqe->len       = len;
    sqe->msg_flags = MSG_NOSIGNAL;
    sqe->user_data = reinterpret_cast<uint64_t>(token);

    int n = 1;
    if (timeout && timeout->count() > 0) {
        sqe->flags = IOSQE_IO_LINK;
        token->ts.tv_sec  = timeout->count() / 1000;
        token->ts.tv_nsec = (timeout->count() % 1000) * 1'000'000LL;

        auto* tsqe = get_sqe();
        if (!tsqe) throw std::runtime_error("io_uring SQ ring full (submit_send timeout)");
        std::memset(tsqe, 0, sizeof(*tsqe));
        tsqe->opcode    = IORING_OP_LINK_TIMEOUT;
        tsqe->addr      = reinterpret_cast<uint64_t>(&token->ts);
        tsqe->len       = 1;
        tsqe->user_data = URING_IGNORE;
        n = 2;
    }
    flush(n);
}

bool uring_reactor::submit_accept(int fd, struct sockaddr_storage* addr,
                                   socklen_t* addrlen, uring_token* token) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = get_sqe();
    if (!sqe) return false;
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode       = IORING_OP_ACCEPT;
    sqe->fd           = fd;
    sqe->addr         = reinterpret_cast<uint64_t>(addr);
    sqe->addr2        = reinterpret_cast<uint64_t>(addrlen);
    sqe->accept_flags = SOCK_NONBLOCK;
    sqe->user_data    = reinterpret_cast<uint64_t>(token);
    flush(1);
    return true;
}

void uring_reactor::submit_connect(int fd, struct sockaddr* addr,
                                    socklen_t addrlen, uring_token* token) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = get_sqe();
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_connect)");
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_CONNECT;
    sqe->fd        = fd;
    sqe->addr      = reinterpret_cast<uint64_t>(addr);
    sqe->off       = addrlen;
    sqe->user_data = reinterpret_cast<uint64_t>(token);
    flush(1);
}

// -----------------------------------------------------------------------
// Poll reactor fallback delegation
// -----------------------------------------------------------------------

void uring_reactor::add_task(int fd, std::coroutine_handle<> handle,
                              IO_direction rw, std::optional<milliseconds> timeout) {
    m_fallback.add_task(fd, handle, rw, timeout);
}

// -----------------------------------------------------------------------
// Timer support
// -----------------------------------------------------------------------

void uring_reactor::sleep_for(std::coroutine_handle<> handle, milliseconds dur) {
    if (!m_uring_ok) { m_fallback.sleep_for(handle, dur); return; }
    if (!handle) return;
    const auto when = steady_clock::now() + dur;
    {
        std::scoped_lock lk { m_timer_mut };
        m_timers.emplace(when, handle);
    }
    notify();
}

void uring_reactor::sleep_until(std::coroutine_handle<> handle,
                                  time_point<steady_clock> when) {
    if (!m_uring_ok) { m_fallback.sleep_until(handle, when); return; }
    if (!handle) return;
    {
        std::scoped_lock lk { m_timer_mut };
        m_timers.emplace(when, handle);
    }
    notify();
}

// -----------------------------------------------------------------------
// Notification - submit a NOP that completes immediately
// -----------------------------------------------------------------------

void uring_reactor::notify() {
    if (!m_uring_ok) { m_fallback.notify(); return; }
    // m_mut serialises notify() calls coming from other threads against each other
    // and against the timer SQE submission in wait().
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = get_sqe();
    if (!sqe) return;  // ring full - wait() will wake on the next real CQE anyway
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_NOP;
    sqe->user_data = URING_IGNORE;
    flush(1);
}

size_t uring_reactor::task_count() {
    if (!m_uring_ok) return m_fallback.task_count();
    return m_in_flight.load(std::memory_order_relaxed);
}

// -----------------------------------------------------------------------
// CQ drain - collect ready coroutine handles (no locking needed: single consumer)
// -----------------------------------------------------------------------

std::vector<std::coroutine_handle<>> uring_reactor::drain_cq() {
    std::vector<std::coroutine_handle<>> out;
    for (;;) {
        uint32_t head = m_cq_head->load(std::memory_order_relaxed);
        uint32_t tail = m_cq_tail->load(std::memory_order_acquire);
        if (head == tail) break;

        auto* cqe = &m_cqes[head & m_cq_ring_mask];
        uint64_t ud  = cqe->user_data;
        int32_t  res = cqe->res;
        m_cq_head->store(head + 1, std::memory_order_release);

        m_in_flight.fetch_sub(1, std::memory_order_relaxed);

        if (ud == URING_IGNORE) continue;

        auto* token = reinterpret_cast<uring_token*>(static_cast<uintptr_t>(ud));
        token->res = res;
        if (token->handle) {
            out.push_back(token->handle);
        }
    }
    return out;
}

// -----------------------------------------------------------------------
// wait() - the main reactor loop entry point
// -----------------------------------------------------------------------

std::vector<std::coroutine_handle<>> uring_reactor::wait(bool noblock) {
    if (!m_uring_ok) return m_fallback.wait(noblock);

    // Check timers first
    const auto now = steady_clock::now();
    std::vector<std::coroutine_handle<>> out;
    {
        std::scoped_lock lk { m_timer_mut };
        while (!m_timers.empty() && m_timers.top().when <= now) {
            out.push_back(m_timers.top().handle);
            m_timers.pop();
        }
    }

    // Non-blocking peek at the CQ
    auto cq_ready = drain_cq();
    out.insert(out.end(), cq_ready.begin(), cq_ready.end());

    if (!out.empty() || noblock) {
        return out;
    }

    // Compute how long until the next timer fires
    std::optional<time_point<steady_clock>> next_wake;
    {
        std::scoped_lock lk { m_timer_mut };
        if (!m_timers.empty()) next_wake = m_timers.top().when;
    }

    // If there's a timer deadline, submit a timeout SQE so io_uring_enter wakes up in time
    if (next_wake) {
        auto dur = *next_wake - steady_clock::now();
        if (dur.count() <= 0) {
            // Already expired - collect and return
            std::scoped_lock lk { m_timer_mut };
            while (!m_timers.empty() && m_timers.top().when <= steady_clock::now()) {
                out.push_back(m_timers.top().handle);
                m_timers.pop();
            }
            return out;
        }
        auto ms = duration_cast<milliseconds>(dur) + 1ms;

        // Heap-allocate a small timespec; we use a local uring_timespec here.
        // It only needs to live until the timeout CQE fires (before io_uring_enter returns).
        // Placing it on the stack is safe because the call to io_uring_enter is synchronous.
        uring_timespec ts { ms.count() / 1000, (ms.count() % 1000) * 1'000'000LL };
        {
            std::scoped_lock lk { m_sq_mut };
            auto* sqe = get_sqe();
            if (sqe) {
                std::memset(sqe, 0, sizeof(*sqe));
                sqe->opcode    = IORING_OP_TIMEOUT;
                sqe->addr      = reinterpret_cast<uint64_t>(&ts);
                sqe->len       = 1;
                sqe->user_data = URING_IGNORE;
                flush(1);
            }
        }
        // Block until >=1 CQE (either the timeout or a real op)
        sys_io_uring_enter(m_ring_fd, 0, 1, IORING_ENTER_GETEVENTS);
    } else {
        // No timers - block indefinitely until any CQE
        sys_io_uring_enter(m_ring_fd, 0, 1, IORING_ENTER_GETEVENTS);
    }

    // Drain CQEs that arrived while we were blocked
    auto more = drain_cq();
    out.insert(out.end(), more.begin(), more.end());

    // Re-check timers (timer SQE may have fired)
    {
        const auto after = steady_clock::now();
        std::scoped_lock lk { m_timer_mut };
        while (!m_timers.empty() && m_timers.top().when <= after) {
            out.push_back(m_timers.top().handle);
            m_timers.pop();
        }
    }

    return out;
}

#endif // __linux__
