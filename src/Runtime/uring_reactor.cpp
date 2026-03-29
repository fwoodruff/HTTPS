//
//  uring_reactor.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 15/03/2026.
//

#ifdef __linux__

#include "uring_reactor.hpp"
#include "executor.hpp"

#include <sys/socket.h>
#include <stdexcept>
#include <algorithm>

// -----------------------------------------------------------------------
// Construction / destruction
// -----------------------------------------------------------------------

uring_reactor::uring_reactor() {
    io_uring_queue_init(256, &m_ring, 0);
    m_uring_ok = (m_ring.ring_fd >= 0);
}

uring_reactor::~uring_reactor() {
    io_uring_queue_exit(&m_ring);
}

// -----------------------------------------------------------------------
// Async operation submission
// -----------------------------------------------------------------------

void uring_reactor::submit_recv(int fd, void* buf, uint32_t len,
                                 uring_token* token,
                                 std::optional<milliseconds> timeout) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_recv)");
    io_uring_prep_recv(sqe, fd, buf, len, 0);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));

    if (timeout && timeout->count() > 0) {
        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
        token->ts = { timeout->count() / 1000, (timeout->count() % 1000) * 1'000'000LL };

        auto* tsqe = io_uring_get_sqe(&m_ring);
        if (!tsqe) throw std::runtime_error("io_uring SQ ring full (submit_recv timeout)");
        io_uring_prep_link_timeout(tsqe, &token->ts, 0);
        io_uring_sqe_set_data64(tsqe, URING_IGNORE);
    }
    io_uring_submit(&m_ring);
}

void uring_reactor::submit_send(int fd, const void* buf, uint32_t len,
                                 uring_token* token,
                                 std::optional<milliseconds> timeout) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_send)");
    io_uring_prep_send(sqe, fd, buf, len, MSG_NOSIGNAL);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));

    if (timeout && timeout->count() > 0) {
        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
        token->ts = { timeout->count() / 1000, (timeout->count() % 1000) * 1'000'000LL };

        auto* tsqe = io_uring_get_sqe(&m_ring);
        if (!tsqe) throw std::runtime_error("io_uring SQ ring full (submit_send timeout)");
        io_uring_prep_link_timeout(tsqe, &token->ts, 0);
        io_uring_sqe_set_data64(tsqe, URING_IGNORE);
    }
    io_uring_submit(&m_ring);
}

void uring_reactor::submit_recvmsg(int fd, struct msghdr* msg,
                                    uring_token* token,
                                    std::optional<milliseconds> timeout) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_recvmsg)");
    io_uring_prep_recvmsg(sqe, fd, msg, 0);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));

    if (timeout && timeout->count() > 0) {
        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
        token->ts = { timeout->count() / 1000, (timeout->count() % 1000) * 1'000'000LL };

        auto* tsqe = io_uring_get_sqe(&m_ring);
        if (!tsqe) throw std::runtime_error("io_uring SQ ring full (submit_recvmsg timeout)");
        io_uring_prep_link_timeout(tsqe, &token->ts, 0);
        io_uring_sqe_set_data64(tsqe, URING_IGNORE);
    }
    io_uring_submit(&m_ring);
}

void uring_reactor::submit_sendmsg(int fd, const struct msghdr* msg,
                                    uring_token* token,
                                    std::optional<milliseconds> timeout) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_sendmsg)");
    io_uring_prep_sendmsg(sqe, fd, msg, 0);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));

    if (timeout && timeout->count() > 0) {
        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK);
        token->ts = { timeout->count() / 1000, (timeout->count() % 1000) * 1'000'000LL };

        auto* tsqe = io_uring_get_sqe(&m_ring);
        if (!tsqe) throw std::runtime_error("io_uring SQ ring full (submit_sendmsg timeout)");
        io_uring_prep_link_timeout(tsqe, &token->ts, 0);
        io_uring_sqe_set_data64(tsqe, URING_IGNORE);
    }
    io_uring_submit(&m_ring);
}

void uring_reactor::submit_read(int fd, void* buf, uint32_t len,
                                 uint64_t offset, uring_token* token) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_read)");
    io_uring_prep_read(sqe, fd, buf, len, offset);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));
    io_uring_submit(&m_ring);
}

bool uring_reactor::submit_accept(int fd, struct sockaddr_storage* addr,
                                   socklen_t* addrlen, uring_token* token) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) return false;
    io_uring_prep_accept(sqe, fd, reinterpret_cast<struct sockaddr*>(addr), addrlen, SOCK_NONBLOCK);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));
    io_uring_submit(&m_ring);
    return true;
}

void uring_reactor::submit_connect(int fd, struct sockaddr* addr,
                                    socklen_t addrlen, uring_token* token) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_connect)");
    io_uring_prep_connect(sqe, fd, addr, addrlen);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));
    io_uring_submit(&m_ring);
}

void uring_reactor::submit_openat(int dfd, const char* path, int flags,
                                   mode_t mode, uring_token* token) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_openat)");
    io_uring_prep_openat(sqe, dfd, path, flags, mode);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));
    io_uring_submit(&m_ring);
}

void uring_reactor::submit_close(int fd, uring_token* token) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_close)");
    io_uring_prep_close(sqe, fd);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));
    io_uring_submit(&m_ring);
}

void uring_reactor::submit_statx(int fd, const char* path, int flags,
                                  unsigned mask, uring_statx_buf* buf, uring_token* token) {
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) throw std::runtime_error("io_uring SQ ring full (submit_statx)");
    io_uring_prep_statx(sqe, fd, path, flags, mask, buf);
    io_uring_sqe_set_data64(sqe, reinterpret_cast<uint64_t>(token));
    io_uring_submit(&m_ring);
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
    std::scoped_lock lk { m_sq_mut };
    auto* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) return;  // ring full - wait() will wake on the next real CQE anyway
    io_uring_prep_nop(sqe);
    io_uring_sqe_set_data64(sqe, URING_IGNORE);
    io_uring_submit(&m_ring);  // publish sq_tail
    // Must enter immediately (min_complete=0) to wake up any thread blocked in
    // io_uring_wait_cqe_nr, since io_uring_submit no longer calls io_uring_enter.
    io_uring_wait_cqe_nr(&m_ring, 0);
}

size_t uring_reactor::task_count() {
    if (!m_uring_ok) return m_fallback.task_count();
    return m_ring.in_flight.load(std::memory_order_relaxed);
}

// -----------------------------------------------------------------------
// CQ drain - resolve tokens into coroutine handles
// -----------------------------------------------------------------------

std::vector<std::coroutine_handle<>> uring_reactor::drain_cq() {
    std::vector<std::coroutine_handle<>> out;
    struct io_uring_cqe* cqe;
    while (io_uring_peek_cqe(&m_ring, &cqe) == 0) {
        uint64_t ud  = cqe->user_data;
        int32_t  res = cqe->res;
        io_uring_cq_advance(&m_ring, 1);
        if (ud == URING_IGNORE) continue;
        auto* token = reinterpret_cast<uring_token*>(static_cast<uintptr_t>(ud));
        token->res = res;
        if (token->handle) out.push_back(token->handle);
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

    auto cq_ready = drain_cq();
    out.insert(out.end(), cq_ready.begin(), cq_ready.end());

    if (!out.empty() || noblock) return out;

    // Compute how long until the next timer fires.
    std::optional<time_point<steady_clock>> next_wake;
    {
        std::scoped_lock lk { m_timer_mut };
        if (!m_timers.empty()) next_wake = m_timers.top().when;
    }

    // Declared here so it outlives the io_uring_wait_cqe_nr call below
    // the kernel may read the timespec asynchronously until the op completes.
    uring_timespec ts {};
    if (next_wake) {
        auto dur = *next_wake - steady_clock::now();
        if (dur.count() <= 0) {
            // Already expired, collect and return without blocking.
            std::scoped_lock lk { m_timer_mut };
            while (!m_timers.empty() && m_timers.top().when <= steady_clock::now()) {
                out.push_back(m_timers.top().handle);
                m_timers.pop();
            }
            return out;
        }
        auto ms = duration_cast<milliseconds>(dur) + 1ms;
        ts = { ms.count() / 1000, (ms.count() % 1000) * 1'000'000LL };
        {
            std::scoped_lock lk { m_sq_mut };
            auto* sqe = io_uring_get_sqe(&m_ring);
            if (sqe) {
                io_uring_prep_timeout(sqe, &ts, 1, 0);
                io_uring_sqe_set_data64(sqe, URING_IGNORE);
                io_uring_submit(&m_ring);  // publish sq_tail so wait_cqe_nr sees this SQE
            }
        }
    }

    // Batch submit: wait_cqe_nr will submit all pending SQEs (both regular and timeout)
    // in a single io_uring_enter syscall before blocking
    io_uring_wait_cqe_nr(&m_ring, 1);

    // Drain all ready CQEs. If the CQ overflowed while we were blocked,
    // flush the kernel overflow list back into the ring and drain again,
    // repeating until no overflow remains.
    {
        auto more = drain_cq();
        out.insert(out.end(), more.begin(), more.end());
    }
    while (io_uring_cq_has_overflow(&m_ring)) {
        io_uring_get_events(&m_ring);
        auto more = drain_cq();
        out.insert(out.end(), more.begin(), more.end());
    }

    // Re-check timers (the timeout SQE may have fired).
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
