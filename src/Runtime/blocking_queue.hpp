//
//  blocking_queue.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 7/7/2024.
//

#ifndef blocking_queue_hpp
#define blocking_queue_hpp

#include <stdio.h>
#include <queue>
#include <vector>
#include <optional>
#include "concurrent_queue.hpp"

#ifdef __linux__

// Direct-futex semaphore: zero spin, zero wasted syscalls when no waiters.
//
// std::counting_semaphore on GCC 15 / glibc uses POSIX sem_post/sem_wait which:
//  - sem_post always calls futex(FUTEX_WAKE) even with no waiters (~1 extra
//    syscall per release)
//  - the GCC atomic-wait spin loop calls sched_yield 16 times before sleeping
//    (visible in strace as 16 sched_yields per io_uring wakeup cycle)
//
// This implementation goes straight to futex and only wakes waiters when at
// least one thread is actually blocked in acquire().

#include <sys/syscall.h>
#include <linux/futex.h>
#include <unistd.h>
#include <atomic>
#include <algorithm>

class futex_semaphore {
    std::atomic<int> m_count{0};
    std::atomic<int> m_waiters{0};

    static void futex_wait(std::atomic<int>& addr, int expected) noexcept {
        ::syscall(SYS_futex, &addr, FUTEX_WAIT_PRIVATE, expected, nullptr, nullptr, 0);
    }
    static void futex_wake(std::atomic<int>& addr, int n) noexcept {
        ::syscall(SYS_futex, &addr, FUTEX_WAKE_PRIVATE, n, nullptr, nullptr, 0);
    }

public:
    explicit futex_semaphore(ptrdiff_t desired = 0) noexcept
        : m_count(static_cast<int>(desired)) {}

    // Non-blocking: a plain CAS loop, no yield, no syscall.
    bool try_acquire() noexcept {
        int v = m_count.load(std::memory_order_acquire);
        while (v > 0) {
            if (m_count.compare_exchange_weak(v, v - 1,
                    std::memory_order_acquire, std::memory_order_relaxed))
                return true;
        }
        return false;
    }

    // Blocking: registers as a waiter then sleeps on futex.
    // On a single-core / single-threaded server this path is never taken —
    // the main thread only ever calls try_acquire().
    void acquire() noexcept {
        while (true) {
            if (try_acquire()) return;
            m_waiters.fetch_add(1, std::memory_order_relaxed);
            // Recheck count now that we are registered; if it went positive
            // between the failed try_acquire and the fetch_add above we would
            // otherwise sleep forever.
            int v = m_count.load(std::memory_order_acquire);
            if (v > 0) {
                m_waiters.fetch_sub(1, std::memory_order_relaxed);
                continue;
            }
            // futex_wait checks that count == v atomically; returns EAGAIN if
            // a release() slipped in between our load and this call.
            futex_wait(m_count, v);
            m_waiters.fetch_sub(1, std::memory_order_relaxed);
        }
    }

    // Release n units. Wakes at most n waiters only if any are registered.
    void release(ptrdiff_t update = 1) noexcept {
        m_count.fetch_add(static_cast<int>(update), std::memory_order_release);
        if (m_waiters.load(std::memory_order_acquire) > 0) {
            futex_wake(m_count, static_cast<int>(update));
        }
    }
};

using sem_type = futex_semaphore;

#else
#include <semaphore>
using sem_type = std::counting_semaphore<>;
#endif // __linux__

template<typename T>
class blocking_queue {
public:
    void push(T value) {
        m_queue.push(value);
        hint_size.fetch_add(1, std::memory_order_relaxed);
        m_sem.release();
    }
    void push_bulk(std::vector<T> values) {
        if(values.empty()) {
            return;
        }
        auto size = values.size();
        m_queue.push_bulk(std::move(values));
        hint_size.fetch_add(size, std::memory_order_relaxed);
        m_sem.release(size);
    }
    std::optional<T> try_pop() {
        bool acqu = m_sem.try_acquire();
        if(!acqu) {
            return std::nullopt;
        }
        auto res = m_queue.try_pop();
        hint_size.fetch_sub(1, std::memory_order_relaxed);
        return res;
    }
    T pop() {
        m_sem.acquire();
        auto res = *m_queue.try_pop();
        hint_size.fetch_sub(1, std::memory_order_relaxed);
        return res;
    }
    size_t size_hint() {
        return hint_size.load(std::memory_order_relaxed);
    }
private:
    std::atomic<int> hint_size = 0;
    sem_type m_sem{0};
    concurrent_queue<T> m_queue;
};

#endif // blocking_queue_hpp
