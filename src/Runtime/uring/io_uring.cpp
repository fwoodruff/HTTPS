//
//  io_uring.cpp
//  HTTPS Server
//

#ifdef __linux__

#include "io_uring.h"

#include <sys/mman.h>
#include <sys/syscall.h>
#include <signal.h>
#include <unistd.h>
#include <stdexcept>
#include <algorithm>
#include <atomic>
#include <print>
#include <cerrno>

// Syscall numbers are stable Linux ABI; provide fallbacks for cross-compilers
// that don't ship kernel headers with these defines.
#ifndef __NR_io_uring_setup
#  define __NR_io_uring_setup  425
#  define __NR_io_uring_enter  426
#endif

static int sys_io_uring_setup(uint32_t entries, struct io_uring_params* p) {
    return (int)syscall(__NR_io_uring_setup, entries, p);
}

static int sys_io_uring_enter(int fd, uint32_t to_submit, uint32_t min_complete,
                               uint32_t flags) {
    return (int)syscall(__NR_io_uring_enter, fd, to_submit, min_complete, flags,
                        (sigset_t*)nullptr, (size_t)(_NSIG / 8));
}

// -----------------------------------------------------------------------
// Init / exit
// -----------------------------------------------------------------------

int io_uring_queue_init(unsigned entries, struct io_uring* ring, unsigned /*flags*/) {
    struct io_uring_params p {};
    ring->ring_fd = sys_io_uring_setup(entries, &p);
    if (ring->ring_fd < 0) {
        std::println(stderr, "io_uring unavailable (errno {}), falling back to poll reactor", errno);
        return -1;
    }
    if (!(p.features & IORING_FEAT_SINGLE_MMAP)) {
        std::println(stderr, "io_uring lacks IORING_FEAT_SINGLE_MMAP, falling back to poll reactor");
        ::close(ring->ring_fd);
        ring->ring_fd = -1;
        return -1;
    }

    size_t sq_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    size_t cq_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    ring->ring_sz = std::max(sq_sz, cq_sz);
    ring->ring_ptr = ::mmap(nullptr, ring->ring_sz, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE, ring->ring_fd, IORING_OFF_SQ_RING);
    if (ring->ring_ptr == MAP_FAILED) {
        ::close(ring->ring_fd);
        ring->ring_fd  = -1;
        ring->ring_ptr = nullptr;
        return -1;
    }

    ring->sqes_sz  = p.sq_entries * sizeof(struct io_uring_sqe);
    ring->sqes_ptr = ::mmap(nullptr, ring->sqes_sz, PROT_READ | PROT_WRITE,
                            MAP_SHARED | MAP_POPULATE, ring->ring_fd, IORING_OFF_SQES);
    if (ring->sqes_ptr == MAP_FAILED) {
        ::munmap(ring->ring_ptr, ring->ring_sz);
        ::close(ring->ring_fd);
        ring->ring_fd  = -1;
        ring->ring_ptr = nullptr;
        ring->sqes_ptr = nullptr;
        return -1;
    }

    auto* base = static_cast<char*>(ring->ring_ptr);
    ring->sq_head      = reinterpret_cast<uint32_t*>(base + p.sq_off.head);
    ring->sq_tail      = reinterpret_cast<uint32_t*>(base + p.sq_off.tail);
    ring->sq_ring_mask = *reinterpret_cast<uint32_t*>(base + p.sq_off.ring_mask);
    ring->sq_flags     = reinterpret_cast<uint32_t*>(base + p.sq_off.flags);
    ring->sq_array     = reinterpret_cast<uint32_t*>(base + p.sq_off.array);
    ring->sqes         = static_cast<struct io_uring_sqe*>(ring->sqes_ptr);

    ring->cq_head      = reinterpret_cast<uint32_t*>(base + p.cq_off.head);
    ring->cq_tail      = reinterpret_cast<uint32_t*>(base + p.cq_off.tail);
    ring->cq_ring_mask = *reinterpret_cast<uint32_t*>(base + p.cq_off.ring_mask);
    ring->cqes         = reinterpret_cast<struct io_uring_cqe*>(base + p.cq_off.cqes);

    return 0;
}

void io_uring_queue_exit(struct io_uring* ring) {
    if (ring->sqes_ptr && ring->sqes_ptr != MAP_FAILED) ::munmap(ring->sqes_ptr, ring->sqes_sz);
    if (ring->ring_ptr && ring->ring_ptr != MAP_FAILED) ::munmap(ring->ring_ptr, ring->ring_sz);
    if (ring->ring_fd >= 0) ::close(ring->ring_fd);
    ring->ring_fd  = -1;
    ring->ring_ptr = nullptr;
    ring->sqes_ptr = nullptr;
}

// -----------------------------------------------------------------------
// SQE acquisition (caller must hold external lock)
// -----------------------------------------------------------------------

struct io_uring_sqe* io_uring_get_sqe(struct io_uring* ring) {
    uint32_t head = std::atomic_ref<uint32_t>(*ring->sq_head).load(std::memory_order_acquire);
    if (ring->sq_tail_local - head > ring->sq_ring_mask) return nullptr;
    uint32_t idx = ring->sq_tail_local & ring->sq_ring_mask;
    ring->sq_array[idx] = idx;
    ++ring->sq_tail_local;
    return &ring->sqes[idx];
}

// -----------------------------------------------------------------------
// Submit (caller must hold external lock)
// -----------------------------------------------------------------------

int io_uring_submit(struct io_uring* ring) {
    // Compute how many SQEs have been gotten but not yet published
    uint32_t published = std::atomic_ref<uint32_t>(*ring->sq_tail).load(std::memory_order_relaxed);
    uint32_t n = ring->sq_tail_local - published;
    if (n == 0) return 0;
    std::atomic_ref<uint32_t>(*ring->sq_tail).store(ring->sq_tail_local, std::memory_order_release);
    sys_io_uring_enter(ring->ring_fd, n, 0, 0);
    ring->in_flight.fetch_add(n, std::memory_order_relaxed);
    return static_cast<int>(n);
}

// -----------------------------------------------------------------------
// CQE consumption (single consumer)
// -----------------------------------------------------------------------

int io_uring_peek_cqe(struct io_uring* ring, struct io_uring_cqe** cqe_ptr) {
    uint32_t head = std::atomic_ref<uint32_t>(*ring->cq_head).load(std::memory_order_relaxed);
    uint32_t tail = std::atomic_ref<uint32_t>(*ring->cq_tail).load(std::memory_order_acquire);
    if (head == tail) { *cqe_ptr = nullptr; return -EAGAIN; }
    *cqe_ptr = &ring->cqes[head & ring->cq_ring_mask];
    return 0;
}

void io_uring_cq_advance(struct io_uring* ring, unsigned nr) {
    std::atomic_ref<uint32_t>(*ring->cq_head).fetch_add(nr, std::memory_order_release);
    ring->in_flight.fetch_sub(nr, std::memory_order_relaxed);
}

// -----------------------------------------------------------------------
// Blocking wait
// -----------------------------------------------------------------------

int io_uring_wait_cqe_nr(struct io_uring* ring, unsigned wait_nr) {
    return sys_io_uring_enter(ring->ring_fd, 0, wait_nr, IORING_ENTER_GETEVENTS);
}

int io_uring_get_events(struct io_uring* ring) {
    return sys_io_uring_enter(ring->ring_fd, 0, 0, IORING_ENTER_GETEVENTS);
}

#endif // __linux__
