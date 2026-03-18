//
//  io_uring.h
//  HTTPS Server
//
//  Minimal liburing-compatible interface — only the operations used by this server.
//  Non-trivial functions are implemented in io_uring.cpp; trivial prep functions
//  are static inline here, matching the style of the real liburing.
//

#ifndef io_uring_h
#define io_uring_h

#ifdef __linux__

#include "uring_defs.hpp"

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <atomic>
#include <sys/socket.h>

// Kernel-compatible 64-bit timespec (matches struct __kernel_timespec)
struct uring_timespec {
    int64_t tv_sec;
    int64_t tv_nsec;
};

// -----------------------------------------------------------------------
// Ring descriptor
// -----------------------------------------------------------------------

struct io_uring {
    int ring_fd = -1;

    // Submission queue
    uint32_t*            sq_head       = nullptr;
    uint32_t*            sq_tail       = nullptr;
    uint32_t             sq_tail_local = 0;   // shadow tail: pending gets not yet submitted
    uint32_t             sq_ring_mask  = 0;
    uint32_t*            sq_array      = nullptr;
    struct io_uring_sqe* sqes          = nullptr;

    // Completion queue (single consumer)
    uint32_t*            cq_head      = nullptr;
    uint32_t*            cq_tail      = nullptr;
    uint32_t             cq_ring_mask = 0;
    struct io_uring_cqe* cqes         = nullptr;

    // Mapped regions
    void*  ring_ptr = nullptr;
    size_t ring_sz  = 0;
    void*  sqes_ptr = nullptr;
    size_t sqes_sz  = 0;

    std::atomic<size_t> in_flight { 0 };
};

// -----------------------------------------------------------------------
// Init / exit
// -----------------------------------------------------------------------

// Returns 0 on success; on failure prints to stderr and returns -1 with ring_fd < 0.
int  io_uring_queue_init(unsigned entries, struct io_uring* ring, unsigned flags);
void io_uring_queue_exit(struct io_uring* ring);

// -----------------------------------------------------------------------
// SQE acquisition and field helpers
// -----------------------------------------------------------------------

// Must be called under the same external lock as io_uring_submit.
// Returns nullptr if the SQ ring is full.
struct io_uring_sqe* io_uring_get_sqe(struct io_uring* ring);

static inline void io_uring_sqe_set_data64(struct io_uring_sqe* sqe, uint64_t data) {
    sqe->user_data = data;
}
static inline void io_uring_sqe_set_flags(struct io_uring_sqe* sqe, uint8_t flags) {
    sqe->flags = flags;
}

// -----------------------------------------------------------------------
// Prep functions — zero the SQE then fill the relevant fields
// -----------------------------------------------------------------------

static inline void io_uring_prep_recv(struct io_uring_sqe* sqe, int fd,
                                       void* buf, unsigned len, int flags) {
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_RECV;
    sqe->fd        = fd;
    sqe->addr      = reinterpret_cast<uint64_t>(buf);
    sqe->len       = len;
    sqe->msg_flags = static_cast<uint32_t>(flags);
}

static inline void io_uring_prep_send(struct io_uring_sqe* sqe, int fd,
                                       const void* buf, unsigned len, int flags) {
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode    = IORING_OP_SEND;
    sqe->fd        = fd;
    sqe->addr      = reinterpret_cast<uint64_t>(buf);
    sqe->len       = len;
    sqe->msg_flags = static_cast<uint32_t>(flags);
}

static inline void io_uring_prep_accept(struct io_uring_sqe* sqe, int fd,
                                         struct sockaddr* addr, socklen_t* addrlen,
                                         int flags) {
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode       = IORING_OP_ACCEPT;
    sqe->fd           = fd;
    sqe->addr         = reinterpret_cast<uint64_t>(addr);
    sqe->addr2        = reinterpret_cast<uint64_t>(addrlen);
    sqe->accept_flags = static_cast<uint32_t>(flags);
}

static inline void io_uring_prep_connect(struct io_uring_sqe* sqe, int fd,
                                          const struct sockaddr* addr, socklen_t addrlen) {
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_CONNECT;
    sqe->fd     = fd;
    sqe->addr   = reinterpret_cast<uint64_t>(addr);
    sqe->off    = addrlen;
}

static inline void io_uring_prep_link_timeout(struct io_uring_sqe* sqe,
                                               struct uring_timespec* ts,
                                               unsigned flags) {
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode        = IORING_OP_LINK_TIMEOUT;
    sqe->addr          = reinterpret_cast<uint64_t>(ts);
    sqe->len           = 1;
    sqe->timeout_flags = flags;
}

static inline void io_uring_prep_timeout(struct io_uring_sqe* sqe,
                                          struct uring_timespec* ts,
                                          unsigned count, unsigned flags) {
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode        = IORING_OP_TIMEOUT;
    sqe->addr          = reinterpret_cast<uint64_t>(ts);
    sqe->len           = count;
    sqe->timeout_flags = flags;
}

static inline void io_uring_prep_read(struct io_uring_sqe* sqe, int fd,
                                       void* buf, unsigned len, uint64_t offset) {
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READ;
    sqe->fd     = fd;
    sqe->off    = offset;
    sqe->addr   = reinterpret_cast<uint64_t>(buf);
    sqe->len    = len;
}

static inline void io_uring_prep_nop(struct io_uring_sqe* sqe) {
    std::memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_NOP;
}

// -----------------------------------------------------------------------
// Submit (must be called under the same external lock as io_uring_get_sqe)
// -----------------------------------------------------------------------

// Publishes all pending SQEs and submits them to the kernel.
// Returns the number of entries submitted.
int io_uring_submit(struct io_uring* ring);

// -----------------------------------------------------------------------
// CQE consumption (single-consumer — no lock needed)
// -----------------------------------------------------------------------

// Non-blocking peek: sets *cqe_ptr and returns 0 if a CQE is ready,
// or returns -EAGAIN if the CQ is empty.
int  io_uring_peek_cqe(struct io_uring* ring, struct io_uring_cqe** cqe_ptr);

// Mark nr CQEs as consumed, advancing the CQ head.
void io_uring_cq_advance(struct io_uring* ring, unsigned nr);

// -----------------------------------------------------------------------
// Blocking wait (called without the SQ lock)
// -----------------------------------------------------------------------

// Block until at least wait_nr CQEs are available.
int io_uring_wait_cqe_nr(struct io_uring* ring, unsigned wait_nr);

#endif // __linux__
#endif // io_uring_h
