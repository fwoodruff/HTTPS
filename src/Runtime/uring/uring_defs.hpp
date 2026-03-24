//
//  uring_defs.hpp
//  HTTPS Server
//
//  Minimal io_uring ABI definitions for kernels >= 5.1.
//  Derived from linux/io_uring.h which is dual-licensed GPL-2.0/MIT.
//  These structs are part of the stable userspace ABI and will not change.
//

#ifndef uring_defs_hpp
#define uring_defs_hpp

#ifdef __linux__

#include <cstdint>

// Submission Queue Entry
struct io_uring_sqe {
    uint8_t  opcode;
    uint8_t  flags;
    uint16_t ioprio;
    int32_t  fd;
    union { uint64_t off; uint64_t addr2; };
    union { uint64_t addr; uint64_t splice_off_in; };
    uint32_t len;
    union {
        uint32_t rw_flags;
        uint32_t fsync_flags;
        uint16_t poll_events;
        uint32_t poll32_events;
        uint32_t sync_range_flags;
        uint32_t msg_flags;
        uint32_t timeout_flags;
        uint32_t accept_flags;
        uint32_t cancel_flags;
        uint32_t open_flags;
        uint32_t statx_flags;
        uint32_t fadvise_advice;
        uint32_t splice_flags;
    };
    uint64_t user_data;
    union {
        struct {
            union { uint16_t buf_index; uint16_t buf_group; } __attribute__((packed));
            uint16_t personality;
            int32_t  splice_fd_in;
        };
        uint64_t __pad2[3];
    };
};

// SQE flags
static constexpr uint8_t IOSQE_IO_LINK = (1u << 2);

// SQ ring flags (written by the kernel into sq_off.flags)
static constexpr uint32_t IORING_SQ_CQ_OVERFLOW = (1u << 1);  // CQ ring is full; call GETEVENTS to flush

// Completion Queue Entry
struct io_uring_cqe {
    uint64_t user_data;
    int32_t  res;
    uint32_t flags;
};

// Ring mmap offsets
static constexpr uint64_t IORING_OFF_SQ_RING = 0ULL;
static constexpr uint64_t IORING_OFF_CQ_RING = 0x8000000ULL;
static constexpr uint64_t IORING_OFF_SQES    = 0x10000000ULL;

// io_uring_enter flags
static constexpr uint32_t IORING_ENTER_GETEVENTS = 1u;

// io_uring_params feature flags
static constexpr uint32_t IORING_FEAT_SINGLE_MMAP = 1u;

// Opcodes used by this server
enum {
    IORING_OP_NOP          = 0,
    IORING_OP_READV        = 1,
    IORING_OP_WRITEV       = 2,
    IORING_OP_RECVMSG      = 3,
    IORING_OP_SENDMSG      = 4,
    IORING_OP_POLL_ADD     = 6,
    IORING_OP_TIMEOUT      = 11,
    IORING_OP_LINK_TIMEOUT = 15,
    IORING_OP_ACCEPT       = 13,
    IORING_OP_CONNECT      = 16,
    IORING_OP_READ         = 22,
    IORING_OP_SEND         = 26,
    IORING_OP_RECV         = 27,
};

// SQ / CQ ring offset descriptors (populated by io_uring_setup)
struct io_sqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t flags;
    uint32_t dropped;
    uint32_t array;
    uint32_t resv1;
    uint64_t resv2;
};

struct io_cqring_offsets {
    uint32_t head;
    uint32_t tail;
    uint32_t ring_mask;
    uint32_t ring_entries;
    uint32_t overflow;
    uint32_t cqes;
    uint32_t flags;
    uint32_t resv1;
    uint64_t resv2;
};

// Parameters passed to and filled by io_uring_setup
struct io_uring_params {
    uint32_t sq_entries;
    uint32_t cq_entries;
    uint32_t flags;
    uint32_t sq_thread_cpu;
    uint32_t sq_thread_idle;
    uint32_t features;
    uint32_t wq_fd;
    uint32_t resv[3];
    struct io_sqring_offsets sq_off;
    struct io_cqring_offsets cq_off;
};

#endif // __linux__
#endif // uring_defs_hpp
