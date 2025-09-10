//
//  writeable.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#include "await_stream.hpp"
#include "../stream_base.hpp"
#include "../../Runtime/executor.hpp"

#include <sys/socket.h>
#include <liburing.h>
#include <span>

using namespace std::chrono_literals;
using namespace std::chrono;

namespace fbw {


readable::readable(int fd, std::span<uint8_t>& bytes, std::optional<milliseconds> millis ) :
    m_fd(fd), m_buffer(&bytes), m_millis(millis) {}

bool readable::await_ready() const noexcept {
    return false;
}

bool readable::await_suspend(std::coroutine_handle<> continuation) {
    assert(m_fd != -1);
    assert(m_buffer);
    this_coro = continuation;
    io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) {
        m_res = stream_result::closed;
        return false;
    }
    io_uring_sqe* ts_sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) {
        m_res = stream_result::closed;
        return false;
    }
    io_uring_prep_recv(sqe, m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    uint64_t user_data = std::bit_cast<uint64_t>(this);
    sqe->user_data = user_data;
    if(m_millis) {
        __kernel_timespec ts;
        ts.tv_sec = m_millis->count() / 1000;
        ts.tv_nsec = (m_millis->count() % 1000) * 1'000'000;
        io_uring_prep_link_timeout(ts_sqe, &ts, 0);
        ts_sqe->user_data = user_data;
    }
    io_uring_submit(&m_ring);
    return true;
}

std::pair<std::span<uint8_t>, stream_result> readable::await_resume() {
    return {m_bytes_read, m_res};
}

writeable::writeable(int fd, std::span<const uint8_t>& bytes, std::optional<milliseconds> millis )
    : m_fd(fd), m_buffer(&bytes), m_millis(millis) {}

bool writeable::await_ready() const noexcept {
    return false;
}

bool writeable::await_suspend(std::coroutine_handle<> continuation) {
    assert(m_fd != -1);
    assert(m_buffer);
    this_coro = continuation;
    io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) {
        m_res = stream_result::closed;
        return false;
    }
    io_uring_prep_send(sqe, m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    uint64_t user_data = std::bit_cast<uint64_t>(this);
    sqe->user_data = user_data;

    if(m_millis) {
        __kernel_timespec ts;
        ts.tv_sec = m_millis->count() / 1000;
        ts.tv_nsec = (m_millis->count() % 1000) * 1'000'000;
        io_uring_prep_link_timeout(ts_sqe, &ts, 0);
        ts_sqe->user_data = user_data;
    }
    return true;

}

std::pair<std::span<const uint8_t>, stream_result> writeable::await_resume() {
    return { m_bytes_written, m_res };
}

} // namespace
