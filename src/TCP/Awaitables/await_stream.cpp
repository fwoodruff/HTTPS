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
    ssize_t succ = ::recv(m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    if(succ == 0) {
        m_bytes_read = m_buffer->subspan(0, succ);
        m_res = stream_result::closed;
        return false;
    }
    if(succ < 0) {
        if(errno == EWOULDBLOCK or errno == EAGAIN) {
            auto& exec = executor_singleton();
            exec.m_reactor.add_task(m_fd, continuation, IO_direction::Read, m_millis);
            m_res = stream_result::awaiting;
            return true;
        }
        m_bytes_read = m_buffer->subspan(0, succ);
        m_res = stream_result::closed;
        return false;
    }
    if(succ > 0) {
        m_bytes_read = m_buffer->subspan(0, succ);
        m_res = stream_result::ok;
        return false;
    }
    assert(false);
}

std::pair<std::span<uint8_t>, stream_result> readable::await_resume() {
    if(m_res != stream_result::awaiting) {
        return {m_bytes_read, m_res};
    }
    ssize_t succ = ::recv(m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    if(succ == 0) {
        return {std::span<uint8_t>(), stream_result::closed };
    }
    if(succ < 0) {
        if(errno == EWOULDBLOCK or errno == EAGAIN) {
            return { std::span<uint8_t>(), stream_result::read_timeout };
        }
        return { std::span<uint8_t>(), stream_result::closed };
    }
    if(succ > 0) {
        m_bytes_read = m_buffer->subspan(0, succ);
        *m_buffer = m_buffer->subspan(succ);
        m_res = stream_result::ok;
        return { m_bytes_read, m_res};
    }
    return {m_bytes_read, m_res};
}

writeable::writeable(int fd, std::span<const uint8_t>& bytes, std::optional<milliseconds> millis )
    : m_fd(fd), m_buffer(&bytes), m_millis(millis) {}

bool writeable::await_ready() const noexcept {
    return false;
}

bool writeable::await_suspend(std::coroutine_handle<> continuation) {
    // process a few records before moving onto the next client
    static std::atomic<size_t> fail_sometimes = 1;
    size_t local_value = fail_sometimes.fetch_add(1, std::memory_order_relaxed);
    local_value %= 10;
    if(local_value == 0) {
        m_res = stream_result::awaiting;
        auto& exec = executor_singleton();
        exec.m_reactor.add_task(m_fd, continuation, IO_direction::Write, m_millis);
        return true;
    }
    ssize_t succ = ::send(m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    if(succ == 0) {
        m_bytes_written = m_buffer->subspan(0, 0);
        m_res = stream_result::closed;
        return false;
    }
    if(succ < 0) {
        if(errno == EWOULDBLOCK or errno == EAGAIN) {
            m_res = stream_result::awaiting;
            auto& exec = executor_singleton();
            exec.m_reactor.add_task(m_fd, continuation, IO_direction::Write, m_millis);
            return true;
        }
        
        m_bytes_written = m_buffer->subspan(0, 0);
        m_res = stream_result::closed;
        return false;
    }
    if(succ > 0) {
        m_bytes_written = m_buffer->subspan(0, succ);
        *m_buffer = m_buffer->subspan(succ);
        m_res = stream_result::ok;
        return false;
    }
    assert(false);
}

std::pair<std::span<const uint8_t>, stream_result> writeable::await_resume() {
    
    if(m_res != stream_result::awaiting) {
        return {m_bytes_written, m_res};
    }
    ssize_t succ = ::send(m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    if(succ == 0) {
        return { std::span<uint8_t>(), stream_result::closed };
    }
    if(succ < 0) {
        if(errno == EWOULDBLOCK or errno == EAGAIN) {
            return { std::span<uint8_t>(), stream_result::write_timeout };
        }
        return { std::span<uint8_t>(), stream_result::closed };
    }
    if(succ > 0) {
        m_bytes_written = m_buffer->subspan(0, succ);
        *m_buffer = m_buffer->subspan(succ);
        m_res = stream_result::ok;
        return { m_bytes_written, m_res };
    }
    assert(false);
}

} // namespace
