//
//  writeable.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#include "await_stream.hpp"
#include "executor.hpp"

#include <sys/socket.h>
#include <span>



using namespace std::chrono_literals;
using namespace std::chrono;

namespace fbw {

void park(ssize_t succ, int fd, std::coroutine_handle<> continuation, IO_direction rw, std::optional<milliseconds> timeout) {
    if(succ == -1) {
        if(errno == EWOULDBLOCK or errno == EAGAIN) {
            if(!continuation) {
                throw stream_error("timed out");
            }
            auto& exec = executor_singleton();
            exec.m_reactor.add_task(fd, continuation, rw, timeout);
        } else {
            throw stream_error("operation failed");
        }
    }
}

ssize_t readable::receive_or_park( std::coroutine_handle<> handle) {
    
    ssize_t succ = recv(m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    
    park(succ, m_fd, handle, IO_direction::Read, m_millis);
    if(succ >= 0) {
        m_bytes_read = m_buffer->subspan(0, succ);
        *m_buffer = m_buffer->subspan(succ);
    }
    return succ;
}

ssize_t writeable::send_or_park(std::coroutine_handle<> handle) {
    ssize_t succ = ::send(m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    park(succ, m_fd, handle, IO_direction::Write, m_millis);
    if(succ >= 0) {
        m_bytes_written = m_buffer->subspan(0, succ);
        *m_buffer = m_buffer->subspan(succ);
    }
    return succ;
}

readable::readable(int fd, std::span<uint8_t>& bytes, std::optional<milliseconds> millis ) :
    m_fd(fd), m_buffer(&bytes), m_millis(millis) {}

bool readable::await_ready() const noexcept {
    return false;
}

bool readable::await_suspend(std::coroutine_handle<> awaitingCoroutine) {
    m_succ = receive_or_park(awaitingCoroutine);
    return m_succ == -1;
}

std::span<uint8_t> readable::await_resume() {
    if(m_succ != -1) {
        return m_bytes_read;
    }
    receive_or_park(nullptr);
    return m_bytes_read;
}

writeable::writeable(int fd, std::span<const uint8_t>& bytes, std::optional<milliseconds> millis )
    : m_fd(fd), m_buffer(&bytes), m_millis(millis) {}

bool writeable::await_ready() const noexcept {
    return false;
}



bool writeable::await_suspend(std::coroutine_handle<> awaitingCoroutine) {
    // process a few records before moving onto the next client
    static std::atomic<size_t> fail_sometimes = 0;
    size_t local_value = fail_sometimes.fetch_add(1, std::memory_order_relaxed);
    local_value %= 3;
    if(local_value == 0) {
        m_succ = -1;
        auto& exec = executor_singleton();
        exec.m_reactor.add_task(m_fd, awaitingCoroutine, IO_direction::Write, m_millis);
        return true;
    }
    
    m_succ = send_or_park(awaitingCoroutine);
    return m_succ == -1;
}

std::span<const uint8_t> writeable::await_resume() {
    if(m_succ != -1) {
        return m_bytes_written;
    }
    send_or_park(nullptr);
    return m_bytes_written;
}

} // namespace
