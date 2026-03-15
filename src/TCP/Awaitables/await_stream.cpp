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
#include <cerrno>

using namespace std::chrono_literals;
using namespace std::chrono;

namespace fbw {


readable::readable(int fd, std::span<uint8_t>& bytes, std::optional<milliseconds> millis ) :
    m_fd(fd), m_buffer(&bytes), m_millis(millis) {}

bool readable::await_ready() const noexcept {
    return false;
}

bool readable::await_suspend(std::coroutine_handle<> continuation) {
#ifdef __linux__
    assert(m_fd != -1);
    assert(m_buffer);
    if (m_millis && m_millis->count() == 0) {
        // 0ms means "non-blocking check"; io_uring has no non-blocking RECV,
        // so signal read_timeout without suspending.
        m_token.res = -EAGAIN;
        return false;
    }
    m_token.handle = continuation;
    executor_singleton().m_reactor.submit_recv(
        m_fd, m_buffer->data(), static_cast<uint32_t>(m_buffer->size()),
        &m_token, m_millis);
    return true;
#else
    assert(m_fd != -1);
    assert(m_buffer);
    ssize_t succ = ::recv(m_fd, m_buffer->data(), m_buffer->size(), MSG_NOSIGNAL);
    if(succ == 0) {
        m_bytes_read = m_buffer->subspan(0, succ);
        m_res = stream_result::closed;
        return false;
    }
    if(succ < 0) {
        if(errno == EWOULDBLOCK or errno == EAGAIN) {
            if(m_millis == 0ms) {
                m_res = stream_result::read_timeout;
                return false;
            }
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
#endif
}

std::pair<std::span<uint8_t>, stream_result> readable::await_resume() {
#ifdef __linux__
    int32_t res = m_token.res;
    if (res == 0) {
        return { std::span<uint8_t>{}, stream_result::closed };
    }
    if (res < 0) {
        int err = -res;
        if (err == ECANCELED || err == ETIMEDOUT || err == EAGAIN) {
            return { std::span<uint8_t>{}, stream_result::read_timeout };
        }
        return { std::span<uint8_t>{}, stream_result::closed };
    }
    auto bytes = m_buffer->subspan(0, static_cast<size_t>(res));
    *m_buffer = m_buffer->subspan(static_cast<size_t>(res));
    return { bytes, stream_result::ok };
#else
    if(m_res != stream_result::awaiting) {
        return {m_bytes_read, m_res};
    }
    assert(m_fd != -1);
    assert(m_buffer);
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
#endif
}

writeable::writeable(int fd, std::span<const uint8_t>& bytes, std::optional<milliseconds> millis )
    : m_fd(fd), m_buffer(&bytes), m_millis(millis) {}

bool writeable::await_ready() const noexcept {
    return false;
}

bool writeable::await_suspend(std::coroutine_handle<> continuation) {
#ifdef __linux__
    assert(m_fd != -1);
    assert(m_buffer);
    m_token.handle = continuation;
    executor_singleton().m_reactor.submit_send(
        m_fd, m_buffer->data(), static_cast<uint32_t>(m_buffer->size()),
        &m_token, m_millis);
    return true;
#else
    // process a few records before moving onto the next client
    //static std::atomic<size_t> fail_sometimes = 1;
    //size_t local_value = fail_sometimes.fetch_add(1, std::memory_order_relaxed);
    //local_value %= 10;
    //if(local_value == 0) {
    //    m_res = stream_result::awaiting;
    //    auto& exec = executor_singleton();
    //    exec.m_reactor.add_task(m_fd, continuation, IO_direction::Write, m_millis);
    //    return true;
    //}
    assert(m_fd != -1);
    assert(m_buffer);
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
#endif
}

std::pair<std::span<const uint8_t>, stream_result> writeable::await_resume() {
#ifdef __linux__
    int32_t res = m_token.res;
    if (res == 0) {
        return { std::span<const uint8_t>{}, stream_result::closed };
    }
    if (res < 0) {
        int err = -res;
        if (err == ECANCELED || err == ETIMEDOUT) {
            return { std::span<const uint8_t>{}, stream_result::write_timeout };
        }
        return { std::span<const uint8_t>{}, stream_result::closed };
    }
    auto bytes = m_buffer->subspan(0, static_cast<size_t>(res));
    *m_buffer = m_buffer->subspan(static_cast<size_t>(res));
    return { bytes, stream_result::ok };
#else

    if(m_res != stream_result::awaiting) {
        return {m_bytes_written, m_res};
    }
    assert(m_buffer);
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
#endif
}

} // namespace
