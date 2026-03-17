//
//  await_file.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/03/2026.
//

#include "await_file.hpp"
#include "../../Runtime/executor.hpp"

#include <unistd.h>

namespace fbw {

file_readable::file_readable(int fd, void* buf, uint32_t len, uint64_t offset) noexcept
    : m_fd(fd), m_buf(buf), m_len(len), m_offset(offset) {}

bool file_readable::await_suspend(std::coroutine_handle<> h) {
#ifdef __linux__
    if (executor_singleton().m_reactor.uring_ok()) {
        m_token.handle = h;
        if (executor_singleton().m_reactor.submit_read(m_fd, m_buf, m_len, m_offset, &m_token)) {
            m_used_uring = true;
            return true;  // suspend; will resume via CQE
        }
        // Ring full — fall through to synchronous pread.
    }
#endif
    m_res = ::pread(m_fd, m_buf, m_len, static_cast<off_t>(m_offset));
    return false;
}

ssize_t file_readable::await_resume() const noexcept {
#ifdef __linux__
    if (m_used_uring) {
        return static_cast<ssize_t>(m_token.res);  // positive = bytes read, negative = -errno
    }
#endif
    return m_res;
}

} // namespace fbw
