//
//  await_file.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/03/2026.
//

#ifndef await_file_hpp
#define await_file_hpp

#include <coroutine>
#include <cstdint>
#include <sys/types.h>

#ifdef __linux__
#include "../../Runtime/uring_reactor.hpp"
#endif

namespace fbw {

// Asynchronously reads len bytes from fd at the given offset (like pread).
// On Linux with io_uring: submits IORING_OP_READ and suspends the coroutine.
// Otherwise: performs a synchronous pread and returns immediately.
// await_resume() returns the number of bytes read, or a negative errno value.
class file_readable {
public:
    file_readable(int fd, void* buf, uint32_t len, uint64_t offset) noexcept;

    bool   await_ready()   const noexcept { return false; }
    bool   await_suspend(std::coroutine_handle<> h);
    ssize_t await_resume() const noexcept;

private:
    int      m_fd;
    void*    m_buf;
    uint32_t m_len;
    uint64_t m_offset;
#ifdef __linux__
    uring_token m_token {};
    bool        m_used_uring = false;
#endif
    ssize_t m_res = 0;
};

} // namespace fbw

#endif // await_file_hpp
