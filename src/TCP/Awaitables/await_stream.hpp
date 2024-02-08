//
//  writeable.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#ifndef writeable_hpp
#define writeable_hpp

#include <cstdio>
#include <span>

#include <chrono>
#include <optional>

#ifdef __cpp_impl_coroutine
#include <coroutine>
#else
#include <experimental/coroutine>
namespace std {
    namespace experimental {}
    using namespace experimental;
}
#endif

#include "../stream_base.hpp"

using namespace std::chrono;


namespace fbw {

// co_await a readable, shrinks the input buffer to the remaining buffer, and returns the bytes read
class readable {
public:
    readable(int fd, std::span<uint8_t>& buffer, std::optional<milliseconds> millis);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaitingCoroutine);
    std::span<uint8_t> await_resume();
private:
    ssize_t receive_or_park(std::coroutine_handle<> handle);
    
    int m_fd;
    ssize_t m_succ;
    std::span<uint8_t>* m_buffer;  // scoped to callee
    std::span<uint8_t> m_bytes_read;  // scoped to await_resume and await_suspend
    std::optional<milliseconds> m_millis;
};

// co_await a writeable, shrinks the input buffer to the remaining buffer, and returns the bytes written
class writeable {
public:
    writeable(int fd, std::span<const uint8_t>& bytes, std::optional<milliseconds> millis);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaitingCoroutine);
    std::span<const uint8_t> await_resume();
private:
    ssize_t send_or_park(std::coroutine_handle<> handle);
    
    int m_fd;
    ssize_t m_succ;
    std::span<const uint8_t>* m_buffer;
    std::span<const uint8_t> m_bytes_written; // scoped to await_resume and await_suspend
    std::optional<milliseconds> m_millis;
};

}

#endif // writeable_hpp
