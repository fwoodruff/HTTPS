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
#include <utility>

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
    std::pair<std::span<uint8_t>, stream_result> await_resume();
private:
    
    int m_fd;
    stream_result m_res;
    std::span<uint8_t> m_bytes_read;  // scoped to await_resume and await_suspend
    std::span<uint8_t>* m_buffer; // scoped to caller
    std::optional<milliseconds> m_millis;
};

// co_await a writeable, shrinks the input buffer to the remaining buffer, and returns the bytes written
class writeable {
public:
    writeable(int fd, std::span<const uint8_t>& bytes, std::optional<milliseconds> millis);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaitingCoroutine);
    std::pair<std::span<const uint8_t>, stream_result> await_resume();
private:
    
    int m_fd;
    stream_result m_res;
    std::span<const uint8_t>* m_buffer;
    std::span<const uint8_t> m_bytes_written; // scoped to await_resume and await_suspend
    std::optional<milliseconds> m_millis;
};

}

#endif // writeable_hpp
