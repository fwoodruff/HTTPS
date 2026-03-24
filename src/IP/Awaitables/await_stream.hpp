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

#include <coroutine>

#include "../stream_base.hpp"

#ifdef __linux__
#include "../../Runtime/uring_reactor.hpp"
#endif

using namespace std::chrono;


namespace fbw {

// co_await a readable, shrinks the input buffer to the remaining buffer, and returns the bytes read
class readable {
public:
    readable(int fd, std::span<uint8_t>& buffer, std::optional<milliseconds> millis);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    std::pair<std::span<uint8_t>, stream_result> await_resume();
private:
    int m_fd;
    std::span<uint8_t>* m_buffer;
    std::optional<milliseconds> m_millis;
    stream_result m_res {};
    std::span<uint8_t> m_bytes_read;
#ifdef __linux__
    uring_token m_token {};
#endif
};

// co_await a writeable, shrinks the input buffer to the remaining buffer, and returns the bytes written
class writeable {
public:
    writeable(int fd, std::span<const uint8_t>& bytes, std::optional<milliseconds> millis);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    std::pair<std::span<const uint8_t>, stream_result> await_resume();
private:
    int m_fd;
    std::span<const uint8_t>* m_buffer;
    std::optional<milliseconds> m_millis;
    stream_result m_res {};
    std::span<const uint8_t> m_bytes_written;
#ifdef __linux__
    uring_token m_token {};
#endif
};

}

#endif // writeable_hpp
