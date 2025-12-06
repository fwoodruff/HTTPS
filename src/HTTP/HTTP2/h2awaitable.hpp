//
//  h2awaitable.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 21/09/2024.
//

#ifndef h2awaitable_hpp
#define h2awaitable_hpp

#include <cstdio>
#include <span>
#include <utility>

#include <chrono>
#include <optional>
#include <memory>
#include <queue>
#include <memory>
#include "hpack.hpp"

#include "../../IP/stream_base.hpp"

#include <coroutine>

using namespace std::chrono;

namespace fbw {

class HTTP2;
struct h2_data;
class h2_stream;

// awaits until stream write buffer is cleared and we can write more
class h2writeable {
public:
    h2writeable(std::weak_ptr<HTTP2> h2_contx, uint32_t stream_id);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    stream_result await_resume();
private:
    std::weak_ptr<HTTP2> m_h2_contx;
    uint32_t m_stream_id;
};

class unless_blocking_read {
public:
    unless_blocking_read(std::weak_ptr<HTTP2> h2_contx);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    stream_result await_resume();
private:
    std::weak_ptr<HTTP2> m_h2_contx;
};

class h2readable {
public:
    h2readable(std::weak_ptr<HTTP2> connection, int32_t stream_id, const std::span<uint8_t> data);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    std::pair<size_t, bool> await_resume();
private:
    std::optional<std::pair<uint32_t, bool>> m_bytes_read;
    std::weak_ptr<HTTP2> m_h2_contx;
    int32_t m_stream_id;
    std::span<uint8_t> m_data;
};

// todo: stream_yield awaitable that suspends for owners, incrementing processable_streams 
// todo: await trailing headers


}

#endif // writeable_hpp
