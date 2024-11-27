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

#include "../../TCP/stream_base.hpp"

#ifdef __cpp_impl_coroutine
#include <coroutine>
#else
#include <experimental/coroutine>
namespace std {
    namespace experimental {}
    using namespace experimental;
}
#endif

using namespace std::chrono;

namespace fbw {

class HTTP2;
struct h2_data;
class h2_stream;

// co_await a writeable, shrinks the input buffer to the remaining buffer, and returns the bytes written
class h2writewindowable {
public:
    h2writewindowable(std::weak_ptr<HTTP2> connection, int32_t stream_id, uint32_t desired_size);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    int32_t await_resume(); // how many data bytes can we send?
private:
    std::weak_ptr<HTTP2> m_connection;
    int32_t m_stream_id;
    int64_t m_desired_size;
};

// co_await a readable, reads data - relevant to POST requests, not implemented yet
class h2readable {
public:
    h2readable(std::weak_ptr<HTTP2> connection, int32_t stream_id);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    std::pair<std::optional<h2_data>, stream_result> await_resume();
private:
    std::weak_ptr<HTTP2> m_connection;
    int32_t m_stream_id;
};

std::pair<std::shared_ptr<HTTP2>, std::shared_ptr<h2_stream>> lock_stream(std::weak_ptr<HTTP2> weak_conn, uint32_t stream_id);

// todo: this interface is a silly relic of when I considered writing data from multiple threads
//[[nodiscard]] task<stream_result> write_headers(std::weak_ptr<HTTP2> connection, int32_t stream_id, const std::vector<entry_t>& headers);
//[[nodiscard]] task<stream_result> write_some_data(std::weak_ptr<HTTP2> connection, int32_t stream_id, std::span<const uint8_t>& bytes, bool data_end);


class h2read_headers {
    std::weak_ptr<h2_stream> m_hstream;
public:
    h2read_headers(std::weak_ptr<h2_stream> hstream);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    std::pair<std::vector<entry_t>, stream_result> await_resume();
};

// todo: we need a stream_yield awaitable that suspends for owners, incrementing processable_streams 

}

#endif // writeable_hpp
