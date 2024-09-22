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

#include "../TCP/stream_base.hpp"


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

// co_await a readable, shrinks the input buffer to the remaining buffer, and returns the bytes read
class h2readable {
public:
    h2readable(std::weak_ptr<HTTP2> connection, int32_t stream_id);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaitingCoroutine);
    std::pair<std::optional<h2_data>, stream_result> await_resume();
private:
    std::weak_ptr<HTTP2> m_connection;
    int32_t m_stream_id;
};

// co_await a writeable, shrinks the input buffer to the remaining buffer, and returns the bytes written
class h2writeable {
public:
    h2writeable(std::weak_ptr<HTTP2> connection, int32_t stream_id);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaitingCoroutine);
    std::pair<stream_result, int32_t> await_resume(); // how many data bytes can we send?
private:
    std::weak_ptr<HTTP2> m_connection;
    int32_t m_stream_id;
};

}

#endif // writeable_hpp
