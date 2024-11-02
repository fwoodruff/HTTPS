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



// co_await a writeable, shrinks the input buffer to the remaining buffer, and returns the bytes written
class h2writewindowable {
public:
    h2writewindowable(std::weak_ptr<HTTP2> connection, int32_t stream_id);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    std::pair<stream_result, int32_t> await_resume(); // how many data bytes can we send?
private:
    std::weak_ptr<HTTP2> m_connection;
    int32_t m_stream_id;
};

class extract_current_handle {
public:
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    std::coroutine_handle<> await_resume();
private:
    std::coroutine_handle<> handle;
};

class async_mutex {
public:
    class lockable {
    public:
        bool await_ready() const noexcept;
        bool await_suspend(std::coroutine_handle<> continuation);
        void await_resume(); // how many data bytes can we send?
        lockable(async_mutex* ptr);
    private:
        async_mutex* p_async_mut;
    };

    lockable lock();
    void unlock();
private:
    std::mutex mut;
    bool locked = false;
    std::queue<std::coroutine_handle<>> waiters;
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

// todo: we need a stream_yield awaitable that suspends for owners, incrementing processable_streams 

}

#endif // writeable_hpp
