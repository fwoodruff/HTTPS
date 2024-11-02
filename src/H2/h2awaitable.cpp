//
//  h2awaitable.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 21/09/2024.
//

#include "h2awaitable.hpp"
#include "h2frame.hpp"
#include "h2proto.hpp"
#include <span>

using namespace std::chrono_literals;
using namespace std::chrono;

namespace fbw {

std::pair<std::shared_ptr<HTTP2>, std::shared_ptr<h2_stream>> lock_stream(std::weak_ptr<HTTP2> weak_conn, uint32_t stream_id) {
    auto conn = weak_conn.lock();
    if(conn == nullptr) {
        return {nullptr, nullptr};
    }
    auto it = conn->m_h2streams.find(stream_id);
    if(it == conn->m_h2streams.end()) {
        return { conn, nullptr };
    }
    return { conn, it->second };
}

task<stream_result> write_data(std::weak_ptr<HTTP2> connection, int32_t stream_id, std::span<const uint8_t> bytes) {
    auto [ stream_res, num_bytes ] = co_await h2writewindowable{ connection, stream_id };
    if(stream_res != stream_result::ok) {
        co_return stream_res;
    }
    auto [ conn, stream ] = lock_stream(connection, stream_id);
    ssize_t bytes_to_write = std::min(size_t(num_bytes), bytes.size());
    while(bytes_to_write > 0) {
        auto frame_size = std::max(ssize_t(conn->server_settings.max_frame_size), bytes_to_write);
        h2_data frame;
        frame.data.assign(bytes.begin(), bytes.begin() + frame_size);
        auto strmres = co_await conn->write_safe(frame.serialise(), project_options.session_timeout);
        if(strmres != stream_result::ok) {
            co_return strmres;
        }
        bytes = bytes.subspan(frame_size);
        bytes_to_write -= frame_size;
        assert(bytes_to_write >= 0);
    }
    co_return stream_result::ok;
}

h2writewindowable::h2writewindowable(std::weak_ptr<HTTP2> connection, int32_t stream_id)
    : m_connection(connection), m_stream_id(stream_id) {}

bool h2writewindowable::await_ready() const noexcept {
    return false;
}

bool h2writewindowable::await_suspend(std::coroutine_handle<> continuation) { // placeholder: ignores windowing 
    //auto [ conn, stream ] = lock_stream(m_connection, m_stream_id);
    (void)m_stream_id;
    return true;
}

std::pair<stream_result, int32_t> h2writewindowable::await_resume() {
    return {stream_result::ok, 0x7fffffff};
}

bool async_mutex::lockable::await_ready() const noexcept {
    return false;
}

bool async_mutex::lockable::await_suspend(std::coroutine_handle<> continuation) {
    std::scoped_lock lk {p_async_mut->mut};
    if(p_async_mut->locked) {
        p_async_mut->waiters.push(continuation);
        return false;
    }
    p_async_mut->locked = true;
    return true;
}

void async_mutex::lockable::await_resume() {}

async_mutex::lockable async_mutex::lock() {
    return lockable{this};
}

async_mutex::lockable::lockable(async_mutex* ptr) : p_async_mut(ptr) {}

void async_mutex::unlock() {
    while(true) {
        std::queue<std::coroutine_handle<>> local_queue;
        {
            std::scoped_lock lk{mut};
            if(waiters.empty()) {
                locked = false;
                return;
            }
            local_queue = std::exchange(waiters, {});
        }
        while(!local_queue.empty()) {
            auto continuation = std::move(local_queue.front());
            local_queue.pop();
            continuation.resume();
        }
    }
}

bool extract_current_handle::await_ready() const noexcept {
    return false;
}

bool extract_current_handle::await_suspend(std::coroutine_handle<> awaiting_coroutine) {
    handle = awaiting_coroutine;
    return false;
}

std::coroutine_handle<> extract_current_handle::await_resume() {
    return handle;
}

h2readable::h2readable(std::weak_ptr<HTTP2> connection, int32_t stream_id) :
    m_connection(connection), m_stream_id(stream_id) {}

bool h2readable::await_suspend(std::coroutine_handle<> continuation) {
    auto [ conn, stream ] = lock_stream(m_connection, m_stream_id);
    if(!conn) {
        // if the connection is dead, we need to resume and fail
        return false;
    }
    if(!stream) {
        // if the stream is dead, then resume and fail
        return false;
    }
    if(!stream->inbox.empty()) {
        // if data is awaint, resume succeed
        return false;
    }
    // todo: send a WINDOW_UPDATE if necessary
    stream->m_reader.store(continuation);
    return true;
}

std::pair<std::optional<h2_data>, stream_result> h2readable::await_resume() {
    auto [ conn, stream ] = lock_stream(m_connection, m_stream_id);
    if(!stream) {
        return {std::nullopt, stream_result::closed};
    }
    // the stream might not exist if this is called after closing the stream (logically ok but revisit)
    if(stream->inbox.empty()) {
        assert(false); // not quite sure how we'd end up here, revisit
        return { std::nullopt, stream_result::closed };
    }
    auto res = std::move(stream->inbox.front());
    stream->inbox.pop();
    return {{std::move(res)}, stream_result::ok};
}

bool h2readable::await_ready() const noexcept {
    return false;
}

} // namespace
