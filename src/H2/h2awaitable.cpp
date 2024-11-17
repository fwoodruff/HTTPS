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

// writes as much as window allows then return
task<stream_result> write_some_data(std::weak_ptr<HTTP2> connection, int32_t stream_id, std::span<const uint8_t>& bytes) {
    auto num_bytes = co_await h2writewindowable{ connection, stream_id, (uint32_t)bytes.size() };
    auto [ conn, stream ] = lock_stream(connection, stream_id);
    if(stream == nullptr or conn->notify_close_sent) {
        co_return stream_result::closed;
    }
    ssize_t bytes_to_write = std::min(size_t(num_bytes), bytes.size());
    while(bytes_to_write > 0) {
        auto frame_size = std::max(ssize_t(conn->server_settings.max_frame_size), bytes_to_write);
        h2_data frame;
        frame.contents.assign(bytes.begin(), bytes.begin() + frame_size);
        assert(!conn->notify_close_sent);
        auto strmres = co_await conn->m_stream->write(frame.serialise(), project_options.session_timeout);
        if(strmres != stream_result::ok) {
            co_return strmres;
        }
        bytes = bytes.subspan(frame_size);
        bytes_to_write -= frame_size;
        assert(bytes_to_write >= 0);
    }
    co_return stream_result::ok;
}

h2writewindowable::h2writewindowable(std::weak_ptr<HTTP2> connection, int32_t stream_id, uint32_t desired_size)
    : m_connection(connection), m_stream_id(stream_id), m_desired_size(desired_size) {}

bool h2writewindowable::await_ready() const noexcept {
    return false;
}

bool h2writewindowable::await_suspend(std::coroutine_handle<> continuation) {
    auto [ conn, stream ] = lock_stream(m_connection, m_stream_id);
    if(!conn) {
        return false;
    }
    if(!stream) {
        return false;
    }
    if(conn->connection_current_window <= 0) {
        conn->waiters_global.push(continuation);
        return true;
    }
    if(stream->stream_current_window <= 0) {
        stream->m_writer = continuation;
        return true;
    }
    auto siz = std::min(conn->connection_current_window, stream->stream_current_window);
    siz = std::min(siz, (int64_t)m_desired_size);
    conn->connection_current_window -= siz;
    stream->stream_current_window -= siz;
    window_size = siz;
    return false;
}

int32_t h2writewindowable::await_resume() {
    auto [ conn, stream ] = lock_stream(m_connection, m_stream_id);
    if(!conn) {
        return 0;
    }
    if(!stream) {
        return 0;
    }
    if(window_size != 0) {
        return window_size;
    }
    auto siz = std::min(conn->connection_current_window, stream->stream_current_window);
    siz = std::min(siz, (int64_t)m_desired_size);
    siz = std::max(siz, int64_t(0));
    conn->connection_current_window -= siz;
    stream->stream_current_window -= siz;
    return siz;
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
    stream->m_reader = continuation;
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
