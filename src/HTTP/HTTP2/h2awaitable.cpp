//
//  h2awaitable.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 21/09/2024.
//

#include "h2awaitable.hpp"
#include "h2frame.hpp"
#include "h2proto.hpp"
#include "h2stream.hpp"
#include <span>

using namespace std::chrono_literals;
using namespace std::chrono;

namespace fbw {

// todo: overused - many functions should just be members of the connection
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
    if(conn->connection_current_window_remaining <= 0) {
        conn->waiters_global.push(continuation);
        return true;
    }
    if(stream->stream_current_window_remaining <= 0) {
        stream->m_writer = continuation;
        return true;
    }
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
    if(stream->stream_current_window_remaining < 0) {
        return 0;
    }
    if(conn->connection_current_window_remaining < 0) {
        return 0;
    }
    const auto max_frame_size = std::min(conn->connection_current_window_remaining, stream->stream_current_window_remaining);
    auto frame_size = std::min(max_frame_size, (int64_t)m_desired_size);
    conn->connection_current_window_remaining -= frame_size;
    stream->stream_current_window_remaining -= frame_size;
    return frame_size;
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
        // if data is await, resume succeed
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

h2read_headers::h2read_headers(std::weak_ptr<h2_stream> hstream) : m_hstream(hstream) {}

bool h2read_headers::await_ready() const noexcept {
    return false;
}

bool h2read_headers::await_suspend(std::coroutine_handle<> awaiting_coroutine) {
    auto conn = m_hstream.lock();
    if(conn->client_sent_headers == stream_frame_state::data_expected) {
        return false;
    }
    if(conn->client_sent_headers == stream_frame_state::done) {
        // trailers
        return false;
    }
    conn->m_read_headers = awaiting_coroutine;
    return true;
}

std::pair<std::vector<entry_t>, stream_result> h2read_headers::await_resume() {
    auto conn = m_hstream.lock();
    if(conn == nullptr) {
        return { {}, stream_result::closed };
    }
    if(conn->client_sent_headers == stream_frame_state::data_expected) {
        return { std::move(conn->m_received_headers), stream_result::ok };
    } else if(conn->client_sent_headers == stream_frame_state::done) {
        return { std::move(conn->m_received_headers), stream_result::ok };
    }
    assert(false);
}

} // namespace
