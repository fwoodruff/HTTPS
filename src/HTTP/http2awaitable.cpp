//
//  writeable.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 21/09/2024.
//

#include "http2awaitable.hpp"
#include "http2frame.hpp"
#include "HTTP2.hpp"
#include <span>

using namespace std::chrono_literals;
using namespace std::chrono;

namespace fbw {

h2readable::h2readable(std::weak_ptr<HTTP2> connection, int32_t stream_id) :
    m_connection(connection), m_stream_id(stream_id) {}

std::pair<std::shared_ptr<HTTP2>, std::shared_ptr<h2_stream>> lock_stream(std::weak_ptr<HTTP2> weak_conn, uint32_t stream_id) {
    auto conn = weak_conn.lock();
    if(conn == nullptr) {
        return {nullptr, nullptr};
    }
    std::scoped_lock lk {conn->conn_mut};
    auto it = conn->m_h2streams.find(stream_id);
    if(it == conn->m_h2streams.end()) {
        return { conn, nullptr };
    }
    return { conn, it->second };
}

bool h2readable::await_suspend(std::coroutine_handle<> continuation) {
    auto [ conn, stream ] = lock_stream(m_connection, m_stream_id);
    if(!conn) {
        // if the connection is dead, we need to resume and fail
        return true;
    }
    if(!stream) {
        // if the stream is dead, we need to notify the connection that we're home, then resume and fail
        // todo: consider moving this into the logic for accepting a RST_STREAM
        conn->running_streams.fetch_sub(1);
        return true;
    }
    if(!stream->inbox.empty()) {
        return true;
    }
    // todo: send a WINDOW_UPDATE if necessary
    stream->m_reader.store(continuation);
    return false;
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

h2writeable::h2writeable(std::weak_ptr<HTTP2> connection, int32_t stream_id)
    : m_connection(connection), m_stream_id(stream_id) {}

bool h2writeable::await_ready() const noexcept {
    return false;
}

bool h2writeable::await_suspend(std::coroutine_handle<> continuation) { // placeholder: ignores windowing 
    //auto [ conn, stream ] = lock_stream(m_connection, m_stream_id);
    (void)m_stream_id;
    return true;
}

std::pair<stream_result, int32_t> h2writeable::await_resume() {
    return {stream_result::ok, 0x7fffffff};
}

// initially just write up until we can't any more, later revisit
task<stream_result> write_data(std::weak_ptr<HTTP2> connection, int32_t stream_id, std::span<const uint8_t> bytes) {
    auto [ stream_res, num_bytes ] = co_await h2writeable{ connection, stream_id };
    if(stream_res != stream_result::ok) {
        co_return stream_res;
    }
    auto [ conn, stream ] = lock_stream(connection, stream_id);
    ssize_t bytes_to_write = std::max(size_t(num_bytes), bytes.size());
    while(bytes_to_write > 0) {
        auto frame_size = std::max(ssize_t(conn->server_settings.max_frame_size), bytes_to_write);
        h2_data frame;
        frame.data.append(bytes.begin(), bytes.begin() + frame_size);
        conn->outbox.push({std::make_unique<h2_data>(std::move(frame)), project_options.session_timeout});
        bytes = bytes.subspan(frame_size);
        bytes_to_write -= frame_size;
        assert(bytes_to_write >= 0);
    }
    co_return stream_result::ok;
}

} // namespace
