//
//  h2stream.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/11/2024.
//

#include "h2stream.hpp"
#include "h2proto.hpp"

namespace fbw {

h2_stream::h2_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id) :
    m_connection(connection), m_stream_id(stream_id)
{}

task<stream_result> h2_stream::write_headers(const std::vector<entry_t>& headers) {
    auto conn = m_connection.lock();
    if(!conn) {
        co_return stream_result::closed;
    }
    bool success = conn->h2_ctx.buffer_headers(headers, m_stream_id);
    if(!success) {
        co_return stream_result::closed;
    }
    co_return co_await conn->send_outbox();
}

task<stream_result> h2_stream::write_data(std::span<const uint8_t> data, bool end) {
    auto conn = m_connection.lock();
    if(!conn) {
        co_return stream_result::closed;
    }
    assert(conn);
    auto suspend = conn->h2_ctx.buffer_data(data, m_stream_id, end);
    auto res = co_await conn->send_outbox();
    if(res != stream_result::ok) {
        co_return res;
    }
    if(suspend) {
        auto connection_alive = co_await h2writeable(m_connection, m_stream_id);
        if(connection_alive != stream_result::ok) {
            co_return connection_alive;
        }
    }
    co_return stream_result::ok;
}

task<std::pair<stream_result, bool>> h2_stream::append_http_data(ustring& buffer) {
    std::array<uint8_t, 4096> subbuffer{};
    auto [bytes, data_done] = co_await h2readable(m_connection, m_stream_id, subbuffer);
    if(bytes == 0) {
        co_return {stream_result::closed, false};
    }
    buffer.append(subbuffer.begin(), subbuffer.begin() + bytes);

    // push window updates
    auto conn = m_connection.lock();
    if(!conn) {
        co_return { stream_result::closed, false };
    }
    auto res = co_await conn->send_outbox();
    if(res != stream_result::ok) {
        co_return {res, false};
    }
    co_return {stream_result::ok, data_done };
}

std::vector<entry_t> h2_stream::get_headers() {
    auto connection = m_connection.lock();
    if(!connection) {
        return {};
    }
    auto& cx = connection->h2_ctx;
    return cx.get_headers(m_stream_id);
}

}