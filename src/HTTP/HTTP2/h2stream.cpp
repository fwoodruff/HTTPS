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

bool h2_stream::is_done() {
    auto conn = m_connection.lock();
    if(!conn) {
        return true;
    }
    return conn->h2_ctx.is_closed(m_stream_id) == stream_result::closed;
}

task<stream_result> h2_stream::write_headers(const std::vector<entry_t>& headers) {
    auto conn = m_connection.lock();
    if(!conn) {
        co_return stream_result::closed;
    }
    std::cout << "headers sent: \n";
    for(auto header : headers) {
        std::cout << header.name << ": " << header.value << std::endl;
    }
    std::cout << "headers sent end" << std::endl;
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
    if(conn->h2_ctx.is_closed(m_stream_id) == stream_result::closed) {
        co_return stream_result::closed;
    }
    auto stream_resu = conn->h2_ctx.buffer_data(data, m_stream_id, end);
    auto res = co_await conn->send_outbox();
    if(res != stream_result::ok) {
        co_return res;
    }
    if(stream_resu == stream_result::awaiting) {
        auto connection_alive = co_await h2writeable(m_connection, m_stream_id);
        if(connection_alive != stream_result::ok) {
            co_return connection_alive;
        }
    }
    co_return stream_resu;
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
    auto headers = cx.get_headers(m_stream_id);
    std::cout << "headers received: \n";
    for(auto header : headers) {
        std::cout << header.name << ": " << header.value << std::endl;
    }
    std::cout << "headers received end" << std::endl;
    return headers;
}

}