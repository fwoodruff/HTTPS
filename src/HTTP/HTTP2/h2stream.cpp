//
//  h2stream.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/11/2024.
//

#include "h2stream.hpp"
#include "h2proto.hpp"

namespace fbw {

void h2_stream::receive_headers(std::vector<entry_t> headers) {
    if(m_received_headers.empty()) {
        m_received_headers = std::move(headers);
        return;
    }
    m_received_headers.insert(m_received_headers.end(), headers.begin(), headers.end());
}

void h2_stream::receive_trailers(std::vector<entry_t> headers) {
    for(auto&& header : headers) {
        m_received_trailers.push_back(std::move(header));
    }
}

task<stream_result> h2_stream::write_headers(const std::vector<entry_t>& headers, bool end) {
    auto conn = wp_connection.lock();
    if(!conn) {
        co_return stream_result::closed;
    }
    co_return co_await conn->write_headers(m_stream_id, headers, end);
}

task<stream_result> h2_stream::write_data(std::span<const uint8_t> data, bool end) {
    auto conn = wp_connection.lock();
    if(!conn) {
        co_return stream_result::closed;
    }
    co_return co_await conn->write_data(m_stream_id, data, end);
}

task<stream_result> h2_stream::read_headers(std::vector<entry_t>& headers) {
    auto [ vec, res ] = co_await h2read_headers(shared_from_this());
    headers = std::move(vec);
    co_return res;
}

}