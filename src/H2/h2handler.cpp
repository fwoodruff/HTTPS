//
//  H2handler.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/09/2024.
//

#include "../Runtime/task.hpp"
#include "h2handler.hpp"
#include "h2proto.hpp"
#include "h2awaitable.hpp"
#include "../global.hpp"

namespace fbw {

[[nodiscard]] task<void> handle_stream_inner(std::weak_ptr<HTTP2> connection, uint32_t stream_id);

task<stream_result> write_data(std::weak_ptr<HTTP2> connection, int32_t stream_id, std::span<const uint8_t> bytes, bool data_end = true) {
    while(!bytes.empty()) {
        auto stres = co_await write_some_data(connection, stream_id, bytes, data_end);
        if(stres != stream_result::ok) {
            co_return stres;
        }
    }
    co_return stream_result::ok;
}

task<void> handle_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id) {
    co_await handle_stream_inner(connection, stream_id);
    auto conn = connection.lock();
    // ensure we are running on the same thread as the connection here
    conn->m_h2streams.erase(stream_id);
    co_return;
}

// handle stream starts when headers have been received
task<void> handle_stream_inner(std::weak_ptr<HTTP2> connection, uint32_t stream_id) {
    auto [ conn, stream ] = lock_stream(connection, stream_id);
    
    std::vector<entry_t> send_headers;
    const std::string message = "<HTML>HELLO WORLD</HTML>";

    if(stream->method != "GET") {
        send_headers.push_back({":status", "500"});
        send_headers.push_back({"content-length", std::to_string(message.size())});
        co_await write_headers(conn, stream_id, send_headers);
        std::span<const uint8_t> sp {(uint8_t*)message.data(), message.size()};
        co_await write_data(conn, stream_id, sp);
        co_return;
    }

    send_headers.push_back({":status", "200"});
    send_headers.push_back({"content-length", std::to_string(message.size())});
    send_headers.push_back({"content-type", "text/html; charset=utf-8"});
    auto res = co_await write_headers(conn, stream_id, send_headers);
    if(res != stream_result::ok) {
        co_return;
    }
    std::span<const uint8_t> sp {(uint8_t*)message.data(), message.size()};
    co_await write_data(conn, stream_id, sp);
    co_return;
}

}