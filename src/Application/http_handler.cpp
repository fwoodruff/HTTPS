//
//  H2handler.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/09/2024.
//

#include "../Runtime/task.hpp"
#include "http_handler.hpp"

#include "../global.hpp"

namespace fbw {

// handle stream starts when headers have been received
task<void> application_handler(std::shared_ptr<http_ctx> connection) {

    std::vector<entry_t> request_headers;
    auto res_in = co_await connection->read_headers(request_headers);
    if(res_in != stream_result::ok) {
        co_return;
    }

    std::vector<entry_t> send_headers;
    const std::string message = "<HTML>HELLO WORLD.</HTML>";
    auto it = std::find_if(send_headers.begin(), send_headers.end(), [](const entry_t& val) { return val.name == ":method"; });
    if(it == send_headers.end() or it->value != "GET") {
        send_headers.push_back({":status", "500"});
        send_headers.push_back({"content-length", std::to_string(message.size())});
        auto res = co_await connection->write_headers(send_headers);
        if(res != stream_result::ok) {
            co_return;
        }
        std::span<const uint8_t> sp {(uint8_t*)message.data(), message.size()};
        co_await connection->write_data(sp);
        co_return;
    }
    send_headers.push_back({":status", "200"});
    send_headers.push_back({"content-length", std::to_string(message.size())});
    send_headers.push_back({"content-type", "text/html; charset=utf-8"});
    auto res = co_await connection->write_headers(send_headers);
    if(res != stream_result::ok) {
        co_return;
    }
    
    std::span<const uint8_t> sp {(uint8_t*)message.data(), message.size()};
    co_await connection->write_data(sp);
    co_return;
}

}