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
    assert(connection != nullptr);
    std::vector<entry_t> request_headers = connection->get_headers();

    auto method_it = std::find_if(request_headers.begin(), request_headers.end(), [](const entry_t& entry){ return entry.name == ":method"; });
    if(method_it == request_headers.end()) {
        co_return;
    }
    
    if(method_it->value == "POST") {
        ustring some_data;
        do {
            auto [ res, end ] = co_await connection->append_http_data(some_data);
            if(res != stream_result::ok) {
                co_return;
            }
            if(!end) {
                continue;
            }
        } while(false);
    }
    
    std::vector<entry_t> send_headers;
    const std::string message = "<HTML>HELLO WORLD</HTML>";
    if(method_it == send_headers.end() or method_it->value != "GET") {
        send_headers.push_back({":status", "500"});
        send_headers.push_back({"content-length", std::to_string(message.size())});
        auto res = co_await connection->write_headers(send_headers);
        if(res != stream_result::ok) {
            co_return;
        }
        auto umessage = to_unsigned(message);
        std::span<const uint8_t> sp {(uint8_t*)umessage.data(), umessage.size()};
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
    co_await connection->write_data(sp, true);
    co_return;
}

}