//
//  http_ctx.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/11/2024.
//

#include "http_ctx.hpp"
#include "string_utils.hpp"

namespace fbw {

task<void> send_error(http_ctx& connection, uint32_t status_code, std::string status_message) {
    std::vector<entry_t> send_headers;
    std::string message = error_to_html(status_code, status_message);
    send_headers.push_back({":status", std::to_string(status_code)});
    send_headers.push_back({"content-length", std::to_string(message.size())});
    send_headers.push_back({"content-type", "text/html; charset=utf-8"});
    send_headers.push_back({"server", "FredPi/0.1 (Unix) (Raspbian/Linux)"});
    auto res = co_await connection.write_headers(send_headers);
    if(res != stream_result::ok) {
        co_return;
    }
    auto umessage = to_unsigned(message);
    std::span<const uint8_t> sp {umessage};
    auto resu = co_await connection.write_data(sp, true);
    if(resu != stream_result::ok) {
        co_return;
    }
}

}