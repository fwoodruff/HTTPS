//
//  HTTP.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "string_utils.hpp"
#include "../global.hpp"
#include "../TLS/protocol.hpp"

#include <sstream>
#include <memory>
#include <optional>
#include <fstream>
#include <string>
#include <print>


namespace fbw {

ssize_t get_file_size(std::filesystem::path filename) {
    std::ifstream t(filename, std::ifstream::ate | std::ifstream::binary);
    if(t.fail()) {
        throw http_error(404, "Not Found");
    }
    return t.tellg();
}

std::unordered_map<std::string, std::string> prepare_headers(const ssize_t file_size, std::string MIME, std::string domain) {
    auto time = std::time(0);
    if(static_cast<std::time_t>(-1) == time) {
        throw http_error(500, "Internal Server Error");
    }
    constexpr time_t day = 24*60*60;
    std::unordered_map<std::string, std::string> headers {
        {"Date", timestring(time)},
        {"Expires", timestring(time + day)},
        {"Content-Type", MIME + (MIME.substr(0, 4) == "text" ? "; charset=UTF-8" : "")},
        {"Content-Length", std::to_string(file_size)},
        {"Connection", "Keep-Alive"},
        {"Keep-Alive", "timeout=" + std::to_string(project_options.keep_alive.count())},
        {"Server", make_server_name()},
        {"X-Served-By", domain }
    };
    if(project_options.http_strict_transport_security) {
        headers.insert({"Strict-Transport-Security", "max-age=31536000"});
    }
    return headers;
}

std::string range_header(std::pair<ssize_t, ssize_t> range, ssize_t file_size) {
    return "Content-Range: bytes " + std::to_string(range.first) + "-" + std::to_string(range.second) + "/" + std::to_string(file_size) + "\r\n\r\n";
}

std::string moved_301() {
    return
R"(<html>
    <head>
        <title>301 Moved Permanently</title>
    </head>
    <body>
        <h1>301 Moved Permanently</h1>
        <p>Redirecting</p>
    </body>
</html>
)";
}


};// namespace fbw
