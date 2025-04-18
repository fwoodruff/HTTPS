//
//  H2handler.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/09/2024.
//

#include "../Runtime/task.hpp"
#include "http_handler.hpp"
#include "../HTTP/HTTP1_1/HTTP.hpp"
#include "../HTTP/HTTP1_1/mimemap.hpp"
#include "../TLS/Cryptography/one_way/keccak.hpp"
#include <algorithm>

#include "../global.hpp"

namespace fbw {

std::optional<std::string> find_header(const std::vector<entry_t>& request_headers, std::string header) {
    auto it = std::find_if(request_headers.begin(), request_headers.end(), [&](const entry_t& entry){ return entry.name == header; });
    if(it == request_headers.end()) {
        return std::nullopt;
    }
    return it->value;
}

std::string app_error_to_html(std::string error) {
    std::ostringstream oss;
    oss << "<!DOCTYPE html>\n"
        << "<html>\n"
        << "<head><title>\n" << error << "</title></head>\n"
        << "\t<body><h1>\n" << error << "</h1></body>\n" 
        << "</html>";
    return oss.str();
}

task<void> send_error(std::shared_ptr<http_ctx> connection, uint32_t status_code, std::string status_message) {
    std::vector<entry_t> send_headers;
    std::string message = app_error_to_html(status_message);
    send_headers.push_back({":status", std::to_string(status_code)});
    send_headers.push_back({"content-length", std::to_string(message.size())});
    send_headers.push_back({"content-type", "text/html; charset=utf-8"});
    send_headers.push_back({"server", "FredPi/0.1 (Unix) (Raspbian/Linux)"});
    auto res = co_await connection->write_headers(send_headers);
    if(res != stream_result::ok) {
        co_return;
    }
    auto umessage = to_unsigned(message);
    std::span<const uint8_t> sp {umessage};
    auto resu = co_await connection->write_data(sp, true);
    if(resu != stream_result::ok) {
        co_return;
    }
}

std::vector<entry_t> headers_to_send(ssize_t file_size, std::string mime, bool full = true) {
    auto time = std::time(0);
    constexpr time_t day = 24*60*60;
    std::vector<entry_t> out;
    std::string status_code;
    if(file_size == 0) {
        status_code = "204";
    } else {
        if(!full) {
            status_code = "206";
        } else {
            status_code = "200";
        }
    }
    out.push_back({":status", status_code});
    if(file_size != 0) {
        out.push_back({"content-length", std::to_string(file_size)});
    }
    out.push_back({"date", timestring(time)});
    out.push_back({"expires", timestring(time + day)});
    auto content_type = mime + (mime.substr(0, 4) == "text" ? "; charset=UTF-8" : "");
    out.push_back({"content-type", content_type});
    out.push_back({"server", make_server_name()});
    
    return out;
}

task<stream_result> app_send_body_slice(std::shared_ptr<http_ctx> conn, const std::filesystem::path& file_path, ssize_t begin, ssize_t end) {
    std::ifstream t(file_path, std::ifstream::binary);
    if(t.fail()) {
        co_return stream_result::closed;
    }
    ustring buffer;
    t.seekg(begin);
    while(t.tellg() != end && !t.eof()) {
        auto next_buffer_size = std::min(FILE_READ_SIZE, ssize_t(end - t.tellg()));
        buffer.resize(next_buffer_size);
        t.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        auto res = co_await conn->write_data(buffer);
        if(res != stream_result::ok) [[unlikely]] {
            co_return res;
        }
        assert(t.tellg() <= end);
    }
    co_return stream_result::ok;
}

std::string http1_1_range_header(std::pair<ssize_t, ssize_t> range, ssize_t file_size) {
    return "Content-Range: bytes " + std::to_string(range.first) + "-" + std::to_string(range.second) + "/" + std::to_string(file_size) + "\r\n\r\n";
}

// todo: sanitise inputs
std::pair<ssize_t, ssize_t> app_get_range_bounds(ssize_t file_size, std::pair<ssize_t, ssize_t>& range) {
    ssize_t begin;
    ssize_t end;
    if(range.first == -1) {
        begin = file_size - range.second;
        end = file_size;
        range.first = begin;
        range.second = end - 1;
    } else if(range.second == -1) {
        begin = range.first;
        end = std::min(ssize_t(file_size), range.first + RANGE_SUGGESTED_SIZE);
        range.second = end - 1;
    } else {
        begin = range.first;
        end = range.second + 1;
    }

    if (range.first > range.second or range.second >= file_size) {
        return {0,0};
    }
    assert(end > begin);
    return {begin, end};
}

task<bool> send_ranged_response(std::shared_ptr<http_ctx> conn, const std::filesystem::path& file_path, ssize_t file_size, std::string mime, std::pair<uint32_t, uint32_t> range,  bool send_body) {
    if(range.first >= range.second) {
        co_await send_error(conn, 416, "Range Not Satisfiable");
        co_return false;
    }
    auto headers = headers_to_send(range.second - range.first, mime, false);
    headers.push_back({"accept-ranges", "bytes"});
    headers.push_back({"content-range", "bytes " + std::to_string(range.first) + "-" + std::to_string(range.second) + "/" + std::to_string(file_size)});
    auto res = co_await conn->write_headers(headers);
    if(res != stream_result::ok) {
        co_return false;
    }
    if(send_body) {
        co_await app_send_body_slice(conn, file_path, range.first, range.second);
    }
    co_return true;
}

task<void> send_multi_ranged_response(std::shared_ptr<http_ctx> conn, const std::filesystem::path& file_path, ssize_t file_size, std::string mime, std::vector<std::pair<ssize_t, ssize_t>> ranges,  bool send_body) {
    std::array<uint8_t, 28> entropy;
    randomgen.randgen(entropy);
    std::string boundary_string;
    for(unsigned c : entropy) {
        boundary_string.push_back('A' + c % 26);
    }
    
    std::string mid_bound =  "--" + boundary_string + "\r\nContent-Type: " + mime + "\r\n";
    std::string end_bound = "--" + boundary_string + "--\r\n";

    auto content_size = 0;
    for(auto& range : ranges) {
        auto [begin, end] = app_get_range_bounds(file_size, range);
        if(begin == 0 and end == 0) {
            co_await send_error(conn, 416, "Requested Range Not Satisfiable");
            co_return;
        }
        content_size += mid_bound.size();
        content_size += http1_1_range_header(range, file_size).size();
        content_size += (end - begin);
        content_size += std::string("\r\n").size();
    }
    content_size += end_bound.size();

    auto headers = headers_to_send(content_size, "multipart/byteranges; boundary=" + boundary_string, false);
    headers.push_back({"accept-ranges", "bytes"});

    auto res = co_await conn->write_headers(headers);
    if(res != stream_result::ok) {
        co_return;
    }
    if(send_body) {
        for(auto& range : ranges) {
            auto [begin, end] = app_get_range_bounds(file_size, range);
            auto delimi = to_unsigned(mid_bound + http1_1_range_header(range, file_size));
            auto result = co_await conn->write_data(delimi);
            if(result != stream_result::ok) {
                co_return;
            }
            if(send_body) {
                result = co_await app_send_body_slice(conn, file_path, begin, end);
                if(result != stream_result::ok) {
                    co_return;
                }
            }
            auto endda = to_unsigned("\r\n");
            result = co_await conn->write_data(endda);
            if(result != stream_result::ok) {
                co_return;
            }
        }
        auto sig_end_bound = to_unsigned(end_bound);
        co_await conn->write_data(sig_end_bound);
    }
    co_return;
}

task<void> send_full_response(std::shared_ptr<http_ctx> conn, const std::filesystem::path& file_path, ssize_t file_size, std::string mime, bool send_body) {
    auto headers = headers_to_send(file_size, mime);
    if(file_size > RANGE_SUGGESTED_SIZE) {
        headers.push_back({"accept-ranges", "bytes"});
    }
    auto res = co_await conn->write_headers(headers);
    if(res != stream_result::ok) {
        co_return;
    }
    if(send_body) {
        co_await app_send_body_slice(conn, file_path, 0, file_size);
    }
    co_return;
}

task<void> handle_get_request(std::shared_ptr<http_ctx> conn, const std::filesystem::path& file_path, const std::vector<entry_t>& headers, bool send_body) {
    ssize_t file_size = get_file_size(file_path);
    if(file_size < 0) {
        co_await send_error(conn, 404, "Not Found");
        co_return;
    }
    std::string mime = Mime_from_file(file_path);
    auto range_hdr = find_header(headers, "range");
    if (range_hdr) {
        auto ranges = parse_range_header(*range_hdr);
        if(ranges.empty()) {
            co_await send_error(conn, 400, "Bad Request");
            co_return;
        }
        if(ranges.size() == 1) {
            co_await send_ranged_response(conn, file_path, file_size, mime, ranges[0], send_body);
        } else {
            co_await send_multi_ranged_response(conn, file_path, file_size, mime, ranges, send_body);
        }
    } else {
        co_await send_full_response(conn, file_path, file_size, mime, send_body);
    }
}

task<void> handle_post_request(std::shared_ptr<http_ctx> connection, const std::filesystem::path& file_path, const std::vector<entry_t>& headers) {
    co_return;
}

// handle stream starts when headers have been received
task<bool> application_handler(std::shared_ptr<http_ctx> connection) { // todo: reference not shared_ptr?
    assert(connection != nullptr);
    const std::vector<entry_t> request_headers = connection->get_headers();
    auto method = find_header(request_headers, ":method");
    auto path = find_header(request_headers, ":path");
    auto authority = find_header(request_headers, ":authority");
    auto scheme = find_header(request_headers, ":scheme");
    if (!method.has_value() or !path.has_value() or !scheme.has_value()) {
        co_await send_error(connection, 400, "Bad Request");
        co_return false;
    }
    if(!authority or authority->starts_with("localhost")) {
        authority = project_options.default_subfolder;
    }

    std::filesystem::path safe_path = fix_filename(*path);

    auto webroot = project_options.webpage_folder;
    
    auto file_path = (webroot/(*authority)/(safe_path.relative_path()));

    auto canonical_webroot = std::filesystem::canonical(webroot);
    auto canonical_file = std::filesystem::weakly_canonical(file_path);

    if (std::mismatch(canonical_webroot.begin(), canonical_webroot.end(), canonical_file.begin()).first != canonical_webroot.end()) {
        co_await send_error(connection, 403, "Forbidden");
        co_return false;
    }
    if(method == "POST") {
        co_await handle_post_request(connection, file_path, request_headers);
    } else if(method == "GET") {
        co_await handle_get_request(connection, file_path, request_headers, true);
    } else if(method == "HEAD") {
        co_await handle_get_request(connection, file_path, request_headers, false);
    } else {
        co_await send_error(connection, 405, "Method Not Allowed");
        co_return false;
    }
    co_return true;
}

}