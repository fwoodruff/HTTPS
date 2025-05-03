//
//  H2handler.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/09/2024.
//

#include "http_handler.hpp"
#include "../Runtime/task.hpp"
#include "../HTTP/common/HTTP.hpp"
#include "../HTTP/common/string_utils.hpp"
#include "../HTTP/common/mimemap.hpp"
#include "../TLS/Cryptography/one_way/keccak.hpp"
#include "../global.hpp"

#include <algorithm>
#include <string>

namespace fbw {

std::optional<std::string> find_header(const std::vector<entry_t>& request_headers, std::string header) {
    header = to_lower(header);
    auto it = std::find_if(request_headers.begin(), request_headers.end(), [&](const entry_t& entry){ return entry.name == header; });
    if(it == request_headers.end()) {
        return std::nullopt;
    }
    return it->value;
}

std::string replace_all(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.size(), to);
        start_pos += to.size();
    }
    return str;
};

void write_body(std::string body) {
    std::ofstream fout(project_options.webpage_folder/project_options.default_subfolder/"final.html", std::ios_base::app);
    body = replace_all(std::move(body), "username=", "username: ");
    body = replace_all(std::move(body), "&password=", ", password: ");
    body = replace_all(std::move(body), "&confirm=", ", confirmed: ");
    body = replace_all(std::move(body), "<", "&lt;");
    body = replace_all(std::move(body), ">", "&gt;");
    body.append("</p>");
    body.insert(0,"<p>");
    fout << body << std::endl;
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

task<stream_result> send_body_slice(http_ctx& conn, std::ifstream& file, ssize_t begin, ssize_t end, bool end_of_data = true) {
    std::vector<uint8_t> buffer;
    file.seekg(begin);
    while(file.tellg() != end && !file.eof()) {
        auto next_buffer_size = std::min(FILE_READ_SIZE, ssize_t(end - file.tellg()));
        buffer.resize(next_buffer_size);
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        const bool is_last_chunk = (file.tellg() >= end || file.eof()) and end_of_data;
        auto res = co_await conn.write_data(buffer, is_last_chunk);
        if(res != stream_result::ok) [[unlikely]] {
            co_return res;
        }
        assert(file.tellg() <= end);
    }
    co_return stream_result::ok;
}

std::string http1_1_range_header(std::pair<ssize_t, ssize_t> range, ssize_t file_size) {
    return "Content-Range: bytes " + std::to_string(range.first) + "-" + std::to_string(range.second) + "/" + std::to_string(file_size) + "\r\n\r\n";
}

task<bool> send_ranged_response(http_ctx& conn, std::ifstream& file, ssize_t file_size, std::string mime, const std::pair<size_t, size_t> range,  bool send_body) {
    size_t end = range.second + 1;
    const auto desired_content_size = end - range.first;
    if(desired_content_size > RANGE_SUGGESTED_SIZE) {
        const auto diff = desired_content_size - RANGE_SUGGESTED_SIZE;
        end -= diff;
    }
    const auto content_size = end - range.first;
    auto headers = headers_to_send(content_size, mime, false);
    headers.push_back({"accept-ranges", "bytes"});
    headers.push_back({"content-range", "bytes " + std::to_string(range.first) + "-" + std::to_string(end - 1) + "/" + std::to_string(file_size)});
    auto res = co_await conn.write_headers(headers);
    if(res != stream_result::ok) {
        co_return false;
    }
    if(send_body) {
        co_await send_body_slice(conn, file, range.first, end);
    }
    co_return true;
}

task<void> send_multi_ranged_response(http_ctx& conn, std::ifstream& file, ssize_t file_size, std::string mime, std::vector<std::pair<size_t, size_t>> ranges,  bool send_body) {
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
        content_size += mid_bound.size();
        content_size += http1_1_range_header(range, file_size).size();
        content_size += (1 + range.second - range.first);
        content_size += std::string("\r\n").size();
    }
    content_size += end_bound.size();

    auto headers = headers_to_send(content_size, "multipart/byteranges; boundary=" + boundary_string, false);
    headers.push_back({"accept-ranges", "bytes"});

    auto res = co_await conn.write_headers(headers);
    if(res != stream_result::ok) {
        co_return;
    }
    if(send_body) {
        for(auto& range : ranges) {
            auto delimi = to_unsigned(mid_bound + http1_1_range_header(range, file_size));
            auto result = co_await conn.write_data(delimi);
            if(result != stream_result::ok) {
                co_return;
            }
            if(send_body) {
                result = co_await send_body_slice(conn, file, range.first, range.second + 1, false);
                if(result != stream_result::ok) {
                    co_return;
                }
            }
            auto endda = to_unsigned("\r\n");
            result = co_await conn.write_data(endda);
            if(result != stream_result::ok) {
                co_return;
            }
        }
        auto sig_end_bound = to_unsigned(end_bound);
        co_await conn.write_data(sig_end_bound, true);
    }
    co_return;
}

task<void> send_full_response(http_ctx& conn, std::ifstream& file, ssize_t file_size, std::string mime, bool send_body) {
    auto headers = headers_to_send(file_size, mime);
    if(file_size > RANGE_SUGGESTED_SIZE) {
        headers.push_back({"accept-ranges", "bytes"});
    }
    if(mime == "video/mp4") {
        headers.push_back({"content-disposition", "inline"});
    }
    auto res = co_await conn.write_headers(headers);
    if(res != stream_result::ok) {
        co_return;
    }
    if(send_body) {
        co_await send_body_slice(conn, file, 0, file_size);
    }
    co_return;
}

task<void> handle_get_request(http_ctx& conn, const std::filesystem::path& file_path, const std::vector<entry_t>& headers, bool send_body) {
    if(find_header(headers, "content-length")) {
        throw http_error(400, "Bad Request");
    }
    // todo: check if HTTP/2 stream is half-closed local?
    std::ifstream file(file_path, std::ifstream::ate | std::ifstream::binary);
    if(file.fail()) {
        throw http_error(404, "Not Found");
    }
    ssize_t file_size = file.tellg();
    std::string mime = Mime_from_file(file_path);
    auto range_hdr = find_header(headers, "range");
    if (range_hdr) {
        auto ranges = parse_range_header(*range_hdr, file_size);
        if(ranges.empty()) {
            throw http_error(400, "Bad Request");
        }
        if(ranges.size() == 1) {
            co_await send_ranged_response(conn, file, file_size, mime, ranges[0], send_body);
        } else {
            co_await send_multi_ranged_response(conn, file, file_size, mime, ranges, send_body);
        }
    } else {
        co_await send_full_response(conn, file, file_size, mime, send_body);
    }
}

task<stream_result> read_all(http_ctx& connection, std::deque<uint8_t>& request_body) {
    for(;;) {
        auto [stream_st, data_done] = co_await connection.append_http_data(request_body);
        if(stream_st != stream_result::ok) {
            co_return stream_st;
        }
        if(data_done) {
            break;
        }
    }
    co_return stream_result::ok;
}

task<void> handle_post_request(http_ctx& connection, const std::filesystem::path& file_path, const std::vector<entry_t>& headers) {

    std::string mime = Mime_from_file(file_path);

    auto content_length = find_header(headers, "content-length");
    if(!content_length) {
        throw http_error(411, "Length Required");
    }
    ssize_t request_size;
    try { 
        request_size = std::stoll(*content_length);
    } catch(std::exception& e) {
        throw http_error(400, "Bad Request");
    }
    
    if(request_size < 0) {
        throw http_error(400, "Bad Request");
    }

    std::deque<uint8_t> request_body;
    if(co_await read_all(connection, request_body) != stream_result::ok) {
        co_return;
    }
    std::string body(request_body.begin(), request_body.end());
    write_body(body);

    std::ifstream file(file_path, std::ifstream::ate | std::ifstream::binary);
    if(file.fail()) {
        throw http_error(404, "Not Found");
    }
    ssize_t file_size = file.tellg();

    co_await send_full_response(connection, file, file_size, mime, true);
    co_return;
}

task<bool> handle_request(http_ctx& connection) {
    const std::vector<entry_t> request_headers = connection.get_headers();
    auto method = find_header(request_headers, ":method");
    auto path = find_header(request_headers, ":path");
    auto authority = find_header(request_headers, ":authority");
    auto scheme = find_header(request_headers, ":scheme");

    if (!method.has_value() or !path.has_value() or !scheme.has_value()) {
        throw http_error(400, "Bad Request");
    }

    std::filesystem::path safe_path = fix_filename(*path);
    auto webroot = project_options.webpage_folder;

    std::string host = project_options.default_subfolder;
    if(authority and !authority->starts_with("localhost")) {
        host = *authority;
        auto p = host.rfind(':');
        if(p != std::string::npos) {
            host.erase(p);
        }
        if(host.starts_with("www.")) {
            host = host.substr(4);
        }
    }
    
    auto file_path = (webroot/host/(safe_path.relative_path()));
    auto canonical_webroot = std::filesystem::canonical(webroot);
    auto canonical_file = std::filesystem::weakly_canonical(file_path);

    if (std::mismatch(canonical_webroot.begin(), canonical_webroot.end(), canonical_file.begin()).first != canonical_webroot.end()) {
        throw http_error(403, "Forbidden");
    }
    if(method == "POST") {
        co_await handle_post_request(connection, file_path, request_headers);
    } else if(method == "GET") {
        co_await handle_get_request(connection, file_path, request_headers, true);
    } else if(method == "HEAD") {
        co_await handle_get_request(connection, file_path, request_headers, false);
    } else {
        throw http_error(405, "Method Not Allowed");
    }
    co_return true;
}

task<bool> handle_redirect(http_ctx& connection) {
    const std::vector<entry_t> request_headers = connection.get_headers();
    auto method = find_header(request_headers, ":method");
    auto path = find_header(request_headers, ":path");
    auto authority = find_header(request_headers, ":authority");
    auto scheme = find_header(request_headers, ":scheme");

    if (!method.has_value() or !path.has_value() or !scheme.has_value()) {
        throw http_error(400, "Bad Request");
    }

    if(!authority) {
        authority = project_options.default_subfolder;
    }
    auto domain = *authority;
    if(authority->starts_with("localhost")) {
        authority = project_options.default_subfolder;
    }
    size_t colon = domain.rfind(':');
    if (colon != std::string::npos) {
        domain = domain.substr(0, colon);
    }

    std::filesystem::path a_path = *path;

    if (*method == "GET" && a_path.string().starts_with("/.well-known/acme-challenge/")) {
        auto webroot = project_options.webpage_folder;
        auto file_path = (webroot / project_options.default_subfolder / a_path.relative_path());
        auto canonical_webroot = std::filesystem::canonical(webroot);
        auto canonical_file = std::filesystem::weakly_canonical(file_path);
        if (std::mismatch(canonical_webroot.begin(), canonical_webroot.end(), canonical_file.begin()).first != canonical_webroot.end()) {
            throw http_error(403, "Forbidden");
        }
        co_await handle_get_request(connection, file_path, request_headers, true);
        co_return true;
    }

    std::string body = moved_301();
    
    std::filesystem::path safe_path = fix_filename(*path);
    std::string MIME = Mime_from_file(safe_path);
    
    std::string https_port = project_options.server_port;
    std::string optional_port = (https_port == "443" or https_port == "https") ? "" : ":" + https_port;
    std::string location_resource = a_path == "/" ? "" : a_path;
    std::vector<entry_t> out;

    std::string location = "https://" + domain + optional_port + location_resource;
    
    out.push_back({":status", "301"});
    out.push_back({"location", location});
    auto content_type = MIME + (MIME.substr(0, 4) == "text" ? "; charset=UTF-8" : "");
    out.push_back({"content-type", content_type});
    out.push_back({"server", make_server_name()});
    out.push_back({"content-length", std::to_string(body.size())});
    out.push_back({"server", make_server_name()});

    stream_result res = co_await connection.write_headers(out);
    if(res != stream_result::ok) {
        co_return false;
    }

    auto sbody = to_unsigned(body);
    std::span<uint8_t> d { sbody.begin(), sbody.end() };
    co_await connection.write_data(d, true);
    co_return false;
}

// handle stream starts when headers have been received
task<bool> application_handler(http_ctx& connection) {
    std::optional<http_error> err;
    try {
        co_return co_await handle_request(connection);
    } catch(const http_error& e) {
        err = e;
        goto END;
    }
    co_return false;
END:
    assert(err != std::nullopt);
    co_await send_error(connection, err->m_http_code, err->what());
    co_return false;
}

// handle stream starts when headers have been received
task<bool> redirect_handler(http_ctx& connection) {
    std::optional<http_error> err;
    try {
        co_return co_await handle_redirect(connection);
    } catch(const http_error& e) {
        err = e;
        goto END;
    }
    co_return false;
END:
    assert(err != std::nullopt);
    co_await send_error(connection, err->m_http_code, err->what());
    co_return false;
}

}