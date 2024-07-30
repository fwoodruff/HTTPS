//
//  HTTP.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "HTTP.hpp"
#include "string_utils.hpp"
#include "../global.hpp"
#include "mimemap.hpp"
#include "../TLS/Cryptography/one_way/keccak.hpp"

#include <iostream>
#include <sstream>
#include <memory>
#include <optional>
#include <fstream>
#include <string>


namespace fbw {


// an HTTP handler streams data in, gets a file from a folder and streams it back
// or it might redirect unencrypted HTTP traffic
HTTP::HTTP(std::unique_ptr<stream> stream, std::string folder, bool redirect) :
    m_folder(folder), m_redirect(redirect), m_stream(std::move(stream)) {
        assert(m_stream != nullptr);
}

// to extract a full HTTP request we first need to extract the request's header but
// the full header may not be in the buffer yet
std::optional<http_header> HTTP::try_extract_header(ustring& m_buffer) {
    if(m_buffer.size() > MAX_HEADER_SIZE) {
        throw http_error("413 Payload Too Large");
    }
    auto header_bytes = extract(m_buffer, "\r\n\r\n");
    if(header_bytes.empty()) {
        return std::nullopt;
    }
    return parse_http_headers(to_signed(header_bytes));
}

ssize_t http_stoll(std::string number) {
    try {
        return std::stoll(number);
    } catch(std::exception& e) {
        throw http_error("400 Bad Request");
    }
}

bool is_body_required(const http_header& header) {
    if(header.protocol != "HTTP/1.1" and header.protocol != "HTTP/1.0" and header.protocol != "HTTP/0.9") {
        throw http_error("400 Bad Request");
    }
    if (header.verb == "PUT" or header.verb == "DELETE" or header.verb == "CONNECT" or header.verb == "PATCH"
        or header.verb == "TRACE" or header.verb == "OPTIONS") {
        throw http_error("405 Method Not Allowed");
    }
    if( header.verb == "POST") {
        bool is_transfer_encoded = false;
        if(auto it = header.headers.find("transfer-encoding"); it != header.headers.end()) {
            is_transfer_encoded = (it->second == "chunked"); // not implemented
        }
        bool has_length = header.headers.contains("content-length");
        if(is_transfer_encoded) {
            throw http_error("400 Bad Request");
        }
        if(!has_length) {
            throw http_error("411 Length Required");
        }
        return true;
    }
    if(header.headers.contains("content-length")) {
        throw http_error("400 Bad Request");
    }
    return false;
}

// we may receive a partial HTTP request, in which case we want to leave it in a buffer
// extracting an HTTP request is required to generate a response
std::optional<ustring> try_extract_body(ustring& m_buffer, const http_header& header) {
    auto len = header.headers.at("content-length");
    auto size = http_stoll(len);
    if(size > MAX_BODY_SIZE) {
        throw http_error("413 Payload Too Large");
    }
    ustring body;
    if(size != 0) {
        body += extract(m_buffer, size);
        if(body.empty()) {
            return std::nullopt;
        }
    }
    return { body };
}

// suspends until enough data has been read in over the network to generate an HTTP header
// leaves the input buffer intact and ready to consume further HTTP requests
task<std::optional<http_frame>> HTTP::try_read_http_request() {
    std::optional<http_header> header;
    std::optional<ustring> body;
    for(;;) {
        header = try_extract_header(m_buffer);
        if(header) {
            break;
        }
        assert(m_stream != nullptr);
        stream_result connection_alive = co_await m_stream->read_append(m_buffer, option_singleton().keep_alive);
        if (connection_alive == stream_result::read_timeout) {
            co_await m_stream->close_notify();
            co_return std::nullopt;
        }
        if(connection_alive != stream_result::ok) {
            co_return std::nullopt;
        }
        // todo: size check on m_buffer
    }
    assert(header != std::nullopt);
    if(!is_body_required(*header)) {
        co_return {{*header, {}}};
    }
    for(;;) {
        body = try_extract_body(m_buffer, *header);
        if(body) {
            break;
        }
        stream_result connection_alive = co_await m_stream->read_append(m_buffer, option_singleton().session_timeout);
        // todo: size check on m_buffer
        if(connection_alive != stream_result::ok) {
            co_return std::nullopt;
        }
        continue;
    }
    assert(body != std::nullopt);
    co_return http_frame { *header, *body };
}

task<void> HTTP::send_error(http_error http_err) {
    auto error_message = std::string(http_err.what());
    auto error_html = error_to_html(error_message);
    std::ostringstream oss;
    oss << "HTTP/1.1 " << error_message << "\r\n"
    << "Connection: close\r\n"
    << "Content-Type: text/html; charset=UTF-8\r\n"
    << "Content-Length: " << error_html.size() << "\r\n"
    << "Server: FredPi/0.1 (Unix) (Raspbian/Linux)\r\n"
    << "\r\n"
    << error_html;
    ustring output = to_unsigned(oss.str());
    auto res = co_await m_stream->write(output, option_singleton().session_timeout);
    if(res == stream_result::ok) {
        co_await m_stream->close_notify();
    }
    co_return;
}

// a per TCP client handler that frames HTTP requests and responds to them, until either the connection is
// shut down or times out
task<void> HTTP::client() {
    std::optional<http_error> http_err {};
    try {
        for(;;) {
            auto http_request = co_await try_read_http_request();
            if(!http_request) {
                co_return; // connection closed
            }
            if(m_redirect) {
                co_await redirect(std::move(*http_request));
                co_return;
            } else {
                auto res = co_await respond(m_folder, std::move(*http_request));
                if (res != stream_result::ok) {
                    co_return;
                }
                res = co_await m_stream->flush();
                if (res != stream_result::ok) {
                    co_return;
                }
            }
        }
    } catch(const http_error& e) {
        http_err = e;
        goto ERROR; // cannot co_await inside catch block
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
        co_return;
    } catch(...) {
        assert(false);
    }
ERROR:
    // if the request handler fails with an HTTP error, the error response is reported to the client here
    // for example this is where 404 Not Found messages are constructed and sent to clients
    if(http_err) {
        co_await send_error(*http_err);
    }
}

// Creates an HTTP response from an HTTP request
task<stream_result> HTTP::respond(const std::filesystem::path& rootdirectory, http_frame http_request) {
    const std::filesystem::path& filename = http_request.header.resource;
    if(http_request.header.protocol != "HTTP/1.0" and http_request.header.protocol != "HTTP/1.1" and http_request.header.protocol != "HTTP/0.9") {
        throw http_error("505 HTTP Version Not Supported");
    }
    std::string subfolder = option_singleton().default_subfolder;
    if(auto it = http_request.header.headers.find("host"); it != http_request.header.headers.end()) {
        const auto domain = parse_domain(it->second);
        if(std::filesystem::exists(rootdirectory/domain)) {
            subfolder = domain;
        }
    }
    if(http_request.header.verb == "GET" or http_request.header.verb == "HEAD") {
        auto it = http_request.header.headers.find("range");
        if(it == http_request.header.headers.end()) {
            co_return co_await send_file(rootdirectory, subfolder, filename, (http_request.header.verb == "GET"));
        }
        auto range_str = http_request.header.headers.at("range");
        auto ranges = parse_range_header(range_str);
        if(ranges.empty()) {
            throw http_error("400 Bad Request");
        }
        if(ranges.size() == 1) {
            co_return co_await send_range(rootdirectory, subfolder, filename, ranges[0], (http_request.header.verb == "GET"));
        }
        co_return co_await send_multi_ranges(rootdirectory, subfolder, filename, ranges, (http_request.header.verb == "GET"));
    } else if(http_request.header.verb == "POST") {
        write_body(std::move( http_request.body));
        co_return co_await send_file(rootdirectory, subfolder, filename, true);
    } else {
        throw http_error("405 Method Not Allowed\r\n");
    }
}

std::string replace_all(std::string str, const std::string& from, const std::string& to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.size(), to);
        start_pos += to.size();
    }
    return str;
};

// POST requests need some server-dependent program logic
// Here we just sanitise and write the application/x-www-form-urlencoded data to final.html
void HTTP::write_body(ustring frame) {
    auto body = to_signed(std::move(frame));
    std::ofstream fout(option_singleton().webpage_folder/"final.html", std::ios_base::app);
    body = replace_all(std::move(body), "username=", "username: ");
    body = replace_all(std::move(body), "&password=", ", password: ");
    body = replace_all(std::move(body), "&confirm=", ", confirmed: ");
    body = replace_all(std::move(body), "<", "&lt;");
    body = replace_all(std::move(body), ">", "&gt;");
    body.append("</p>");
    body.insert(0,"<p>");
    fout << body << std::endl;
}

ssize_t get_file_size(std::filesystem::path filename) {
    std::ifstream t(filename, std::ifstream::ate | std::ifstream::binary);
    if(t.fail()) {
        throw http_error("404 Not Found");
    }
    return t.tellg();
}

std::unordered_map<std::string, std::string> prepare_headers(const ssize_t file_size, std::string MIME, std::string domain) {
    auto time = std::time(0);
    if(static_cast<std::time_t>(-1) == time) {
        throw http_error("500 Internal Server Error");
    }
    constexpr time_t day = 24*60*60;
    std::unordered_map<std::string, std::string> headers {
        {"Date", timestring(time)},
        {"Expires", timestring(time + day)},
        {"Content-Type", MIME + (MIME.substr(0, 4) == "text" ? "; charset=UTF-8" : "")},
        {"Content-Length", std::to_string(file_size)},
        {"Connection", "Keep-Alive"},
        {"Keep-Alive", "timeout=" + std::to_string(option_singleton().keep_alive.count())},
        {"Server", make_server_name()},
        {"X-Served-By", domain }
    };
    if(option_singleton().http_strict_transport_security) {
        headers.insert({"Strict-Transport-Security", "max-age=31536000"});
    }
    return headers;
}

// our HTTP client has sent an HTTP request. We send over the response header, then stream the file
// contents back to them. If sending would block, we park this coroutine for polling
task<stream_result> HTTP::send_file(const std::filesystem::path& rootdir, const std::string& domain, std::filesystem::path filename, bool send_body) {
    filename = fix_filename(std::move(filename));
    auto file_path = rootdir/domain/filename.relative_path();
    std::string MIME = Mime_from_file(filename);
    ssize_t file_size = get_file_size(file_path);
    auto headers = prepare_headers(file_size, MIME, file_path);
    if(file_size > RANGE_SUGGESTED_SIZE) {
        headers.insert({"Accept-Ranges", "bytes"});
    }
    ustring header_str = make_header("200 OK", headers);
    auto res = co_await m_stream->write(header_str, option_singleton().session_timeout);
    if(res != stream_result::ok) {
        co_return res;
    }
    if(send_body) {
        auto res = co_await send_body_slice(file_path, 0, file_size);
        if(res != stream_result::ok) {
            co_return res;
        }
        co_return co_await m_stream->flush();
    }

    co_return stream_result::ok;
}

task<stream_result> HTTP::send_range(const std::filesystem::path& rootdirectory, const std::string& subfolder, std::filesystem::path filename, std::pair<ssize_t, ssize_t> range, bool send_body) {
    assert(range.first != -1 or range.second != -1);
    filename = fix_filename(std::move(filename));
    auto file_path = rootdirectory/subfolder/filename.relative_path();
    ssize_t file_size = get_file_size(file_path);
    std::string MIME = Mime_from_file(filename);
    
    auto [begin, end] = get_range_bounds(file_size, range);
    if(begin == 0 and end == file_size) {
        co_return co_await send_file(rootdirectory, subfolder, filename, send_body);
    }

    auto headers = prepare_headers(end - begin, MIME, file_path);
    headers.insert({"Accept-Ranges", "bytes"});
    headers.insert({"Content-Range", "bytes " + std::to_string(range.first) + "-" + std::to_string(range.second) + "/" + std::to_string(file_size)});

    ustring header_str = make_header("206 Partial Content", headers);
    auto res = co_await m_stream->write(header_str, option_singleton().session_timeout);
    if(res != stream_result::ok) {
        co_return res;
    }
    if(send_body) {
        co_return co_await send_body_slice(file_path, begin, end);
    }
    co_return stream_result::ok;
}


std::string range_header(std::pair<ssize_t, ssize_t> range, ssize_t file_size) {
    return "Content-Range: bytes " + std::to_string(range.first) + "-" + std::to_string(range.second) + "/" + std::to_string(file_size) + "\r\n\r\n";
}

task<stream_result> HTTP::send_multi_ranges(const std::filesystem::path& rootdir, const std::string& subfolder, std::filesystem::path filename, std::vector<std::pair<ssize_t, ssize_t>> ranges, bool send_body) {

    filename = fix_filename(std::move(filename));
    auto file_path = rootdir/subfolder/filename.relative_path();
    size_t file_size = get_file_size(file_path);
    std::string MIME = Mime_from_file(filename);

    std::array<uint8_t, 28> entropy;
    randomgen.randgen(entropy);
    std::string boundary_string;
    for(unsigned c : entropy) {
        boundary_string.push_back('A' + c % 26);
    }
    std::string mid_bound = "--" + boundary_string + "\r\n";
    std::string end_bound = "--" + boundary_string + "--\r\n";

    auto content_size = 0;
    for(auto& range : ranges) {
        auto [begin, end] = get_range_bounds(file_size, range);
        content_size += mid_bound.size();
        content_size += range_header(range, file_size).size();
        content_size += (end - begin);
        content_size += std::string("\r\n").size();
    }
    content_size += end_bound.size();
    auto headers = prepare_headers(content_size, MIME, file_path);
    headers["Content-Type"] = "multipart/byteranges; boundary=" + boundary_string;
    
    ustring header_str = make_header("206 Partial Content", headers);
    auto res = co_await m_stream->write(header_str, option_singleton().session_timeout);
    if(res != stream_result::ok) {
        co_return res;
    }
    for(auto& range : ranges) {
        auto [begin, end] = get_range_bounds(file_size, range);
        auto delimi = mid_bound + range_header(range, file_size);
        auto result = co_await m_stream->write(to_unsigned(delimi), option_singleton().session_timeout);
        if(result != stream_result::ok) {
            co_return result;
        }
        if(send_body) {
            result = co_await send_body_slice(file_path, begin, end);
            if(result != stream_result::ok) {
                co_return result;
            }
        }
        result = co_await m_stream->write(to_unsigned("\r\n"), option_singleton().session_timeout);
        if(result != stream_result::ok) {
            co_return result;
        }
    }
    co_return co_await m_stream->write(to_unsigned(end_bound), option_singleton().session_timeout);
}

task<stream_result> HTTP::send_body_slice(const std::filesystem::path& file_path, ssize_t begin, ssize_t end) {
    std::ifstream t(file_path, std::ifstream::binary);
    if(t.fail()) {
        throw http_error("404 Not Found");
    }
    ustring buffer;
    t.seekg(begin);
    while(t.tellg() != end && !t.eof()) {
        auto next_buffer_size = std::min(FILE_READ_SIZE, ssize_t(end - t.tellg()));
        buffer.resize(next_buffer_size);
        t.read((char*)buffer.data(), buffer.size());
        auto res = co_await m_stream->write(buffer, option_singleton().session_timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
        assert(t.tellg() <= end);
    }
    co_return stream_result::ok;
}


// if a client connects over http:// we need to form a response redirecting them to https://
task<void> HTTP::redirect(http_frame request) {
    std::string filename = fix_filename(std::move(request.header.resource));
    std::string MIME = Mime_from_file(filename);
    std::string body = "HTTP/1.1 301 Moved Permanently";

    std::string domain = option_singleton().default_subfolder;
    if(auto it = request.header.headers.find("host"); it != request.header.headers.end()) {
        domain = it->second;
    }
    
    std::string https_port = option_singleton().server_port;
    std::string optional_port = (https_port == "443" or https_port == "https") ? "" : ":" + https_port;

    std::ostringstream oss;
    oss << "HTTP/1.1 301 Moved Permanently\r\n"
        << "Location: https://" << domain << optional_port << filename << "\r\n"
        << "Content-Type: " << MIME << (MIME.substr(0,4)=="text" ? "; charset=UTF-8" : "") << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Connection: close\r\n"
        << "Server: " << make_server_name() << "\r\n"
        << "\r\n"
        << body;
    
    std::string var = oss.str();
    co_await m_stream->write(to_unsigned(var), option_singleton().session_timeout);
    co_await m_stream->close_notify();
}

};// namespace fbw
