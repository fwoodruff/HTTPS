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

#include <iostream>
#include <sstream>
#include <memory>
#include <optional>
#include <fstream>
#include <string>
#include <regex>


namespace fbw {

// an HTTP handler streams data in, gets a file from a folder and streams it back
// or it might redirect unencrypted HTTP traffic
HTTP::HTTP(std::unique_ptr<stream> stream, std::string folder, bool redirect) :
    m_folder(folder), m_redirect(redirect), m_stream(std::move(stream)) {
        assert(m_stream != nullptr);
}

// to extract a full HTTP request we first need to extract the request's header but
// the full header may not be in the buffer yet
std::optional<ustring> HTTP::try_extract_header(ustring& m_buffer) {
    ustring header;
    if(m_buffer.size() > max_bytes_queued) {
        throw http_error("414 URI Too Long");
    }
    header = extract(m_buffer, "\r\n\r\n");
    if(header.empty()) {
        return std::nullopt;
    }
    return header;
}

// we may receive a partial HTTP request, in which case we want to leave it in a buffer
// extracting an HTTP request is required to generate a response
std::optional<ustring> try_extract_body(ustring& m_buffer, ustring header) {
    const auto [delimiter, size] = body_size(header);
    assert(delimiter == "" or size == 0);
    ustring body;
    if(delimiter != "") {
        body = extract(m_buffer, delimiter);
        if(body.empty()) {
            return std::nullopt;
        }
    }
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
    std::optional<ustring> header;
    std::optional<ustring> body;
    for(;;) {
        header = try_extract_header(m_buffer);
        if(header) {
            break;
        }
        assert(m_stream != nullptr);
        stream_result connection_alive = co_await m_stream->read_append(m_buffer, option_singleton().keep_alive);
        if (connection_alive == stream_result::timeout) {
            co_await m_stream->close_notify();
            co_return std::nullopt;
        }
        if(connection_alive == stream_result::closed) {
            co_return std::nullopt;
        }
    }
    for(;;) {
        assert(header != std::nullopt);
        body = try_extract_body(m_buffer, *header);
        if(body) {
            break;
        }
        stream_result connection_alive = co_await m_stream->read_append(m_buffer, option_singleton().session_timeout);
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
    std::ostringstream oss;
    oss << "HTTP/1.1 " << error_message << "\r\n"
    << "Connection: close\r\n"
    << "Content-Type: text/html; charset=UTF-8\r\n"
    << "Content-Length: " << error_message.size() << "\r\n"
    << "Server: FredPi/0.1 (Unix) (Raspbian/Linux)\r\n"
    << "\r\n"
    << error_message;
    ustring output = to_unsigned(oss.str());
    auto res = co_await m_stream->write(output, option_singleton().session_timeout);
    if(res != stream_result::ok) {
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
                auto& domains = option_singleton().domain_names;
                if(domains.empty()) {
                    // could extract domain names from SSL certificate?
                    throw std::runtime_error("no configured domain names");
                }
                co_await redirect(std::move(*http_request), domains[0]);
                co_return;
            } else {
                auto res = co_await respond(m_folder, std::move(*http_request));
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
    const auto method = get_method( http_request.header);
    if(method.size() < 3) {
        throw http_error("400 Bad Request");
    }
    const std::filesystem::path& filename = method[1];
    if(method[2] != "HTTP/1.0" and method[2] != "HTTP/1.1") {
        throw http_error("505 HTTP Version Not Supported");
    }
    if(method[0] == "GET") {
        co_return co_await file_to_http(rootdirectory, filename);

    } else if(method[0] == "POST") {
        handle_POST(std::move( http_request));
        co_return co_await file_to_http(rootdirectory, filename);
    } else {
        throw http_error("405 Method Not Allowed\r\n");
    }
}

// POST requests need some server-dependent program logic
// Here we just sanitise and write the application/x-www-form-urlencoded data to final.html
void HTTP::handle_POST(http_frame frame) {
    auto body = to_signed(std::move(frame.body));
    std::ofstream fout(option_singleton().webpage_folder/"final.html", std::ios_base::app);
    body = std::regex_replace(body, std::regex("username="), "username: ");
    body = std::regex_replace(body, std::regex("&password="), ", password: ");
    body = std::regex_replace(body, std::regex("&confirm="), ", confirmed: ");
    body = std::regex_replace(body, std::regex("<"), "&lt;");
    body = std::regex_replace(body, std::regex(">"), "&gt;");
    body.append("</p>");
    body.insert(0,"<p>");
    fout << body << std::endl;
}

// HTTP responses include the body size in the header but, to fascilitate streaming, this is not
// directly known ahead of time so we need to extract the file size from the file itself
// rather than just call .size() on a container of data sent
std::ifstream::pos_type filesize(std::filesystem::path filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

// our HTTP client has sent an HTTP request. We send over the response header, then stream the file
// contents back to them. If sending would block, we park this coroutine for polling
task<stream_result> HTTP::file_to_http(const std::filesystem::path& rootdir, std::filesystem::path filename) {
    constexpr time_t day = 24*60*60;
    filename = fix_filename(std::move(filename));
    std::string MIME = Mime_from_file(filename);
    std::ifstream t(rootdir/filename.relative_path(), std::ifstream::ate | std::ifstream::binary);
    if(t.fail()) {
        throw http_error("404 Not Found");
    }
    size_t file_size = t.tellg();
    t.seekg(0);
    auto time = std::time(0);
    if(static_cast<std::time_t>(-1) == time) {
        throw http_error("500 Internal Server Error");
    }
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n"
        << "Date: " << timestring(time) << "\r\n"
        << "Expires: " << timestring(time + day) << "\r\n"
        << "Content-Type: " << MIME << (MIME.substr(0,4)=="text" ? "; charset=UTF-8" : "") << "\r\n"
        << "Content-Length: " << file_size << "\r\n"
        << "Connection: Keep-Alive\r\n"
        << "Keep-Alive: timeout=" << option_singleton().keep_alive.count() << "\r\n"
        << "Server: " << make_server_name() << "\r\n";

    if(option_singleton().http_strict_transport_security) {
        oss << "Strict-Transport-Security: max-age=31536000\r\n";
    }
    oss << "\r\n";

    auto res = co_await m_stream->write(to_unsigned(oss.str()), option_singleton().session_timeout);
    if(res != stream_result::ok) {
        co_return res;
    }
    
    const int buffer_size = 980;
    ustring buffer;
    while(!t.eof()) {
        buffer.resize(buffer_size);
        t.read((char*)buffer.data(), buffer.size());
        ssize_t s = t.gcount();
        buffer.resize(s);
        auto res = co_await m_stream->write(buffer, option_singleton().session_timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
    }
    co_return stream_result::ok;
}

// if a client connects over http:// we need to form a response redirecting them to https://
task<void> HTTP::redirect(http_frame request, std::string domain) {
    const auto method = get_method(request.header);
    if(method.size() < 3) {
        throw http_error("400 Bad Request");
    }
    
    std::string filename = fix_filename(std::move(method[1]));
    std::string MIME = Mime_from_file(filename);
    std::string body = "HTTP/1.1 301 Moved Permanently";
    
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
