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


template<class... Ts>
struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

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
task<http_reader> HTTP::try_read_http_request() {
    try {
        std::optional<ustring> header;
        for(;;) {
            header = try_extract_header(m_buffer);
            if(header) {
                break;
            }
            assert(m_stream != nullptr);
            bool connection_alive = co_await m_stream->read_append(m_buffer);
            if(!connection_alive) {
                co_return false;//std::monostate{};
            }
        }
        std::optional<ustring> body;
        for(;;) {
            assert(header != std::nullopt);
            body = try_extract_body(m_buffer, *header);
            if(body) {
                break;
            }
            bool connection_alive = co_await m_stream->read_append(m_buffer);
            if(!connection_alive) {
                co_return false;//std::monostate{};
            }
            continue;
        }
        assert(body != std::nullopt);
        co_return http_frame { *header, *body };
    } catch(...) {
        co_return std::current_exception();
    }
    
}

// a per-connection client handler that frames HTTP requests and buffers them for responses
task<void> HTTP::client_receiver() {
    std::exception_ptr eptr{};
    for(;;) {
        auto http_request = co_await try_read_http_request();
        try {
            bool success = co_await m_ringbuffer.enqueue(std::move(http_request));
            if (!success) {
                co_return;
            }
            co_await yield_coroutine{}; // prioritise responding to requests over reading requests
            
        } catch(...) {
            assert(false);
        }
        if(!std::holds_alternative<http_frame>(http_request)) {
            co_return;
        }
    }
}

// a per TCP client handler that consumes HTTP requests and responds to them
task<void> HTTP::client_responder() {
    std::exception_ptr eptr{};
    for(;;) {
        auto http_request = co_await m_ringbuffer.dequeue();
        bool return_after = false;
        
        if(!std::holds_alternative<http_frame>(http_request)) {
            return_after = true;
        }
        try {
            if(m_redirect) {
                auto domain = get_option("DOMAIN_NAME");
                co_await redirect(std::move(http_request), domain);
                m_ringbuffer.fast_fail();
            } else {
                co_await respond(m_folder, std::move(http_request));
            }
        } catch(...) {
            eptr = std::current_exception();
            goto ERROR;
        }
        if (return_after) {
            co_return; // connection closed by peer or error
        }
    }

    ERROR:
    co_await exception_handler(eptr);
}


task<void> HTTP::exception_handler(std::exception_ptr eptr) {
    m_ringbuffer.fast_fail();
    std::optional<http_error> http_err {};
    try {
        if (eptr) {
            std::rethrow_exception(eptr);
        }
        assert(false)
;    } catch(const http_error& e) {
        http_err = e; 
        goto ERROR; // cannot co_await inside catch block
    } catch(const stream_error& e) {
    } catch(const std::out_of_range& e) {
        std::cerr << e.what();
        std::cerr << "options not configured" << std::endl;
    }
    catch(const std::runtime_error& e) {
        std::cerr << e.what();
    } catch(...) {
        assert(false);
    }
    co_return; // cannot co_return inside catch block
ERROR:
    // if the request handler fails with an HTTP error, the error response is reported to the client here
    // for example this is where 404 Not Found messages are constructed and sent to clients
    auto error_message = std::string(http_err->what());
    std::ostringstream oss;
    oss << "HTTP/1.1 " << error_message << "\r\n"
    << "Connection: close\r\n"
    << "Content-Type: text/html; charset=UTF-8\r\n"
    << "Content-Length: " << error_message.size() << "\r\n"
    << "Server: FredPi/0.1 (Unix) (Raspbian/Linux)\r\n"
    << "\r\n"
    << error_message;
    ustring output = to_unsigned(oss.str());
    try {
        co_await m_stream->write(output);
    } catch (const stream_error& e) {
        
    }
    co_return;
}


// Creates an HTTP response from an HTTP request
task<void> HTTP::respond(const std::string& rootdirectory, http_reader request_var) {
    
    http_frame http_request {};

    co_await std::visit(overloaded{
            [&](http_frame arg) -> task<void> { http_request = std::move(arg); co_return; },
            [&](const std::exception_ptr& arg) -> task<void> { co_await exception_handler(arg); },
            [](bool b) -> task<void> { co_return; }
    }, request_var);
    if(!std::holds_alternative<http_frame>(request_var)) {
        co_return;
    }
    

    const auto method = get_method( http_request.header);
    if(method.size() < 3) {
        throw http_error("400 Bad Request");
    }
    const std::string& filename = method[1];
    if(method[2] != "HTTP/1.0" and method[2] != "HTTP/1.1") {
        throw http_error("505 HTTP Version Not Supported");
    }
    if(method[0] == "GET") {
        co_await file_to_http(rootdirectory, filename);
    } else if(method[0] == "POST") {
        handle_POST(std::move( http_request));
        co_await file_to_http(rootdirectory, filename);
    } else {
        throw http_error("405 Method Not Allowed\r\n");
    }
}

// POST requests need some server-dependent program logic
// Here we just sanitise and write the application/x-www-form-urlencoded data to final.html
void HTTP::handle_POST(http_frame frame) {
    auto body = to_signed(std::move(frame.body));
    auto rootdir = absolute_directory(get_option("WEBPAGE_FOLDER"));
    std::ofstream fout(rootdir+"/final.html", std::ios_base::app);
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
std::ifstream::pos_type filesize(std::string filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

// our HTTP client has sent an HTTP request. We send over the response header, then stream the file
// contents back to them. If sending would block, we park this coroutine for polling
task<void> HTTP::file_to_http(const std::string& rootdir, std::string filename) {
    constexpr time_t day = 24*60*60;
    filename = fix_filename(std::move(filename));
    std::string MIME = Mime_from_file(filename);
    
    std::ifstream t(rootdir+filename, std::ifstream::ate | std::ifstream::binary);
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
        << "Keep-Alive: timeout=5, max=1000\r\n"
        << "Server: " << make_server_name() << "\r\n"
    << "\r\n";

    co_await m_stream->write(to_unsigned(oss.str()));
    
    ustring buffer (980, '\0');
    while(!t.eof()) {
        t.read((char*)buffer.data(), buffer.size());
        ssize_t s = t.gcount();
        buffer.resize(s);
        co_await m_stream->write(buffer);
    }
}


// if a client connects over http:// we need to form a response redirecting them to https://
task<void> HTTP::redirect(http_reader request_var, const std::string& domain) {
    
    http_frame request {};
    
    co_await std::visit(overloaded{
            [&](http_frame arg) -> task<void> { request = std::move(arg); co_return; },
            [&](const std::exception_ptr& arg) -> task<void> { co_await exception_handler(arg); },
            [](bool b) -> task<void> {co_return; } 
    }, request_var);
    

    if(!std::holds_alternative<http_frame>(request_var)) {
        co_return;
    } 
    

    const auto method = get_method(request.header);
    if(method.size() < 3) {
        throw http_error("400 Bad Request");
    }
    
    std::string filename = fix_filename(std::move(method[1]));
    std::string MIME = Mime_from_file(filename);
    std::string body = "HTTP/1.1 301 Moved Permanently";
    
    std::ostringstream oss;
    oss << "HTTP/1.1 301 Moved Permanently\r\n"
        << "Location: https://" << domain << filename << "\r\n"
        << "Content-Type: " << MIME << (MIME.substr(0,4)=="text" ? "; charset=UTF-8" : "") << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Server: " << make_server_name() << "\r\n"
        << "\r\n"
        << body;
    
    std::string var = oss.str();
    co_await m_stream->write(to_unsigned(var));
}


};// namespace fbw
