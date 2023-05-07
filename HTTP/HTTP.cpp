//
//  HTTP.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "HTTP.hpp"
#include "string_utils.hpp"
#include "global.hpp"
#include "mimemap.hpp"

#include <iostream>
#include <sstream>
#include <memory>
#include <optional>
#include <fstream>
#include <string>
#include <regex>


namespace fbw {

HTTP::HTTP(std::unique_ptr<stream> stream, std::string folder, bool redirect) :
    m_folder(folder), m_redirect(redirect), m_stream(std::move(stream)) {
        assert(m_stream != nullptr);
}

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
        if(body.empty() == 0) {
            return std::nullopt;
        }
    }
    return { body };
}

task<std::optional<http_frame>> HTTP::try_read_http_request() {
    std::optional<ustring> header;
    for(;;) {
        header = try_extract_header(m_buffer);
        if(header) {
            break;
        }
        assert(m_stream != nullptr);
        bool connection_alive = co_await m_stream->read_append(m_buffer);
        if(!connection_alive) {
            co_return std::nullopt;
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
            co_return std::nullopt;
        }
        continue;
    }
    assert(body != std::nullopt);
    co_return http_frame { *header, *body };
    
}

// Unencrypted raw bytes get buffered in here.
// Responses are concatenated for each fully framed HTTP request, otherwise an empty value is returned.
task<void> HTTP::client() {
    std::optional<http_error> http_err {};
    try {
        for(;;) {
            auto http_request = co_await try_read_http_request();
            if(!http_request) {
                co_return; // connection closed by peer
            }
            if(m_redirect) {
                assert(false);
                co_await redirect(std::move(*http_request), domain_name);
            } else {
                co_await respond(m_folder, std::move(*http_request));
            }
        }
    } catch(const http_error& e) {
        http_err = e;
        goto ERROR; // cannot co_await inside catch block
    } catch(const stream_error& e) {
        goto ERROR;
    }
    catch(...) {
        assert(false);
    }
ERROR:
    if(http_err) {
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
        co_await m_stream->write(output);
        co_return;
    } else {
        // we close connection after a time out
        // courteous to send client a notification that we're doing this
        try {
            // co_await m_stream->close_notify();
        } catch(const stream_error& e) {
            std::cout << "caught in close notify" << std::endl;
        }
    }
}



// Creates an HTTP response from an HTTP request
task<void> HTTP::respond(const std::string& rootdirectory, http_frame http_request) {
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

/*
 Here we are just sanitising the inputs and putting them in a file
 */
void HTTP::handle_POST(http_frame frame) {
    auto body = to_signed(std::move(frame.body));
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

std::ifstream::pos_type filesize(std::string filename) {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
}

/*
 GET requests need to return files with a header
 */
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
        // << "ETag: " << make_eTag(file_contents) << "\r\n"
    << "\r\n";
    
    
    co_await m_stream->write(to_unsigned(oss.str()));
    
    ustring buffer (20000, '\0');
    while(!t.eof()) {
        t.read((char*)buffer.data(), buffer.size());
        ssize_t s = t.gcount();
        buffer.resize(s);
        co_await m_stream->write(buffer);
    }
}

task<void> HTTP::redirect(http_frame request, std::string domain) {
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
    assert(false);
    co_await m_stream->write(to_unsigned(var));
}

};// namespace fbw
