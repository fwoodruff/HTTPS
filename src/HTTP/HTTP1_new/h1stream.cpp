//
//  h2stream.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/11/2024.
//

#include "h1stream.hpp"

#include "../../Application/http_handler.hpp"

namespace fbw {


bool HTTP1::is_done() {
    return false;
}

std::string convert_to_http1_headers(const std::vector<entry_t>& headers) {
    std::string method, path, authority;
    std::ostringstream out;
    for (const auto& h : headers) {
        if (h.name == ":method") {
            method = h.value;
        } else if (h.name == ":path") {
            path = h.value;
        } else if (h.name == ":authority") {
            authority = h.value;
        }
    }
    if (method.empty() || path.empty()) {
        throw std::runtime_error("Missing required pseudo-headers for HTTP/1.1 conversion");
    }
    out << method << " " << path << " HTTP/1.1\r\n";
    for (const auto& h : headers) {
        if (h.name.starts_with(":")) {
            continue;
        }
        assert(to_lower(h.name) != "host");
        out << h.name << ": " << h.value << "\r\n";
    }
    if (!authority.empty()) {
        out << "Host: " << authority << "\r\n";
    }
    out << "\r\n";
    return out.str();
}

task<void> HTTP1::send_error(http_error http_err) {
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
    assert(m_stream);
    auto res = co_await m_stream->write(output, project_options.session_timeout);
    if(res == stream_result::ok) {
        co_await m_stream->close_notify();
    }
    co_return;
}

task<stream_result> HTTP1::write_headers(const std::vector<entry_t>& headers) {
    std::string str = convert_to_http1_headers(headers);
    auto res = co_await m_stream->write(to_unsigned(str), project_options.session_timeout);
    co_return res;
}

task<stream_result> HTTP1::write_data(std::span<const uint8_t> data, bool end) {
    ustring dat(data.begin(), data.end());
    auto res = co_await m_stream->write(dat, project_options.session_timeout);
    co_return res;
}

task<std::pair<stream_result, bool>> HTTP1::append_http_data(ustring& buffer) {
    auto size_before = buffer.size();
    auto res = m_stream->read_append(buffer, project_options.session_timeout);
    auto size_after = buffer.size();
    content_length_to_read -= (size_after - size_before);
    co_return {stream_result::ok, content_length_to_read <= 0 };
}

std::vector<entry_t> HTTP1::get_headers() {
    return headers;
}

HTTP1::HTTP1(std::unique_ptr<stream> stream, std::function<task<bool>(std::shared_ptr<http_ctx>)> handler): m_stream(std::move(stream)), m_handler(handler) {}

std::vector<entry_t> app_try_extract_header(ustring& m_buffer) {
    if(m_buffer.size() > MAX_HEADER_SIZE) {
        throw http_error("413 Payload Too Large");
    }
    auto header_bytes = extract(m_buffer, "\r\n\r\n");
    if(header_bytes.empty()) {
        return {};
    }
    auto headers_obj = parse_http_headers(to_signed(header_bytes));
    std::vector<entry_t> headers;
    headers.push_back({":method", headers_obj.verb});
    headers.push_back({":authority", headers_obj.headers["Host"]});
    headers.push_back({":path", headers_obj.resource});
    headers.push_back({":protocol", headers_obj.protocol});
    headers.push_back({":scheme", "https"}); // todo: fix me
    for(auto& [ key, value] : headers_obj.headers ) {
        if(key == "Host") {
            continue;
        }
        headers.push_back({key, value});
    }
    return headers;
}

task<void> HTTP1::client() {
    bool did_handle_connection = false;
    std::optional<http_error> err;
    for(;;) {
        try {
            auto timeout = did_handle_connection ? project_options.keep_alive : project_options.session_timeout;
            co_await m_stream->read_append(m_read_buffer, timeout);
            auto header = app_try_extract_header(m_read_buffer);
            if(header.empty()) {
                continue;
            }
            for(auto& entry : header ) {
                if(entry.name == "content-length") {
                    content_length_to_read = std::stoi( entry.value );
                }
            }
            bool keep_alive = co_await m_handler(shared_from_this());
            if(!keep_alive) {
                co_return;
            }
        } catch(const http_error& e) {
            err = e;
            goto END;
        }
        
        headers.clear();
        content_length_to_read = 0;
        did_handle_connection = true;
    }
    co_return;
    END:
    co_await send_error(*err);
}

}