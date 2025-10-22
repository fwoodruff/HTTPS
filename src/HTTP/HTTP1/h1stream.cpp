//
//  h1stream.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 18/04/2025.
//

#include "h1stream.hpp"

#include <utility>

#include "../../Runtime/executor.hpp"

namespace fbw {

bool HTTP1::is_done() {
    return false;
}

std::string convert_response_to_http1_headers(const std::vector<entry_t>& headers) {
    std::string status;
    std::ostringstream out;
    try {
        for (const auto& h : headers) {
            if (h.name == ":status") {
                status = h.value;
            }
        }
        auto code = std::stoll(status);
        auto msg = http_code_map.at(code);
        out << "HTTP/1.1 " << status << " " << msg << "\r\n";
        for (const auto& h : headers) {
            if (h.name.starts_with(":")) {
                continue;
            }
            out << h.name << ": " << h.value << "\r\n";
        }
        out << "\r\n";
        return out.str();
    } catch(const std::exception& e) {
        return {};
    }
}

task<stream_result> HTTP1::write_headers(const std::vector<entry_t>& headers) {
    std::string const str = convert_response_to_http1_headers(headers);
    auto res = co_await m_stream->write(to_unsigned(str), project_options.session_timeout);
    co_return res;
}

task<stream_result> HTTP1::write_data(std::span<const uint8_t> data, bool end, bool do_flush) {
    auto send_data = m_buffered_writer.write(data, end or do_flush);
    while(!send_data.empty()) {
        auto& packet = send_data.front();
        auto res = co_await m_stream->write(std::move(packet), project_options.session_timeout);
        if(res != stream_result::ok) {
            co_return res;
       }
        send_data.pop_front();
    }

    auto count = counter.fetch_add(1, std::memory_order::relaxed);
    if(count % 0x40 == 0) {
        co_await yield_coroutine{};
    }
    co_return stream_result::ok;
}

task<std::pair<stream_result, bool>> HTTP1::append_http_data(std::deque<uint8_t>& buffer) {
    if(!m_read_buffer.empty()) {
        buffer.insert(buffer.end(), m_read_buffer.begin(), m_read_buffer.end());
        content_length_to_read -= m_read_buffer.size();
        m_read_buffer.clear();
        co_return {stream_result::ok, content_length_to_read <= 0 };
    }

    auto size_before = buffer.size();
    auto res = co_await m_stream->read_append(buffer, project_options.session_timeout);
    if(res != stream_result::ok) {
        co_return {res, true};
    }
    auto size_after = buffer.size();
    content_length_to_read -= (size_after - size_before);
    co_return {stream_result::ok, content_length_to_read <= 0 };
}

std::vector<entry_t> HTTP1::get_headers() {
    return headers;
}

HTTP1::HTTP1(std::unique_ptr<stream> stream, callback handler) : m_stream(std::move(stream)), m_application_handler(std::move(handler)), m_buffered_writer(WRITE_RECORD_SIZE) {}

std::string HTTP1::get_ip() {
    return m_stream->get_ip();
}

std::vector<entry_t> app_try_extract_header(std::deque<uint8_t>& m_buffer) {
    if(m_buffer.size() > MAX_HEADER_SIZE) {
        throw http_error(413, "Payload Too Large");
    }
    if (!m_buffer.empty() and (std::isupper(m_buffer[0]) == 0)) {
        throw http_error(400, "Invalid HTTP request"); 
    }

    auto header_bytes = extract(m_buffer, "\r\n\r\n");
    if(header_bytes.empty()) {
        return {};
    }
    auto headers_obj = parse_http_headers(to_signed(header_bytes));
    std::vector<entry_t> headers;
    headers.push_back({":method", headers_obj.verb});
    headers.push_back({":path", headers_obj.resource});
    headers.push_back({":h1protocol", headers_obj.protocol});
    for(auto& [ key, value] : headers_obj.headers ) {
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
            auto res = co_await m_stream->read_append(m_read_buffer, timeout);
            if(res != stream_result::ok) {
                break;
            }

            if (!did_handle_connection and m_read_buffer.size() >= 3 and m_read_buffer[0] == 0x16 and m_read_buffer[1] == 0x03
                    and (m_read_buffer[2] >= 0x00 && m_read_buffer[2] <= 0x04)) {
                static constexpr std::array<uint8_t,7> tls_alert = {0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46};
                std::vector<uint8_t> const alert_vec(tls_alert.begin(), tls_alert.end());
                auto res = co_await m_stream->write(alert_vec, project_options.session_timeout);
                if(res != stream_result::ok) {
                    break;
                }
                co_await m_stream->close_notify();
                co_return;
            }

            headers = app_try_extract_header(m_read_buffer);
            if(headers.empty()) {
                continue;
            }
            for(auto& entry : headers ) {
                if(entry.name == "content-length") {
                    try {
                        content_length_to_read = std::stoi( entry.value );
                    } catch(const std::exception& e) {
                        throw http_error(400, "Bad Request");
                    }
                    if(content_length_to_read > MAX_BODY_SIZE) {
                        throw http_error(413, "Payload Too Large");
                    }
                    if(content_length_to_read < 0) {
                        throw http_error(400, "Bad Request");
                    }
                }
            }
            bool const keep_alive = co_await m_application_handler(*this);
            std::vector<uint8_t> none {};
            auto send_data = m_buffered_writer.write(none, true);
            while(!send_data.empty()) {
                auto& packet = send_data.front();
                auto res = co_await m_stream->write(std::move(packet), project_options.session_timeout);
                if(res != stream_result::ok) {
                    break;
                }
                send_data.pop_front();
            }
            if(!keep_alive) {
                break;
            }
        } catch(const http_error& e) {
            err = e;
            goto END;
        }
        
        headers.clear();
        content_length_to_read = 0;
        did_handle_connection = true;
    }
    co_await m_stream->close_notify();
    co_return;
    END:
    co_await send_error(*this, err->m_http_code, err->what() );
    co_await m_stream->close_notify();
}



}