//
//  proxy.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 14/03/2026.
//

#include "proxy.hpp"
#include "../IP/Awaitables/await_connect.hpp"
#include "../IP/tcp_stream.hpp"
#include "../HTTP/common/HTTP.hpp"
#include "../HTTP/common/string_utils.hpp"
#include "../global.hpp"

#include <deque>
#include <optional>

namespace fbw {

// Strip absolute-form URI (e.g. from Zscaler/forward proxies):
//   "https://example.com/foo?bar" -> "/foo?bar"
//   "/foo?bar"                    -> "/foo?bar"  (unchanged)
static std::string effective_path(const std::string& path) {
    if (path.starts_with("http://") || path.starts_with("https://")) {
        // find the '/' after "scheme://host"
        auto after_scheme = path.find("//");
        if (after_scheme == std::string::npos) {
            return "/";
        }
        auto path_start = path.find('/', after_scheme + 2);
        return (path_start != std::string::npos) ? path.substr(path_start) : "/";
    }
    return path;
}

// Parse a chunk-size line, stripping optional chunk extensions ("; ext=val")
// Returns std::nullopt on parse failure.
static std::optional<size_t> parse_chunk_size(const std::string& line) {
    auto semi = line.find(';');
    std::string hex = (semi != std::string::npos) ? line.substr(0, semi) : line;
    // trim whitespace
    auto s = hex.find_first_not_of(" \t\r\n");
    auto e = hex.find_last_not_of(" \t\r\n");
    if (s == std::string::npos) {
        return std::nullopt;
    }
    hex = hex.substr(s, e - s + 1);
    if (hex.empty()) {
        return std::nullopt;
    }
    try {
        size_t consumed = 0;
        size_t val = std::stoull(hex, &consumed, 16);
        if (consumed != hex.size()) {
            return std::nullopt;
        }
        return val;
    } catch (...) {
        return std::nullopt;
    }
}

task<void> handle_proxy_request(http_ctx& conn,
                                const std::string& method,
                                const std::string& path,
                                const std::vector<entry_t>& headers,
                                const proxy_rule& rule) {
    auto backend_opt = co_await connectable{rule.backend_host, rule.backend_port};
    if (!backend_opt) {
        throw http_error(502, "Bad Gateway");
    }
    auto& backend = *backend_opt;

    // Normalise path: strip absolute-form URI that forward proxies may send
    std::string norm_path = effective_path(path);

    std::string stripped = norm_path.substr(rule.frontend_path.size());
    if (stripped.empty() || stripped[0] == '?') {
        stripped = "/" + stripped;
    }
    std::string backend_request_path = rule.backend_path + stripped;

    // Build HTTP/1.1 request
    std::string request = method + " " + backend_request_path + " HTTP/1.1\r\n";
    request += "Host: " + rule.backend_host + ":" + std::to_string(rule.backend_port) + "\r\n";
    request += "X-Forwarded-For: " + conn.get_ip() + "\r\n";

    bool has_body = false;
    bool incoming_chunked = false;
    for (const auto& h : headers) {
        if (h.name.starts_with(':')) {
            continue;
        }
        if (h.name == "connection" || h.name == "keep-alive" || h.name == "transfer-encoding") {
            if (h.name == "transfer-encoding" &&
                to_lower(h.value).find("chunked") != std::string::npos) {
                incoming_chunked = true;
            }
            continue;
        }
        request += h.name + ": " + h.value + "\r\n";
        if (h.name == "content-length" && std::stoll(h.value) > 0) {
            has_body = true;
        }
    }
    request += "connection: close\r\n\r\n";

    if (co_await backend.write(to_unsigned(request), std::nullopt) != stream_result::ok) {
        throw http_error(502, "Bad Gateway");
    }

    // Forward request body if present (content-length or chunked)
    if (has_body || incoming_chunked) {
        std::deque<uint8_t> body_buf;
        for (;;) {
            auto [st, done] = co_await conn.append_http_data(body_buf);
            if (st != stream_result::ok) {
                co_return;
            }
            std::vector<uint8_t> chunk(body_buf.begin(), body_buf.end());
            body_buf.clear();
            if (!chunk.empty()) {
                if (co_await backend.write(chunk, std::nullopt) != stream_result::ok) {
                    co_return;
                }
            }
            if (done) {
                break;
            }
        }
    }

    // Read backend HTTP/1.1 response status line
    std::deque<uint8_t> resp_buf;
    auto status_line = co_await read_http_line(backend, resp_buf);
    if (!status_line) {
        throw http_error(502, "Bad Gateway");
    }

    // Parse "HTTP/1.1 200 OK" -> extract status code
    auto first_sp = status_line->find(' ');
    auto second_sp = (first_sp != std::string::npos) ? status_line->find(' ', first_sp + 1) : std::string::npos;
    if (first_sp == std::string::npos || second_sp == std::string::npos) {
        throw http_error(502, "Bad Gateway");
    }
    std::string status_code = status_line->substr(first_sp + 1, second_sp - first_sp - 1);

    // Read and forward backend response headers
    std::vector<entry_t> resp_headers;
    resp_headers.push_back({":status", status_code});
    std::optional<int64_t> resp_content_length;
    bool chunked = false;

    for (;;) {
        auto line = co_await read_http_line(backend, resp_buf);
        if (!line) {
            throw http_error(502, "Bad Gateway");
        }
        if (line->empty()) {
            break;
        }

        auto colon = line->find(':');
        if (colon == std::string::npos) {
            continue;
        }
        std::string name = to_lower(line->substr(0, colon));
        std::string value = line->substr(colon + 1);
        auto ws = value.find_first_not_of(" \t");
        value = (ws != std::string::npos) ? value.substr(ws) : "";

        if (name == "connection" || name == "keep-alive" || name == "te" ||
            name == "trailers" || name == "upgrade") {
            continue;
        }
        if (name == "transfer-encoding") {
            if (to_lower(value).find("chunked") != std::string::npos) {
                chunked = true;
            }
            continue;
        }
        if (name == "content-length") {
            try {
                resp_content_length = std::stoll(value);
            } catch (...) {}
        }
        resp_headers.push_back({name, value});
    }

    if (co_await conn.write_headers(resp_headers) != stream_result::ok) {
        co_return;
    }

    // Stream response body
    if (chunked) {
        for (;;) {
            auto size_line = co_await read_http_line(backend, resp_buf);
            if (!size_line) {
                break;
            }
            auto chunk_sz_opt = parse_chunk_size(*size_line);
            if (!chunk_sz_opt) {
                break;
            }
            size_t chunk_sz = *chunk_sz_opt;
            if (chunk_sz == 0) {
                break;
            }
            while (resp_buf.size() < chunk_sz) {
                if (co_await backend.read_append(resp_buf, std::nullopt) != stream_result::ok) {
                    co_return;
                }
            }
            std::vector<uint8_t> chunk(resp_buf.begin(), resp_buf.begin() + chunk_sz);
            resp_buf.erase(resp_buf.begin(), resp_buf.begin() + chunk_sz);
            co_await read_http_line(backend, resp_buf); // consume trailing CRLF after chunk data
            if (co_await conn.write_data(std::span<const uint8_t>(chunk), false) != stream_result::ok) {
                co_return;
            }
        }
        co_await conn.write_data(std::span<const uint8_t>{}, true);
    } else if (resp_content_length) {
        int64_t remaining = *resp_content_length;
        while (remaining > 0) {
            while (resp_buf.empty()) {
                if (co_await backend.read_append(resp_buf, std::nullopt) != stream_result::ok) {
                    co_return;
                }
            }
            size_t to_send = std::min(static_cast<int64_t>(resp_buf.size()), remaining);
            std::vector<uint8_t> chunk(resp_buf.begin(), resp_buf.begin() + to_send);
            resp_buf.erase(resp_buf.begin(), resp_buf.begin() + to_send);
            remaining -= static_cast<int64_t>(to_send);
            if (co_await conn.write_data(std::span<const uint8_t>(chunk), remaining == 0) != stream_result::ok) {
                co_return;
            }
        }
    } else {
        // Read until backend closes
        for (;;) {
            if (!resp_buf.empty()) {
                std::vector<uint8_t> chunk(resp_buf.begin(), resp_buf.end());
                resp_buf.clear();
                if (co_await conn.write_data(std::span<const uint8_t>(chunk), false) != stream_result::ok) {
                    co_return;
                }
            }
            auto res = co_await backend.read_append(resp_buf, std::nullopt);
            if (res == stream_result::closed || res == stream_result::read_closed) {
                if (!resp_buf.empty()) {
                    std::vector<uint8_t> chunk(resp_buf.begin(), resp_buf.end());
                    co_await conn.write_data(std::span<const uint8_t>(chunk), true);
                } else {
                    co_await conn.write_data(std::span<const uint8_t>{}, true);
                }
                break;
            }
            if (res != stream_result::ok) {
                break;
            }
        }
    }
}

} // namespace fbw
