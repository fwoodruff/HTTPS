//
//  websockets.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 10/05/2025.
//

#include "websockets.hpp"
#include "http_handler.hpp"
#include "../HTTP/common/string_utils.hpp"

#include <coroutine>
#include <memory>
#include <atomic>
#include <span>
#include <array>
#include "../TLS/Cryptography/one_way/sha1.hpp"
#include "../Runtime/executor.hpp"
#include "../Runtime/reactor.hpp"

namespace fbw {

enum class ws_opcode : uint8_t {
    continuation = 0,
    text,
    binary,
    connection_op = 8,
    ping,
    pong
};

struct ws_frame {
    bool finished;
    ws_opcode opcode = ws_opcode::text;
    bool masked = false;
    std::array<uint8_t,4> mask_key {0,0,0,0};
    std::vector<uint8_t> payload;
};

websocket_handler::websocket_handler(std::shared_ptr<http_ctx> conn) :
    on_text_message([](std::string message) {}),
    on_binary_message([](std::vector<uint8_t> blob) {}),
    did_close(std::make_shared<std::atomic<bool>>(false)),
    m_conn(conn) {}

std::vector<uint8_t> serialise_ws_frame(const ws_frame& frame);
std::optional<ws_frame> extract_ws_frame(std::deque<uint8_t>& buffer);
task<stream_result> handle_incoming_bytes(http_ctx& conn, std::deque<uint8_t>& buffer, std::vector<uint8_t>& partial_message);

task<stream_result> accept_upgrade(http_ctx& connection, std::string sec_ws_key, std::string method) {
    static constexpr const char* websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    std::string websocket_accept_payload = (sec_ws_key + websocket_guid);
    sha1 hasher;
    hasher.update_impl(reinterpret_cast<const uint8_t*>(websocket_accept_payload.data()), websocket_accept_payload.size());
    auto websocket_accept_digest = hasher.hash();
    auto websocket_accept = base64_encode(websocket_accept_digest);
    std::vector<entry_t> response_headers;
    if(method == "CONNECT") {
        response_headers.push_back({":status", "200"});
    } else {
        response_headers.push_back({":status", "101"});
        response_headers.push_back({"upgrade", "websocket"});
        response_headers.push_back({"connection", "Upgrade"});
        response_headers.push_back({"sec-websocket-accept", websocket_accept});
    }

    stream_result res = co_await connection.write_headers(response_headers);

    
    co_return res;
}

task<void> websocket_handler::handle_incoming(std::shared_ptr<http_ctx> connection, websocket_handler handler) {
    std::deque<uint8_t> incoming_data;
    std::vector<uint8_t> partial_message;
    while(!handler.did_close->load()) {
        auto [res, data_done] = co_await connection->append_http_data(incoming_data);
        if(res != stream_result::ok) {
            handler.did_close->store(true);
            co_return;
        }
        auto res2 = co_await handle_incoming_bytes(*connection, incoming_data, partial_message); 
        if(res2 != stream_result::ok) {
            handler.did_close->store(true);
            co_return;
        }
        if(data_done) {
            handler.did_close->store(true);
            co_return;
        }
    }
}

task<stream_result> websocket_handler::send_text_message(const std::string& message) {
    if(this->did_close->load()) {
        co_return stream_result::closed;
    }
    ws_frame frame;
    frame.opcode = ws_opcode::text;
    frame.finished = true;
    frame.payload.assign(message.begin(), message.end());
    auto bytes = serialise_ws_frame(frame);
    auto res = co_await m_conn->write_data(bytes, false, true);
    co_return res;
}

task<stream_result> websocket_handler::listen(const std::vector<entry_t>& headers) {
    co_return stream_result::closed; // placeholder until implemented
    const auto sec_ws_key = find_header(headers, "sec-websocket-key");
    assert(sec_ws_key);
    auto res = co_await accept_upgrade(*m_conn, *sec_ws_key, *find_header(headers, ":method"));
    if(res != stream_result::ok) {
        co_return res;
    }
    sync_spawn(handle_incoming(m_conn, *this));
    co_return stream_result::ok;
}

bool is_websocket_upgrade(const std::vector<entry_t>& headers) {
    auto upgrade    = find_header(headers, "upgrade");
    auto connection = find_header(headers, "connection");
    auto method     = find_header(headers, ":method");
    auto protocol   = find_header(headers, ":protocol");

    bool want_http1 = upgrade and (*upgrade) == "websocket" and connection;
    bool want_http2 = method and to_lower(*method) == "connect" and protocol and to_lower(*protocol) == "websocket";

    if (want_http1) {
        bool conn_ok = false;
        for (auto tok : split(*connection, ",")) {
            remove_whitespace(tok);
            if (to_lower(tok) == "upgrade") {
                conn_ok = true;
                break;
            }
        }
        if (!conn_ok) {
            throw http_error(400, "Bad Request: Connection header must include 'Upgrade'");
        }
    }

    if ((upgrade || protocol) && !(want_http1 || want_http2)) {
        throw http_error(400, "Bad Request: Incomplete or invalid WebSocket upgrade headers");
    }

    if (!want_http1 and !want_http2) {
        return false;
    }

    if (want_http1) {
        if (!method || *method != "GET") {
            throw http_error(400, "Bad Request: WebSocket upgrade requires GET");
        }
    }

    auto key = find_header(headers, "sec-websocket-key");
    auto version = find_header(headers, "sec-websocket-version");
    if(!key) {
        throw http_error(400, "Bad Request: Missing Sec-WebSocket-Key");
    }
    if(!version) {
        throw http_error(400, "Bad Request: Unsupported Sec-WebSocket-Version");
    }
    if(*version != "13") {
        throw http_error(426, "Upgrade Required: Version 13 supported");
    }
    return true;
}

std::vector<uint8_t> serialise_ws_frame(const ws_frame& frame) {
    assert(!frame.masked);
    std::vector<uint8_t> out;
    out.reserve(2 + frame.payload.size() + 10);

    uint8_t b0 = (frame.finished ? 0x80 : 0x00) | (static_cast<uint8_t>(frame.opcode) & 0x0F);
    out.push_back(b0);

    const uint64_t n = frame.payload.size();
    if (n <= 125) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n <= 0xFFFF) {
        out.push_back(126);
        std::array<uint8_t, 2> serial_size;
        checked_bigend_write(n, serial_size, 0, 2);
        out.insert(out.end(), serial_size.begin(), serial_size.end());
    } else {
        out.push_back(127);
        std::array<uint8_t, 8> serial_size;
        checked_bigend_write(n, serial_size, 0, 8);
        out.insert(out.end(), serial_size.begin(), serial_size.end());
    }

    out.insert(out.end(), frame.payload.begin(), frame.payload.end());
    return out;
}

std::optional<ws_frame> extract_ws_frame(std::deque<uint8_t>& buffer) {
    return {}; // todo
}

task<stream_result> handle_incoming_bytes(http_ctx& conn, std::deque<uint8_t>& buffer, std::vector<uint8_t>& partial_message) {
    while(true) {
        auto frame_opt = extract_ws_frame(buffer);
        if(!frame_opt) {
            co_return stream_result::ok;
        }
        auto& frame = *frame_opt;
        using enum ws_opcode;
        switch(frame.opcode) {
        case ping: {
            ws_frame pong;
            pong.opcode = ws_opcode::pong;
            pong.finished = true;
            // todo: can partial frames be interleaved with pings?
            pong.payload = std::move(frame.payload);
            auto bytes = serialise_ws_frame(pong);
            auto res = co_await conn.write_data(bytes, false, true);
            if(res != stream_result::ok) {
                co_return res;
            }
        }
        case pong: {
            // todo: ensure receipt
        }
        case connection_op: {
            ws_frame close_frame;
            close_frame.opcode = ws_opcode::connection_op;
            close_frame.finished = true;
            close_frame.payload = std::move(frame.payload);
            auto bytes = serialise_ws_frame(close_frame);
            auto res = co_await conn.write_data(bytes, false, true);
            if(res != stream_result::ok) {
                co_return res;
            }
            co_return stream_result::closed;
        }
        case text: {
            ws_frame text_frame;
            text_frame.opcode = ws_opcode::text;
            co_return stream_result::closed; // not implemented
        }
        default:
            co_return stream_result::closed;
        }
    }
}

}