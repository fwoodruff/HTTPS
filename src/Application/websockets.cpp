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
#include "../TLS/Cryptography/one_way/sha1.hpp"

namespace fbw {

task<stream_result> accept_upgrade(http_ctx& connection, std::string sec_ws_key) {
    static constexpr const char* websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    std::string websocket_accept_payload = (sec_ws_key + websocket_guid);
    sha1 hasher;
    hasher.update_impl(reinterpret_cast<const uint8_t*>(websocket_accept_payload.data()), websocket_accept_payload.size());
    auto websocket_accept_digest = hasher.hash();
    auto websocket_accept = base64_encode(websocket_accept_digest);
    // check version, if wrong, 400 error with version headers
    std::vector<entry_t> response_headers;
    response_headers.push_back({":status", "101"});
    response_headers.push_back({"upgrade", "websocket"});
    response_headers.push_back({"connection", "Upgrade"});
    response_headers.push_back({"sec-websocket-accept", websocket_accept});

    stream_result res = co_await connection.write_headers(response_headers);

    
    co_return res;
}

task<void> handle_websocket(http_ctx& connection, const std::vector<entry_t>& headers) {
    const auto sec_ws_key = find_header(headers, "sec-websocket-key");
    assert(sec_ws_key);
    auto res = co_await accept_upgrade(connection, *sec_ws_key);
    if(res != stream_result::ok) {
        co_return;
    }
    // todo: framing, and some useful handler
    co_return;
}

bool is_websocket_upgrade(const std::vector<entry_t>& headers) {
    auto upgrade    = find_header(headers, "upgrade");
    auto connection = find_header(headers, "connection");
    auto method     = find_header(headers, ":method");
    auto protocol   = find_header(headers, ":protocol");

    bool want_http1 = upgrade and (*upgrade) == "websocket" and connection;
    bool want_http2 = method and to_lower(*method) == "CONNECT" and protocol and to_lower(*protocol) == "websocket";

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
    return true;
}

}