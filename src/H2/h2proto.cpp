//
//  h2proto.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//

#include "../Runtime/task.hpp"

#include "h2proto.hpp"
#include <queue>
#include "../Runtime/executor.hpp"
#include "h2handler.hpp"
#include "h2frame.hpp"
#include "h2awaitable.hpp"
#include "../global.hpp"

namespace fbw {

const std::string connection_init = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

[[nodiscard]] task<void> HTTP2::client() {
    std::optional<h2_error> error;
    ustring buffer;
    using namespace std::chrono_literals;
    try {
        do {
            auto res = co_await m_stream->read_append(buffer, project_options.keep_alive);
            if(res == stream_result::closed) {
                co_return;
            }
            if(buffer.size() < connection_init.size()) {
                continue;
            }
        } while(false);
        for(size_t i = 0; i < connection_init.size(); i++) {
            if(connection_init[i] != buffer[i]) {
                co_return; // maybe with an error?
            }
        }
        buffer = buffer.substr(connection_init.size());

        while(true) {
            if(m_h2streams.size() < client_settings.max_concurrent_streams) {
                auto res = co_await m_stream->read_append(buffer, project_options.keep_alive);
                if(res == stream_result::closed) {
                    co_return;
                }
                if(res != stream_result::ok) {
                    co_await send_goaway(h2_code::NO_ERROR, "");
                    co_return;
                }
                
                for(;;) {
                    auto [frame, did_extract] = extract_frame(buffer);
                    if(!did_extract) {
                        break;
                    }
                    if(frame == nullptr) {
                        // unrecognised frame type
                        continue;
                    }
                    if (co_await handle_frame(*frame) != stream_result::ok) {
                        co_return;
                    }
                };
            } else {
                throw h2_error("too many concurrent streams", h2_code::FLOW_CONTROL_ERROR);
                // todo: executor - whereby stream handlers can choose to yield to other streams
            }
        }
    } catch(const h2_error& e) {
        error = e;
        goto END;
    } catch(const std::exception& e) { // todo: when can this happen?
        co_return;
    }
    co_return;
    END:
    co_await send_goaway(error->m_error_code, error->what());
}

task<stream_result> HTTP2::handle_frame(const h2frame& frame) {
    using enum h2_type;
    if(!received_settings and frame.type != SETTINGS) {
        throw h2_error("first frame must be SETTINGS", h2_code::PROTOCOL_ERROR);
    }
    switch(frame.type) {
        case DATA:
            handle_data_frame(dynamic_cast<const h2_data&>(frame));
            break;
        case HEADERS:
            handle_headers_frame(dynamic_cast<const h2_headers&>(frame));
            break;
        case PRIORITY:
            // rfc9113 recommends ignoring now
            break;
        case RST_STREAM:
            handle_rst_stream(dynamic_cast<const h2_rst_stream&>(frame));
            break;
        case SETTINGS: {
            co_return co_await handle_peer_settings(dynamic_cast<const h2_settings&>(frame));
        }
        case PUSH_PROMISE:
            throw h2_error("received a push promise from a client", h2_code::PROTOCOL_ERROR);
        case PING:
            if(!(frame.flags & h2_flags::ACK)) {
                h2_ping response_frame = dynamic_cast<const h2_ping&>(frame);
                response_frame.flags |= ACK;
                auto res = co_await m_stream->write(response_frame.serialise(), project_options.session_timeout);
                co_return res;
            }
            break;
        case GOAWAY:
            co_return stream_result::closed;
        case WINDOW_UPDATE: {
            auto& window = dynamic_cast<const h2_window_update&>(frame);
            if(window.stream_id == 0) {
                connection_current_window -= window.window_size_increment;
                while(!waiters_global.empty() and connection_current_window < client_settings.initial_window_size) {
                    waiters_global.front().resume();
                    waiters_global.pop();
                }
            } else if(window.stream_id > last_stream_id) {
                throw h2_error("bad window update", h2_code::PROTOCOL_ERROR);
            } else if(auto it = m_h2streams.find(window.stream_id); it != m_h2streams.end()) {
                std::coroutine_handle<> handle = nullptr;
                it->second->stream_current_window -= window.window_size_increment;
                if(it->second->stream_current_window < client_settings.initial_window_size) {
                    handle = std::exchange(it->second->m_writer, nullptr);
                    if(handle != nullptr) {
                        handle.resume();
                    }
                }
            }
            break;
        }
        default:
            throw h2_error("received bad frame type", h2_code::PROTOCOL_ERROR);
            co_return stream_result::closed;
    }
    co_return stream_result::ok;
}

void HTTP2::handle_data_frame(const h2_data& frame) {
    throw h2_error("client data handling not implemented", h2_code::INTERNAL_ERROR);
}

std::pair<std::unique_ptr<h2frame>, bool> extract_frame(ustring& buffer)  {
    if(buffer.size() >= 3) {
        auto size = try_bigend_read(buffer, 0, 3);
        if(size + H2_IDX_0 <= buffer.size()) {
            auto frame_bytes = buffer.substr(0, size + H2_IDX_0);
            std::unique_ptr<h2frame> frame = h2frame::deserialise(frame_bytes);
            buffer = buffer.substr(size + H2_IDX_0);
            return {std::move(frame), true};
        }
    }
    return {nullptr, false};
}

void HTTP2::handle_headers_frame(const h2_headers& frame) {
    auto it = m_h2streams.find(frame.stream_id);
    if(it == m_h2streams.end()) {
        if(frame.stream_id <= last_stream_id) {
            throw h2_error("bad stream id", h2_code::PROTOCOL_ERROR);
            // maybe check that it's the next one not just a later one
        }
        last_stream_id = frame.stream_id;
        auto strm = std::make_unique<h2_stream>();
        if(frame.flags & h2_flags::END_STREAM) {
            strm->state = stream_state::half_closed;
            strm->client_sent_headers = done;
        } else if(frame.flags & h2_flags::END_HEADERS) {
            strm->state = stream_state::open;
            strm->client_sent_headers = data_pp_trailers_expected;
        } else {
            strm->state = stream_state::open;
            strm->client_sent_headers = continuation_expected;
        }
        auto some_headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
        strm->receive_headers(std::move(some_headers));
        m_h2streams.insert({frame.stream_id, std::move(strm)});
        it = m_h2streams.find(frame.stream_id);
        assert(it != m_h2streams.end());
        if(frame.flags & h2_flags::END_HEADERS) {
            sync_spawn(handle_stream(shared_from_this(), frame.stream_id));
        }
    } else {
        if(it->second->client_sent_headers != data_pp_trailers_expected) {
            throw h2_error("trailers frame not expected", h2_code::PROTOCOL_ERROR);
        }
        if(frame.flags & h2_flags::END_STREAM) {
            it->second->client_sent_headers = done;
        } else {
            it->second->client_sent_headers = trailer_continuation_expected;
        }
        auto some_headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
        it->second->receive_trailers(std::move(some_headers));
    }
}

void HTTP2::handle_continuation_frame(const h2_continuation& frame) {
    auto it = m_h2streams.find(frame.stream_id);
    if(it == m_h2streams.end()) {
        throw h2_error("continuation of bad stream id", h2_code::PROTOCOL_ERROR);
    }
    auto some_headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
    if(it->second->client_sent_headers == continuation_expected) {
        it->second->receive_headers(std::move(some_headers));
    } else if (it->second->client_sent_headers == trailer_continuation_expected) {
        it->second->receive_trailers(std::move(some_headers));
    } else {
        throw h2_error("continuation not expected", h2_code::PROTOCOL_ERROR);
    }
}

void HTTP2::handle_rst_stream(const h2_rst_stream& frame) {
    m_h2streams.erase(frame.stream_id);
}

task<stream_result> HTTP2::handle_peer_settings(h2_settings settings) {
    if(settings.stream_id != 0) {
        throw h2_error("bad settings stream id", h2_code::PROTOCOL_ERROR);
    }
    if(settings.flags & h2_flags::ACK) {
        if(!settings.settings.empty()) {
            throw h2_error("bad ack frame", h2_code::PROTOCOL_ERROR);
        }
        if(awaiting_settings_ack == true) {
            awaiting_settings_ack = false;
            // todo: process any frames buffered while waiting for an ACK
            co_return stream_result::ok;
        }
    }
    for(const auto& setting : settings.settings) {
        using enum h2_settings_code;
        switch(setting.identifier) {
        case SETTINGS_HEADER_TABLE_SIZE:
            m_hpack.set_encoder_max_capacity(setting.value);
            break;
        case SETTINGS_ENABLE_PUSH:
            switch(setting.value) {
            case 0:
                server_settings.push_promise_enabled = false;
                break;
            case 1:
                server_settings.push_promise_enabled = true;
                break;
            default:
                throw h2_error("bad push promise setting", h2_code::PROTOCOL_ERROR);
            }
            break;
        case SETTINGS_MAX_CONCURRENT_STREAMS:
            server_settings.max_concurrent_streams = setting.value;
            break;
        case SETTINGS_INITIAL_WINDOW_SIZE: {
            if(setting.value > MAX_WINDOW_SIZE) {
                throw h2_error("bad flow control settings", h2_code::FLOW_CONTROL_ERROR);
            }
            int64_t diff = setting.value - server_settings.initial_window_size;
            connection_current_window += diff;
            for(const auto& stream : m_h2streams) {
                stream.second->stream_current_window += diff;
            }
            server_settings.initial_window_size = setting.value;
            break;
        }
        case SETTINGS_MAX_FRAME_SIZE:
            if(setting.value < MIN_FRAME_SIZE or setting.value > MAX_FRAME_SIZE) {
                throw h2_error("bad max frame control settings", h2_code::PROTOCOL_ERROR);
            }
            server_settings.max_frame_size = setting.value;
            break;
        case SETTINGS_MAX_HEADER_LIST_SIZE:
            server_settings.max_header_size = setting.value;
            break;
        default:
            // rfc9113 6.5.2, unknown settings are ignored
            break;
        }
    }

    received_settings = true;

    h2_settings server_settings;
    server_settings.type = h2_type::SETTINGS;
    server_settings.settings.push_back({h2_settings_code::SETTINGS_MAX_CONCURRENT_STREAMS, INITIAL_MAX_CONCURRENT_STREAMS});
    server_settings.settings.push_back({h2_settings_code::SETTINGS_INITIAL_WINDOW_SIZE, INITIAL_WINDOW_SIZE});
    server_settings.settings.push_back({h2_settings_code::SETTINGS_MAX_FRAME_SIZE, MAX_FRAME_SIZE});
    server_settings.settings.push_back({h2_settings_code::SETTINGS_MAX_HEADER_LIST_SIZE, HEADER_LIST_SIZE});
    server_settings.settings.push_back({h2_settings_code::SETTINGS_ENABLE_PUSH, 0});

    client_settings.max_concurrent_streams = INITIAL_MAX_CONCURRENT_STREAMS;
    client_settings.initial_window_size = INITIAL_WINDOW_SIZE;
    client_settings.max_frame_size = MAX_FRAME_SIZE;
    client_settings.max_header_size = HEADER_LIST_SIZE;
    client_settings.push_promise_enabled = false;

    auto server_settings_bytes = server_settings.serialise();

    auto res2 = co_await m_stream->write(server_settings_bytes, project_options.keep_alive);
    awaiting_settings_ack = true;

    if(res2 != stream_result::ok) {
        co_return res2;
    }

    h2_settings ack_frame;
    ack_frame.type = h2_type::SETTINGS;
    ack_frame.flags |= h2_flags::ACK;
    ack_frame.stream_id = 0;
    ack_frame.settings.clear();
    auto ack_bytes = ack_frame.serialise();
    auto res = co_await m_stream->write(ack_bytes, project_options.session_timeout);
    co_return res;
}

task<void> HTTP2::send_goaway(h2_code code, std::string message) {
    h2_goaway goawayframe;
    goawayframe.last_stream_id = last_stream_id;
    goawayframe.error_code = code;
    goawayframe.additional_debug_data = std::move(message);
    goawayframe.type = h2_type::GOAWAY;
    auto serial_go_away = goawayframe.serialise();
    auto res = co_await m_stream->write(serial_go_away, project_options.error_timeout);
    if(res != stream_result::ok) {
        co_return;
    }
    co_await m_stream->close_notify();
}

HTTP2::HTTP2(std::unique_ptr<stream> stream, std::string folder) : m_stream(std::move(stream)), m_folder(folder) {}

HTTP2::~HTTP2() {
    notify_close_sent = true;
    for (auto it = m_h2streams.begin(); it != m_h2streams.end();) {
        auto reader = std::exchange(it->second->m_reader, nullptr);
        if(reader) {
            reader.resume();
        }
        auto writer = std::exchange(it->second->m_reader, nullptr);
        if(writer) {
            writer.resume();
        }
    }
    while(!waiters_global.empty()) {
        auto coro = waiters_global.front();
        waiters_global.pop();
        coro.resume();
    }
    assert(waiters_global.empty());
}

void h2_stream::receive_headers(std::vector<entry_t> headers) {
    for(auto&& header : headers) {
        if(header.name == ":authority") {
            authority = header.value;
        } else if(header.name == ":method") {
            method = header.value;
        } else if(header.name == ":path") {
            path = header.value;
        } else if (header.name == ":scheme") {
            scheme = header.value;
        } else {
            m_received_headers.push_back(std::move(header));
        }
    }
}

void h2_stream::receive_trailers(std::vector<entry_t> headers) {
    for(auto&& header : headers) {
        m_received_trailers.push_back(std::move(header));
    }
}

h2_stream::~h2_stream() {
    assert(m_reader == nullptr);
    assert(m_writer == nullptr);
}

} // namespace 

