//
//  h2proto.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//

#include "../../Runtime/task.hpp"

#include "h2proto.hpp"
#include <queue>
#include "../../Runtime/executor.hpp"
#include "../../Application/http_handler.hpp"
#include "h2frame.hpp"
#include "h2awaitable.hpp"
#include "../../global.hpp"
#include "h2stream.hpp"

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
        case WINDOW_UPDATE:
            co_await handle_window_frame(dynamic_cast<const h2_window_update&>(frame));
            break;
        default:
            throw h2_error("received bad frame type", h2_code::PROTOCOL_ERROR);
            co_return stream_result::closed;
    }
    co_return stream_result::ok;
}

task<stream_result> HTTP2::write_headers(int32_t stream_id, const std::vector<entry_t>& headers, bool end) {
    h2_headers frame;
    auto fragment = m_hpack.generate_field_block_fragment(headers);
    frame.field_block_fragment = fragment;
    if(end) {
        frame.flags |= h2_flags::END_STREAM;
    }
    frame.flags |= h2_flags::END_HEADERS;
    frame.stream_id = stream_id;
    frame.type = h2_type::HEADERS;
    auto frame_bytes = frame.serialise();
    auto stream_res = co_await m_stream->write(frame_bytes, project_options.session_timeout);
    co_return stream_res;
}

task<stream_result> HTTP2::handle_window_frame(const h2_window_update& frame) {
    if(frame.stream_id == 0) {
        if(frame.window_size_increment == 0) {
            throw h2_error("received 0 size window update", h2_code::PROTOCOL_ERROR);
        }
        connection_current_window_remaining += frame.window_size_increment;
        while(!waiters_global.empty() and connection_current_window_remaining > 0) {
            waiters_global.front().resume();
            waiters_global.pop();
        }
    } else if(frame.stream_id > last_stream_id) {
        throw h2_error("bad window update", h2_code::PROTOCOL_ERROR);
    } else if(auto it = m_h2streams.find(frame.stream_id); it != m_h2streams.end()) {
        if(frame.window_size_increment == 0) {
            co_return co_await raise_stream_error(h2_code::PROTOCOL_ERROR, frame.stream_id);
        }
        std::coroutine_handle<> handle = nullptr;
        auto stream = it->second.lock();
        if(stream != nullptr) {
            co_return stream_result::closed;
        }
        stream->stream_current_window_remaining += frame.window_size_increment;
        if(stream->stream_current_window_remaining > 0x7fffffff) {
            co_return co_await raise_stream_error(h2_code::PROTOCOL_ERROR, frame.stream_id);
        }
        if(stream->stream_current_window_remaining > 0) {
            handle = std::exchange(stream->m_writer, nullptr);
            if(handle != nullptr) {
                handle.resume();
            }
        }
    }
    co_return stream_result::ok;
}

task<stream_result> HTTP2::raise_stream_error(h2_code code, uint32_t stream_id) {
    auto it = m_h2streams.find(stream_id);
    if(it != m_h2streams.end()) {
        auto stream = it->second.lock();
        auto handle = std::exchange(stream->m_writer, nullptr);
        if(handle == nullptr) {
            handle = std::exchange(stream->m_reader, nullptr);
        }
        m_h2streams.erase(stream_id);
        if(handle != nullptr) {
            handle.resume();
        }
    }
    h2_rst_stream frame;
    frame.stream_id = stream_id;
    frame.error_code = code;
    auto frame_bytes = frame.serialise();
    co_return co_await m_stream->write(frame_bytes, project_options.session_timeout);
}

void HTTP2::handle_data_frame(const h2_data& frame) {
    // send window updates on receipt of data frames
    throw h2_error("client data handling not implemented", h2_code::INTERNAL_ERROR);
}

std::pair<std::unique_ptr<h2frame>, bool> extract_frame(ustring& buffer)  {
    if(buffer.size() >= 3) {
        auto size = try_bigend_read(buffer, 0, 3);
        if(size + H2_FRAME_HEADER_SIZE <= buffer.size()) {
            auto frame_bytes = buffer.substr(0, size + H2_FRAME_HEADER_SIZE);
            std::unique_ptr<h2frame> frame = h2frame::deserialise(frame_bytes);
            buffer = buffer.substr(size + H2_FRAME_HEADER_SIZE);
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
        auto strm = std::make_shared<h2_stream>();
        if(frame.flags & h2_flags::END_STREAM) {
            strm->state = stream_state::half_closed;
            strm->client_sent_headers = done;
        } else if(frame.flags & h2_flags::END_HEADERS) {
            strm->state = stream_state::open;
            strm->client_sent_headers = data_expected;
        } else {
            strm->state = stream_state::open;
            strm->client_sent_headers = stream_frame_state::headers_cont_expected;
        }
        strm->m_stream_id = frame.stream_id;
        strm->wp_connection = weak_from_this();
        strm->stream_current_window_remaining = server_settings.initial_window_size;
        auto some_headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
        strm->receive_headers(std::move(some_headers));
        m_h2streams.insert({frame.stream_id, strm});
        it = m_h2streams.find(frame.stream_id);
        assert(it != m_h2streams.end());
        assert(strm != nullptr);
        sync_spawn(handle_stream(strm));
    } else {
        auto stream = it->second.lock();
        if(stream->client_sent_headers != data_expected) {
            throw h2_error("trailers frame not expected", h2_code::PROTOCOL_ERROR);
        }
        if(frame.flags & h2_flags::END_STREAM) {
            stream->client_sent_headers = done;
        } else {
            stream->client_sent_headers = trailer_cont_expected;
        }
        auto some_headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
        stream->receive_trailers(std::move(some_headers));
    }
}

task<void> handle_stream(std::shared_ptr<h2_stream> stream) {
    assert(stream != nullptr);
    co_await application_handler(stream);
    auto id = stream->m_stream_id;
    auto conn = stream->wp_connection.lock();
    if(conn) {
        // ensure we are running on the same thread as the connection here
        conn->m_h2streams.erase(id);
    }
    co_return;
}

void HTTP2::handle_continuation_frame(const h2_continuation& frame) {
    auto it = m_h2streams.find(frame.stream_id);
    auto stream = it->second.lock();
    if(it == m_h2streams.end()) {
        throw h2_error("continuation of bad stream id", h2_code::PROTOCOL_ERROR);
    }
    auto some_headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
    if(stream->client_sent_headers == headers_cont_expected) {
        stream->receive_headers(std::move(some_headers));
    } else if (stream->client_sent_headers == trailer_cont_expected) {
        stream->receive_trailers(std::move(some_headers));
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
            std::vector<std::coroutine_handle<>> resumable;
            std::vector<uint32_t> bad_streams;
            for(const auto& stream_it : m_h2streams) {
                auto stream = stream_it.second.lock();
                if(stream != nullptr) {
                    co_return stream_result::ok;
                }
                stream->stream_current_window_remaining += diff;
                if(stream->stream_current_window_remaining > 0x7fffffff) {
                    bad_streams.push_back(stream_it.first);
                    continue;
                }
                if(stream->stream_current_window_remaining > 0) {
                    std::coroutine_handle<> handle = std::exchange(stream->m_writer, nullptr);
                    if(handle != nullptr) {
                        resumable.push_back(handle);
                    }
                }
            }
            for(auto handle : resumable) {
                handle.resume();
            }
            for(auto stream_i : bad_streams) {
                auto res = co_await raise_stream_error(h2_code::FRAME_SIZE_ERROR, stream_i);
                if(res != stream_result::ok) {
                    co_return res;
                }
            }
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
    auto serial_go_away = goawayframe.serialise();
    auto res = co_await m_stream->write(serial_go_away, project_options.error_timeout);
    if(res != stream_result::ok) {
        co_return;
    }
    co_await m_stream->close_notify();
}

HTTP2::HTTP2(std::unique_ptr<stream> stream, std::string folder) : m_stream(std::move(stream)), m_folder(folder), 
    connection_current_window_remaining(INITIAL_WINDOW_SIZE), 
    last_stream_id(0),
    received_settings(false),
    awaiting_settings_ack(false),
    notify_close_sent(false) {}

HTTP2::~HTTP2() {
    notify_close_sent = true;
    for (auto it = m_h2streams.begin(); it != m_h2streams.end();) {
        auto stream = it->second.lock();
        auto reader = std::exchange(stream->m_reader, nullptr);
        if(reader) {
            reader.resume();
        }
        auto writer = std::exchange(stream->m_reader, nullptr);
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

h2_stream::~h2_stream() {
    assert(m_reader == nullptr);
    assert(m_writer == nullptr);
}

// writes as much as window allows then return
task<stream_result> HTTP2::write_some_data(int32_t stream_id, std::span<const uint8_t>& bytes, bool data_end) {
    auto num_bytes = co_await h2writewindowable{ m_h2streams[stream_id], (uint32_t)bytes.size() };
    if(notify_close_sent) {
        co_return stream_result::closed;
    }
    ssize_t bytes_to_write = std::min(size_t(num_bytes), bytes.size());
    while(bytes_to_write > 0) {
        auto frame_size = std::min(ssize_t(server_settings.max_frame_size), bytes_to_write);
        h2_data frame;
        frame.type = h2_type::DATA;
        frame.stream_id = stream_id;
        if(data_end and bytes_to_write == bytes.size()) {
            frame.flags |= h2_flags::END_STREAM;
        }
        frame.contents.assign(bytes.begin(), bytes.begin() + frame_size);
        assert(!notify_close_sent);
        
        auto frame_bytes = frame.serialise();
        auto strmres = co_await m_stream->write(frame_bytes, project_options.session_timeout);
        if(strmres != stream_result::ok) {
            co_return strmres;
        }
        bytes = bytes.subspan(frame_size);
        bytes_to_write -= frame_size;
        assert(bytes_to_write >= 0);
    }
    co_return stream_result::ok;
}


} // namespace 

