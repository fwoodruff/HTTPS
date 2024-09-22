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

namespace fbw {

[[nodiscard]] task<void> HTTP2::client() {
    std::optional<h2_error> error;
    ustring buffer;
    using namespace std::chrono_literals;
    try {
        while(true) {
            if(m_h2streams.size() < client_settings.max_concurrent_streams) {
                bool should_block = m_h2streams.empty() and !m_h2streams.empty();
                auto res = co_await m_stream->read_append(buffer, should_block? project_options.keep_alive : 0ms);
                if(res == stream_result::closed) {
                    co_return;
                }
                if(res != stream_result::ok and should_block) {
                    co_await send_goaway(h2_code::NO_ERROR);
                    co_return;
                }
                auto frames = extract_frames(buffer);
                for(const auto& frame : frames) {
                    if (co_await handle_frame(frame) != stream_result::ok) {
                        co_return;
                    }
                }
            }
            co_await process_streams();
        }
    } catch(const h2_error& e) {
        error = e;
        goto END;
    } catch(const std::exception& e) { // todo: when can this happen?
        co_return;
    }
    co_return;
    END:
    co_await send_goaway(error->m_error_code);
}

task<stream_result> HTTP2::handle_frame(const h2frame& frame) {
    
    using enum h2_type;
    if(!received_settings) {
        if(frame.type != SETTINGS) {
            co_await send_goaway(h2_code::PROTOCOL_ERROR);
            co_return stream_result::closed;
        }
    }
    switch(frame.type) {
        case DATA:
            // POST requests not implemented yet
            break;
        case HEADERS:
            handle_client_headers(dynamic_cast<const h2_headers&>(frame));
            break;
        case PRIORITY:
            // rfc9113 recommends ignoring now
            break;
        case RST_STREAM:
            handle_rst_stream(dynamic_cast<const h2_rst_stream&>(frame));
            break;
        case SETTINGS:
            set_peer_settings(dynamic_cast<const h2_settings&>(frame));
            break;
        case PUSH_PROMISE:
            throw h2_error("received a push promise from a client", h2_code::PROTOCOL_ERROR);
        case PING:
            if(!(frame.flags & h2_flags::ack)) {
                
                std::unique_ptr<h2frame> response_frame = std::make_unique<h2_ping>(dynamic_cast<const h2_ping&>(frame));
                response_frame->flags |= ack;
                outbox.push({std::move(response_frame), project_options.session_timeout});
                co_return stream_result::ok;
                
            }
            break;
        case GOAWAY:
            co_return stream_result::closed;
        case WINDOW_UPDATE: {
            auto& window = dynamic_cast<const h2_window_update&>(frame);
            if(window.stream_id == 0) {
                connection_current_window += window.window_size_increment;
            } else if(window.stream_id > last_stream_id) {
                throw h2_error("bad window update", h2_code::PROTOCOL_ERROR);
            } else if(auto it = m_h2streams.find(window.stream_id); it != m_h2streams.end()) {
                it->second->stream_current_window += window.window_size_increment;
            }
        }
        default:
            throw h2_error("received bad frame type", h2_code::PROTOCOL_ERROR);
            co_return stream_result::closed;
    }
    co_await flush();
    
    co_return stream_result::ok;
}

task<stream_result> HTTP2::flush() {
    while(true) {
        auto res = co_await write_one();
        if(res == stream_result::awaiting) {
            co_return stream_result::ok;
        }
        if(res != stream_result::ok) {
            co_return res;
        }
    }
}

task<stream_result> HTTP2::process_streams()  {
    for (auto it = m_h2streams.begin(); it != m_h2streams.end(); ) {
        auto& [stream_id, h2stream ] = *it;
        if(h2stream->client_sent_headers) {
            assert(h2stream->m_reader == nullptr or h2stream->m_writer == nullptr);
            auto read_coro = h2stream->m_reader.load();
            if(read_coro != nullptr) {
                if(!h2stream->inbox.empty()) {
                    read_coro.resume();
                }
            }
            auto write_coro = h2stream->m_writer.load();
            if(write_coro != nullptr) {
                // todo: check window
                write_coro.resume();
            }
        }
    }
    // todo:
    // co_await running_streams == 0, notified by h2-readable/h2-writable
    // reloop unsettled streams until all streams have settled
    // advanced:
    // block until either the client proxy or the read becomes available, whichever happens first
    assert(running_streams.load() == 0); // placeholder
    co_return co_await flush();
}

std::vector<h2frame> extract_frames(ustring& buffer)  {
    return {};
}

void HTTP2::handle_client_headers(const h2_headers& frame) {
    // identify stream frame belongs to
    // if new: create an entry for this stream (open) - check it's the next numbered stream, set window to initial value
    // else: check stream is in right state to accept headers
    
    auto it = m_h2streams.find(frame.stream_id);
    if(it == m_h2streams.end()) {
        if(frame.stream_id <= last_stream_id) {
            throw h2_error("bad stream id", h2_code::PROTOCOL_ERROR);
        }
        last_stream_id = frame.stream_id;
        auto strm = std::make_unique<h2_stream>();
        m_h2streams.insert({frame.stream_id, std::move(strm)});
        it = m_h2streams.find(frame.stream_id); // lock?
        assert(it != m_h2streams.end());
    }
    if(it->second->client_sent_headers) {
        throw h2_error("received headers after end of headers", h2_code::PROTOCOL_ERROR);
    }

    if(frame.flags | (h2_flags::end_stream | h2_flags::end_headers)) {
        it->second->client_sent_headers = true;
        async_spawn(handle_stream(shared_from_this(), frame.stream_id));
        // revisit data races, also maybe launch on current thread?
    }
    if(frame.flags & h2_flags::end_stream) {
        it->second->state = stream_state::half_closed;
    }
    // unpack headers
    // if last header, change open -> half-closed, send any push promises
}

void HTTP2::handle_rst_stream(const h2_rst_stream& frame) {
    // look up stream_id, if not present, ignore
    // if found, remove stream_id entry
}

void HTTP2::set_peer_settings(h2_settings settings) {
    if(settings.stream_id != 0) {
        throw h2_error("bad settings stream id", h2_code::PROTOCOL_ERROR);
    }
     if(settings.flags & h2_flags::ack) {
        if(!settings.data.empty()) {
            throw h2_error("bad ack frame", h2_code::PROTOCOL_ERROR);
        }
    }
    for(const auto& setting : settings.settings) {
        using enum h2_settings_codes;
        switch(setting.identifier) {
        case SETTINGS_HEADER_TABLE_SIZE:
            server_settings.compression_table_size = setting.value;
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
            if(setting.value > 0x7fffffff) {
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
            if(setting.value < 16384 or setting.value > 16777215) {
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
}

task<stream_result> HTTP2::write_one() {
    auto val = outbox.try_pop();
    if(!val) {
        co_return stream_result::awaiting;
    }
    auto [pframe, timeout] = std::move(*val);
    if ((pframe->flags & h2_flags::end_stream) or pframe->type == h2_type::RST_STREAM) {
        std::scoped_lock lk { conn_mut };
        m_h2streams.erase(pframe->stream_id); // lock
    }
    auto res = co_await m_stream->write(pframe->serialise(), timeout);
    if(pframe->type == h2_type::GOAWAY) {
        co_return stream_result::closed;
    }
    co_return res;
}

task<void> HTTP2::send_goaway(h2_code code) {
    h2_goaway goawayframe;
    goawayframe.last_stream_id = last_stream_id;
    goawayframe.error_code = code;
    outbox.push({std::make_unique<h2_goaway>(goawayframe), project_options.error_timeout});
    co_await flush();
}

HTTP2::HTTP2(std::unique_ptr<stream> stream, std::string folder) : m_stream(std::move(stream)), m_folder(folder) {}

void h2_stream::receive_headers(std::unordered_map<std::string, std::string> headers) {
    m_received_headers.merge(std::move(headers));
}

h2_stream::~h2_stream() {
    assert(m_reader == nullptr);
    assert(m_writer == nullptr);
}

} // namespace 

