//
//  h2_ctx.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 03/04/2025.
//

#include "h2_ctx.hpp"

namespace fbw {

h2_context::h2_context() :
    last_server_stream_id(0),
    last_client_stream_id(0),
    connection_current_window_remaining(INITIAL_WINDOW_SIZE), 
    connection_current_receive_window_remaining(INITIAL_WINDOW_SIZE),
    awaiting_settings_ack(false),
    go_away_sent(false),
    go_away_received(false),
    initial_settings_done(false)
    {}

std::vector<id_new> h2_context::receive_peer_frame(const h2frame& frame) {
    std::scoped_lock lk(m_mut);
    try {
        using enum h2_type;
        if(!initial_settings_done and frame.type != SETTINGS) {
            throw h2_error("first frame must be SETTINGS", h2_code::PROTOCOL_ERROR);
        }
        switch(frame.type) {
            case DATA:
                return receive_data_frame(dynamic_cast<const h2_data&>(frame));
            case HEADERS:
                return receive_headers_frame(dynamic_cast<const h2_headers&>(frame));
            case PRIORITY:
                // RFC 9113 recommends ignoring now
                return {};
            case RST_STREAM:
                return receive_rst_stream(dynamic_cast<const h2_rst_stream&>(frame));
            case SETTINGS: {
                return receive_peer_settings(dynamic_cast<const h2_settings&>(frame));
            }
            case PUSH_PROMISE:
                throw h2_error("received a push promise from a client", h2_code::PROTOCOL_ERROR);
            case PING:
                if(!(frame.flags & h2_flags::ACK)) {
                    h2_ping response_frame = dynamic_cast<const h2_ping&>(frame);
                    response_frame.flags |= ACK;
                    outbox.push_front(response_frame.serialise());
                }
                return {};
            case GOAWAY:
                enqueue_goaway(h2_code::NO_ERROR, "");
                go_away_received = true;
                return {};
            case WINDOW_UPDATE:
                return receive_window_frame(dynamic_cast<const h2_window_update&>(frame));
            default:
                throw h2_error("received bad frame type", h2_code::PROTOCOL_ERROR);
        }
    } catch(const h2_error& error) {
        enqueue_goaway(error.m_error_code, error.what());
    }
    return {};
}

void h2_context::close_connection() {
    std::scoped_lock lk(m_mut);
    if(!go_away_sent) {
        enqueue_goaway(h2_code::NO_ERROR, "");
    }
    stream_ctx_map.clear();
}

std::pair<std::deque<ustring>, bool> h2_context::extract_outbox() {
    std::scoped_lock lk { m_mut };
    std::deque<ustring> data_contiguous = std::exchange(outbox, {});
    bool closing = go_away_sent and stream_ctx_map.empty();
    return { data_contiguous, closing };
}

std::vector<id_new> h2_context::receive_peer_settings(const h2_settings& frame) {
    if (frame.flags & h2_flags::ACK) {
        awaiting_settings_ack = false; // this is an ACK
        return {};
    }
    const int32_t old_initial_window = client_settings.initial_window_size;
    using enum h2_settings_code;
    for (const auto& setting : frame.settings) {
        switch(setting.identifier) {
        case SETTINGS_HEADER_TABLE_SIZE:
            client_settings.header_table_size = setting.value;
            m_hpack.set_decoder_max_capacity(setting.value);
            break;
        case SETTINGS_ENABLE_PUSH:
            client_settings.push_promise_enabled = (setting.value != 0);
            break;
        case SETTINGS_MAX_CONCURRENT_STREAMS:
            client_settings.max_concurrent_streams = setting.value;
            break;
        case SETTINGS_INITIAL_WINDOW_SIZE:
            client_settings.initial_window_size = setting.value;
            break;
        case SETTINGS_MAX_FRAME_SIZE:
            client_settings.max_frame_size = setting.value;
            break;
        case SETTINGS_MAX_HEADER_LIST_SIZE:
            client_settings.max_header_size = setting.value;
            break;
        default:
            break;
        }
    }

    std::vector<id_new> out;
    if(!initial_settings_done) {
        h2_settings server_settings_frame;
        //server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_HEADER_TABLE_SIZE, server_settings.header_table_size});
        server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_MAX_CONCURRENT_STREAMS, 100 });
        //server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_INITIAL_WINDOW_SIZE, server_settings.initial_window_size});
        //server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_MAX_FRAME_SIZE, server_settings.max_frame_size});
        //server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_MAX_HEADER_LIST_SIZE, server_settings.max_header_size});
        //server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_ENABLE_PUSH, (server_settings.push_promise_enabled? 1u : 0u) });
        initial_settings_done = true;
        m_hpack.set_encoder_max_capacity(server_settings.header_table_size);
        outbox.push_back(server_settings_frame.serialise());

        
        h2_settings ack;
        ack.flags = h2_flags::ACK;
        outbox.push_back(ack.serialise());

        //constexpr uint32_t CONNECTION_UPDATE_INITIAL = 1048515;
        //h2_window_update server_window;
        //server_window.stream_id = 0;
        //server_window.window_size_increment = CONNECTION_UPDATE_INITIAL;
        //outbox.push_back(server_window.serialise());
        //connection_current_receive_window_remaining += CONNECTION_UPDATE_INITIAL;
    } else {
        const int32_t delta = server_settings.initial_window_size - old_initial_window;
        for (auto & [sid, stream] : stream_ctx_map) {
            if (delta > 0) {
                if (stream.stream_current_window_remaining > INT32_MAX - delta) {
                    throw h2_error("stream window overflow", h2_code::FLOW_CONTROL_ERROR);
                }
            } else {
                if (stream.stream_current_window_remaining < INT32_MIN - delta) {
                    throw h2_error("stream window underflow", h2_code::FLOW_CONTROL_ERROR);
                }
            }
            stream.stream_current_window_remaining += delta;
            if(stream.stream_current_window_remaining > 0 and connection_current_window_remaining > 0) {
                out.push_back({sid, wake_action::wake_write});
            }
        }
        h2_settings ack;
        ack.flags = h2_flags::ACK;
        outbox.push_back(ack.serialise());
    }
    return out;
}
std::vector<id_new> h2_context::receive_data_frame(const h2_data& frame) {
    auto it = stream_ctx_map.find(frame.stream_id);
    if (it == stream_ctx_map.end()) {
        throw h2_error("DATA frame for nonexistent stream", h2_code::PROTOCOL_ERROR);
    }
    stream_ctx &stream = it->second;
    uint32_t data_length = frame.contents.size();
    
    // Check stream-level flow control
    if (data_length > stream.stream_current_receive_window_remaining) {
        raise_stream_error(h2_code::FLOW_CONTROL_ERROR, frame.stream_id);
        return {{frame.stream_id, wake_action::wake_read}};
    }
    // Check connection-level flow control
    if (data_length > connection_current_receive_window_remaining) {
        throw h2_error("connection flow control error", h2_code::FLOW_CONTROL_ERROR);
    }
    if(stream.strm_state == stream_state::half_closed or stream.strm_state == stream_state::closed) {
        raise_stream_error(h2_code::PROTOCOL_ERROR, frame.stream_id);
        return {{frame.stream_id, wake_action::wake_any}};
    }
    
    // update windows
    stream.stream_current_receive_window_remaining -= data_length;
    connection_current_receive_window_remaining -= data_length;
    
    // Buffer the data in the stream's inbox.
    stream.inbox.insert(stream.inbox.end(), frame.contents.begin(), frame.contents.end());
    
    // Update stream state if END_STREAM flag is set.
    if (frame.flags & h2_flags::END_STREAM) {
        stream.strm_state = stream_state::half_closed;
    }
    
    return {{frame.stream_id, wake_action::wake_read}};
}

bool is_higher_odd(uint32_t curr, uint32_t next) {
    if((next % 2) != 1) {
        return false;
    }
    if(next > INT32_MAX - 1) {
        return false;
    }
    if(next <= curr) {
        return false;
    }
    return true;
}

std::vector<id_new> h2_context::receive_headers_frame(const h2_headers& frame) {
    auto it = stream_ctx_map.find(frame.stream_id);
    if ( it ==stream_ctx_map.end()) {
        if(!is_higher_odd(last_client_stream_id, frame.stream_id)) {
            throw h2_error("bad stream id", h2_code::PROTOCOL_ERROR);
        }
        if(stream_ctx_map.size() > server_settings.max_concurrent_streams) {
            throw h2_error("too many streams", h2_code::FLOW_CONTROL_ERROR);
        }
        if(go_away_received) {
            throw h2_error("received new stream after go away", h2_code::PROTOCOL_ERROR);
        }

        last_client_stream_id = frame.stream_id;

        stream_ctx strm;
        strm.m_stream_id = frame.stream_id;
        strm.stream_current_window_remaining = client_settings.initial_window_size;
        strm.stream_current_receive_window_remaining = server_settings.initial_window_size;
        if(frame.flags & h2_flags::END_STREAM) {
            strm.strm_state = stream_state::half_closed;
            strm.client_sent_headers = done;
        } else if(frame.flags & h2_flags::END_HEADERS) {
            strm.strm_state = stream_state::open;
            strm.client_sent_headers = data_expected;
        } else {
            strm.strm_state = stream_state::open;
            strm.client_sent_headers = stream_frame_state::headers_cont_expected;
        }
        
        auto headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
        strm.m_received_headers.insert(strm.m_received_headers.end(), headers.begin(), headers.end());
        stream_ctx_map.insert({frame.stream_id, strm});

        if(frame.flags & h2_flags::END_HEADERS) {
            return {{frame.stream_id, wake_action::new_stream}};
        }
        return {};
    } else {
        auto stream = it->second;
        if(stream.client_sent_headers != data_expected) {
            throw h2_error("trailers frame not expected", h2_code::PROTOCOL_ERROR);
        }
        if(frame.flags & h2_flags::END_STREAM) {
            stream.client_sent_headers = done;
        } else {
            stream.client_sent_headers = trailer_cont_expected;
        }
        auto more_headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
        stream.m_received_trailers.insert(stream.m_received_trailers.end(), more_headers.begin(), more_headers.end());
        if(frame.flags & h2_flags::END_HEADERS) {
            return {{frame.stream_id, wake_action::wake_read}};
        }
        return {};
    }
}

std::vector<id_new> h2_context::receive_continuation_frame(const h2_continuation& frame) {
    auto it = stream_ctx_map.find(frame.stream_id);
    if(it == stream_ctx_map.end()) {
        throw h2_error("continuation of bad stream id", h2_code::PROTOCOL_ERROR);
    }
    auto& strm = it->second;
    auto some_headers = m_hpack.parse_field_block_fragment(std::move(frame.field_block_fragment));
    if(strm.client_sent_headers == headers_cont_expected) {
        strm.m_received_headers.insert(strm.m_received_headers.end(), some_headers.begin(), some_headers.end());
    } else if (strm.client_sent_headers == trailer_cont_expected) {
        strm.m_received_trailers.insert(strm.m_received_trailers.end(), some_headers.begin(), some_headers.end());
    } else {
        throw h2_error("continuation not expected", h2_code::PROTOCOL_ERROR);
    }
    if(frame.flags & h2_flags::END_HEADERS) {
        return {{frame.stream_id, wake_action::new_stream}};
    }
    return {};
}

stream_result h2_context::stage_buffer(stream_ctx& stream) { // bool: suspend for completion
    assert(stream.strm_state != stream_state::closed);
    if(stream.outbox.empty() and !stream.server_data_done) {
        return stream_result::ok;
    }
    if(stream.stream_current_window_remaining <= 0) {
        return stream_result::awaiting;
    }
    if(connection_current_window_remaining <= 0) {
        return stream_result::awaiting;
    }
    const auto max_frame_size = std::min(connection_current_window_remaining, stream.stream_current_window_remaining);
    const auto max_frame_size_allowed = std::min<int32_t>(max_frame_size, client_settings.max_frame_size);
    auto frame_size = std::min<int32_t>(max_frame_size_allowed, stream.outbox.size());
    connection_current_window_remaining -= frame_size;
    stream.stream_current_window_remaining -= frame_size;

    h2_data frame;
    frame.stream_id = stream.m_stream_id;
    frame.contents.assign(stream.outbox.begin(), stream.outbox.begin() + frame_size);
    stream.outbox.erase(stream.outbox.begin(), stream.outbox.begin() + frame_size);
    if(stream.server_data_done and stream.outbox.empty()) {
        frame.flags |= h2_flags::END_STREAM;
        stream.strm_state = stream_state::closed;
    }
    outbox.push_back(frame.serialise());
    if(stream.outbox.empty()) {
        return stream_result::ok;
    }
    return stream_result::awaiting;
}

std::optional<std::pair<size_t, bool>> h2_context::read_data(const std::span<uint8_t> app_data, uint32_t stream_id) {
    std::scoped_lock lk{ m_mut };
    auto it = stream_ctx_map.find(stream_id);
    if(it == stream_ctx_map.end()) {
        return {{0, true}};
    }
    auto& stream = it->second;
    if(stream.inbox.empty()) {
        return std::nullopt; // read is blocking
    }
    auto bytes_read = std::min<size_t>(stream.inbox.size(), app_data.size());
    std::copy(stream.inbox.begin(), stream.inbox.begin() + bytes_read, app_data.begin());
    stream.inbox.erase(stream.inbox.begin(), stream.inbox.begin() + bytes_read);

    if(stream.stream_current_receive_window_remaining > INT32_MAX - server_settings.initial_window_size ) {
        throw h2_error("flow control window overflow", h2_code::FLOW_CONTROL_ERROR);
    }
    if(stream.stream_current_receive_window_remaining < server_settings.initial_window_size) {
        h2_window_update window;
        window.stream_id = stream_id;
        window.window_size_increment = server_settings.initial_window_size;
        stream.stream_current_receive_window_remaining += window.window_size_increment;
        outbox.push_back(window.serialise());
    }
    if(connection_current_receive_window_remaining > INT32_MAX - server_settings.initial_window_size ) {
        throw h2_error("flow control window overflow", h2_code::FLOW_CONTROL_ERROR);
    }
    if(connection_current_receive_window_remaining < server_settings.initial_window_size) {
        h2_window_update window;
        window.stream_id = stream_id;
        window.window_size_increment = server_settings.initial_window_size;
        connection_current_receive_window_remaining += window.window_size_increment;
        outbox.push_back(window.serialise());
    }
    auto client_done = stream.strm_state == stream_state::closed or stream.strm_state == stream_state::half_closed;
    return {{bytes_read, client_done}};
}

std::vector<id_new> h2_context::receive_rst_stream(const h2_rst_stream& frame) {
    stream_ctx_map.erase(frame.stream_id);
    return {{frame.stream_id, wake_action::wake_any}};
}

stream_result h2_context::buffer_data(const std::span<const uint8_t> app_data, uint32_t stream_id, bool end) { // bool: suspend for completion
    std::scoped_lock lk{ m_mut };
    auto it = stream_ctx_map.find(stream_id);
    if(it == stream_ctx_map.end()) {
        return stream_result::closed;
    }
    auto& stream = it->second;
    assert(!stream.server_data_done);
    stream.server_data_done = end;
    stream.outbox.insert(stream.outbox.end(), app_data.begin(), app_data.end());

    auto res = stage_buffer(stream);
    if(stream.strm_state == stream_state::closed) {
        stream_ctx_map.erase(stream_id);
        return stream_result::closed;
    }
    return res;
}

bool h2_context::buffer_headers(const std::vector<entry_t>& headers, uint32_t stream_id) {
    std::scoped_lock lk{ m_mut };
    auto it = stream_ctx_map.find(stream_id);
    if(it == stream_ctx_map.end()) {
        return false;
    }
    h2_headers frame;
    auto fragment = m_hpack.generate_field_block_fragment(headers);
    frame.field_block_fragment = fragment;
    frame.flags |= h2_flags::END_HEADERS; // todo: case where we must split headers
    frame.stream_id = stream_id;
    frame.type = h2_type::HEADERS;
    outbox.push_back(frame.serialise());
    return true;
}

stream_result h2_context::is_closed(uint32_t stream_id) {
    std::scoped_lock lk{ m_mut };
    auto it = stream_ctx_map.find(stream_id);
    if(it == stream_ctx_map.end()) {
        return stream_result::closed;
    }
    auto& stream = it->second;
    if(stream.strm_state == stream_state::closed) {
        return stream_result::closed;
    }
    return stream_result::ok;
}
 
std::vector<entry_t> h2_context::get_headers(uint32_t stream_id) {
    std::scoped_lock lk{ m_mut };
    auto it = stream_ctx_map.find(stream_id);
    if(it == stream_ctx_map.end()) {
        return {};
    }
    auto& stream = it->second;
    return stream.m_received_headers;
}

std::vector<id_new> h2_context::receive_window_frame(const h2_window_update& frame) {
    if(frame.stream_id == 0) {
        std::vector<id_new> out;
        if(frame.window_size_increment == 0) {
            throw h2_error("received 0 size window update", h2_code::PROTOCOL_ERROR);
        }
        assert(frame.window_size_increment <= INT32_MAX);
        if (connection_current_window_remaining > INT32_MAX - frame.window_size_increment) {
            throw h2_error("flow control window overflow", h2_code::FLOW_CONTROL_ERROR);
        }
        connection_current_window_remaining += frame.window_size_increment;
        for(auto it = stream_ctx_map.begin(); it != stream_ctx_map.end(); ) {
            auto [id, stream] = *it;
            auto res = stage_buffer(stream);
            if(res != stream_result::awaiting) {
                out.push_back({id, wake_action::wake_write});
            }
            if(stream.strm_state == stream_state::closed) {
                it = stream_ctx_map.erase(it);
            } else{
                it++;
            }
        }
        return out;
    }
    if(frame.stream_id % 2 == 0) {
        if(frame.stream_id > last_server_stream_id) {
            throw h2_error("bad window update for server-initiated stream", h2_code::PROTOCOL_ERROR);
        }
    } else {
        if(frame.stream_id > last_client_stream_id) { 
            throw h2_error("bad window update for client-initiated stream", h2_code::PROTOCOL_ERROR);
        }
    }
    
    auto it = stream_ctx_map.find(frame.stream_id);
    if (it == stream_ctx_map.end()) {
        return {};
    }
    stream_ctx &stream = it->second;
    if (frame.window_size_increment == 0) {
        raise_stream_error(h2_code::PROTOCOL_ERROR, frame.stream_id);
        return {{frame.stream_id, wake_action::wake_write}};
    }
    stream_result suspend = stage_buffer(stream);
    if(stream.strm_state == stream_state::closed) {
        stream_ctx_map.erase(it);
    }
    if(suspend == stream_result::awaiting) {
        return {};
    }
    return {{frame.stream_id, wake_action::wake_write}};
}

void h2_context::enqueue_goaway(h2_code code, std::string message) {
    h2_goaway goawayframe;
    goawayframe.last_stream_id = last_client_stream_id;
    goawayframe.error_code = code;
    goawayframe.additional_debug_data = std::move(message);
    go_away_sent = true;
    outbox.push_back(goawayframe.serialise());
}

void h2_context::raise_stream_error(h2_code code, uint32_t stream_id) {
    auto it = stream_ctx_map.find(stream_id);
    if(it == stream_ctx_map.end()) {
        return;
    }
    h2_rst_stream frame;
    frame.stream_id = stream_id;
    frame.error_code = code;
    outbox.push_back(frame.serialise());
    stream_ctx_map.erase(it);
}


}