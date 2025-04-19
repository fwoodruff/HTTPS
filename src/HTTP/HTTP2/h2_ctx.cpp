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
    awaiting_settings_ack(false),
    go_away_sent(false),
    go_away_received(false),
    initial_settings_done(false) {

        server_settings.max_concurrent_streams = 5;

        connection_current_receive_window_remaining = server_settings.initial_window_size;
        connection_current_window_remaining = DEFAULT_INITIAL_WINDOW_SIZE;
}

std::vector<id_new> h2_context::receive_peer_frame(const h2frame& frame) {
    std::scoped_lock lk(m_mut);
    try {
        using enum h2_type;
        if(!initial_settings_done and frame.type != SETTINGS) {
            throw h2_error("How did you forget to send a SETTINGS frame?", h2_code::PROTOCOL_ERROR);
        }
        switch(frame.type) {
            case DATA:
                return receive_data_frame(dynamic_cast<const h2_data&>(frame));
            case HEADERS:
                return receive_headers_frame(dynamic_cast<const h2_headers&>(frame));
            case PRIORITY:
                if(client_settings.no_rfc7540_priorities) {
                    throw h2_error("You sent a PRIORITY frame. You said you wouldn't and you did it anyway.", h2_code::PROTOCOL_ERROR);
                }
                // RFC 9113 recommends ignoring these
                return {};
            case RST_STREAM:
                return receive_rst_stream(dynamic_cast<const h2_rst_stream&>(frame));
            case SETTINGS: {
                return receive_peer_settings(dynamic_cast<const h2_settings&>(frame));
            }
            case PUSH_PROMISE:
                throw h2_error("You sent a PUSH PROMISE frame. I am the server not you.", h2_code::PROTOCOL_ERROR);
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
                throw h2_error("I don't recognise that frame type and I chose not to ignore it", h2_code::INTERNAL_ERROR);
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

void update_client_settings(setting_values& client_settings, const h2_settings& settings_frame) {
    using enum h2_settings_code;
    for (const auto& setting : settings_frame.settings) {
        switch(setting.identifier) {
        case SETTINGS_INVALID:
            throw h2_error("invalid setting identifier", h2_code::PROTOCOL_ERROR);
        case SETTINGS_HEADER_TABLE_SIZE:
            client_settings.header_table_size = setting.value;
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
        case SETTINGS_NO_RFC7540_PRIORITIES:
            client_settings.no_rfc7540_priorities = (setting.value != 0);
            break;
        default:
            // ignore unrecognised options
            break;
        }
    }
}

std::vector<id_new> h2_context::receive_peer_settings(const h2_settings& frame) {
    if (frame.flags & h2_flags::ACK) {
        awaiting_settings_ack = false; // this is an ACK
        return {};
    }
    const int32_t old_initial_window = client_settings.initial_window_size;
    update_client_settings(client_settings, frame);
    m_hpack.set_decoder_max_capacity(client_settings.header_table_size);

    std::vector<id_new> out;
    if(!initial_settings_done) {
        h2_settings server_settings_frame = construct_settings_frame(server_settings, setting_values{});
        initial_settings_done = true;
        m_hpack.set_encoder_max_capacity(server_settings.header_table_size);
        outbox.push_back(server_settings_frame.serialise());

        constexpr uint32_t CONNECTION_UPDATE_INITIAL = 1048515;
        h2_window_update server_window;
        server_window.stream_id = 0;
        server_window.window_size_increment = CONNECTION_UPDATE_INITIAL;
        outbox.push_back(server_window.serialise());
        connection_current_receive_window_remaining += CONNECTION_UPDATE_INITIAL;
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
    }

    h2_settings ack;
    ack.flags = h2_flags::ACK;
    outbox.push_back(ack.serialise());
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
        strm.stream_current_window_remaining = client_settings.initial_window_size;// + 50'000'000;
        strm.stream_current_receive_window_remaining = server_settings.initial_window_size;
        strm.header_block = frame.field_block_fragment;
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
        stream_ctx_map.insert({frame.stream_id, std::move(strm)});
        auto& stream = stream_ctx_map[frame.stream_id];
        if(frame.flags & h2_flags::END_HEADERS) {
            stream.m_received_headers = m_hpack.parse_field_block(stream.header_block);
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
        stream.trailer_block = frame.field_block_fragment;
        if(frame.flags & h2_flags::END_HEADERS) {
            stream.m_received_trailers = m_hpack.parse_field_block(stream.trailer_block);
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
    auto some_headers = m_hpack.parse_field_block(std::move(frame.field_block_fragment));
    if(strm.client_sent_headers == headers_cont_expected) {
        strm.header_block.append(frame.field_block_fragment);
        if(frame.flags & h2_flags::END_HEADERS) {
            strm.m_received_headers = m_hpack.parse_field_block(strm.header_block);
            return {{frame.stream_id, wake_action::new_stream}};
        }
    } else if (strm.client_sent_headers == trailer_cont_expected) {
        strm.trailer_block.append(frame.field_block_fragment);
        if(frame.flags & h2_flags::END_HEADERS) {
            strm.m_received_trailers = m_hpack.parse_field_block(strm.trailer_block);
            return {{frame.stream_id, wake_action::wake_read}};
        }
    } else {
        throw h2_error("continuation not expected", h2_code::PROTOCOL_ERROR);
    }
    return {};
}

stream_result h2_context::stage_buffer(stream_ctx& stream) { // bool: suspend for completion
    assert(stream.strm_state != stream_state::closed);
    for(;;) {
        if(stream.outbox.empty()) {
            if(stream.server_data_done) {
                h2_data empty_frame;
                empty_frame.stream_id = stream.m_stream_id;
                empty_frame.flags |= h2_flags::END_STREAM;
                stream.strm_state = stream_state::closed;
                outbox.push_back(empty_frame.serialise());
            }
            return stream_result::ok;
        }
        if(stream.stream_current_window_remaining <= 0 || connection_current_window_remaining <= 0) {
            h2_ping ping_frame;
            ping_frame.opaque = 22;
            //outbox.push_front(ping_frame.serialise()); // diagnostic
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
    }
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
    assert(stream.strm_state != stream_state::closed);
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
    
    const auto field_block = m_hpack.generate_field_block(headers);
    size_t offset = 0;
    while (offset < field_block.size()) {
        uint32_t remaining = field_block.size() - offset;
        uint32_t chunk_size = std::min(client_settings.max_frame_size, remaining);
        ustring chunk(field_block.begin() + offset, field_block.begin() + offset + chunk_size);
        if (offset == 0) {
            h2_headers headers_frame;
            headers_frame.field_block_fragment = chunk;
            headers_frame.stream_id = stream_id;
            if (chunk_size == remaining) {
                headers_frame.flags |= h2_flags::END_HEADERS;
            }
            outbox.push_back(headers_frame.serialise());
        } else {
            h2_continuation cont_frame;
            cont_frame.field_block_fragment = chunk;
            cont_frame.stream_id = stream_id;
            if (chunk_size == remaining) {
                cont_frame.flags |= h2_flags::END_HEADERS;
            }
            outbox.push_back(cont_frame.serialise());
        }
        offset += chunk_size;
    }
    return true;
}

stream_result h2_context::stream_status(uint32_t stream_id) {
    std::scoped_lock lk(m_mut);
    auto it = stream_ctx_map.find(stream_id);
    if(it == stream_ctx_map.end()) {
        return stream_result::closed;
    }
    assert(it->first == stream_id);
    auto& stream = it->second;
    if(stream.strm_state == stream_state::closed) {
        return stream_result::closed;
    }
    if(stream.outbox.empty()) {
        return stream_result::ok;
    }
    if(connection_current_window_remaining <= 0 or stream.stream_current_window_remaining <= 0) {
        return stream_result::awaiting;
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
    stream.stream_current_window_remaining += frame.window_size_increment;
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