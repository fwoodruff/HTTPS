
#include "h2frame.hpp"
#include "../../global.hpp"

#include <sstream>


namespace fbw {

using enum h2_code;

std::unique_ptr<h2_data> deserialise_DATA(const ustring& frame_bytes);
std::unique_ptr<h2_headers> deserialise_HEADERS(const ustring& frame_bytes);
std::unique_ptr<h2_priority> deserialise_PRIORITY(const ustring& frame_bytes);
std::unique_ptr<h2_rst_stream> deserialise_RST_STREAM(const ustring& frame_bytes);
std::unique_ptr<h2_settings> deserialise_SETTINGS(const ustring& frame_bytes);
std::unique_ptr<h2_push_promise> deserialise_PUSH_PROMISE(const ustring& frame_bytes);
std::unique_ptr<h2_ping> deserialise_PING(const ustring& frame_bytes);
std::unique_ptr<h2_goaway> deserialise_GOAWAY(const ustring& frame_bytes);
std::unique_ptr<h2_window_update> deserialise_WINDOW_UPDATE(const ustring& frame_bytes);
std::unique_ptr<h2_continuation> deserialise_CONTINUATION(const ustring& frame_bytes);
void set_base_frame_values(h2frame& frame, const ustring& frame_bytes);

h2_data::h2_data() {
    type = h2_type::DATA;
}
h2_headers::h2_headers() {
    type = h2_type::HEADERS;
}
h2_priority::h2_priority() {
    type = h2_type::PRIORITY;
}
h2_rst_stream::h2_rst_stream() {
    type = h2_type::RST_STREAM;
}
h2_settings::h2_settings() {
    type = h2_type::SETTINGS;
}
h2_push_promise::h2_push_promise() {
    type = h2_type::PUSH_PROMISE;
}
h2_ping::h2_ping() {
    type = h2_type::PING;
}
h2_goaway::h2_goaway() {
    type = h2_type::GOAWAY;
}
h2_window_update::h2_window_update() {
    type = h2_type::WINDOW_UPDATE;
}
h2_continuation::h2_continuation() {
    type = h2_type::CONTINUATION;
}

std::unique_ptr<h2frame> h2frame::deserialise(const ustring& frame_bytes) { // todo, span
    assert(frame_bytes.size() >= H2_FRAME_HEADER_SIZE);
    auto type = static_cast<h2_type>(frame_bytes[3]);
    try {
        auto size = try_bigend_read(frame_bytes, 0, 3);
        assert(size == frame_bytes.size() - H2_FRAME_HEADER_SIZE);
        using enum h2_type;
        switch(type) {
            case DATA: 
                return deserialise_DATA(frame_bytes);
            case HEADERS: 
                return deserialise_HEADERS(frame_bytes);
            case PRIORITY:
                return deserialise_PRIORITY(frame_bytes);
            case RST_STREAM:
                return deserialise_RST_STREAM(frame_bytes);
            case SETTINGS:
                return deserialise_SETTINGS(frame_bytes);
            case PUSH_PROMISE: 
                return deserialise_PUSH_PROMISE(frame_bytes);
            case PING:
                return deserialise_PING(frame_bytes);
            case GOAWAY:
                return deserialise_GOAWAY(frame_bytes);
            case WINDOW_UPDATE:
                return deserialise_WINDOW_UPDATE(frame_bytes);
            case CONTINUATION: 
                return deserialise_CONTINUATION(frame_bytes);
            case ALTSVC: [[fallthrough]];
            case ORIGIN: [[fallthrough]];
            case PRIORITY_UPDATE: [[fallthrough]];
            default:
                return nullptr;
        }
    } catch(const std::out_of_range& e) {
        throw h2_error("malformed frame", h2_code::FRAME_SIZE_ERROR);
    } catch(const std::exception& e) {
        throw h2_error("unexpected deserialisation error", h2_code::INTERNAL_ERROR);
    }
}

std::unique_ptr<h2_data> deserialise_DATA(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    assert(size + H2_FRAME_HEADER_SIZE == frame_bytes.size());
    auto frame = std::make_unique<h2_data>();
    set_base_frame_values(*frame, frame_bytes);
    if(frame->flags & h2_flags::PADDED) {
        frame->pad_length = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE, 1);
        auto begin = frame_bytes.begin() + H2_FRAME_HEADER_SIZE+1;
        frame->contents.assign(begin, begin + size-1 - frame->pad_length);
    } else {
        frame->pad_length = 0;
        frame->contents.assign(frame_bytes.begin() + H2_FRAME_HEADER_SIZE, frame_bytes.end());
    }
    return frame;
}

std::unique_ptr<h2_headers> deserialise_HEADERS(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    assert(size + H2_FRAME_HEADER_SIZE == frame_bytes.size());
    auto frame = std::make_unique<h2_headers>();
    set_base_frame_values(*frame, frame_bytes);
    size_t idx = 0;
    if(frame->flags & h2_flags::PADDED) {
        frame->pad_length = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE, 1);
        idx += 1;
    } else {
        frame->pad_length = 0;
    }
    if(frame->flags & h2_flags::PRIORITY) {
        const uint32_t dep_ex = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE + idx, 4);
        frame->stream_dependency = dep_ex & ~(1u << 31);
        frame->exclusive = (dep_ex & (1u << 31)) != 0;
        frame->weight = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE + idx + 4, 1);
        idx += 5;
    }
    auto begin = frame_bytes.begin() + H2_FRAME_HEADER_SIZE + idx;
    frame->field_block_fragment.assign(begin, begin + size - idx - frame->pad_length);
    assert(frame->field_block_fragment.size() + idx + frame->pad_length == size);
    return frame;
}

std::unique_ptr<h2_priority> deserialise_PRIORITY(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    auto frame = std::make_unique<h2_priority>();
    set_base_frame_values(*frame, frame_bytes);
    const uint32_t dep_ex = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE, 4);
    frame->stream_dependency = dep_ex & ~(1u << 31);
    frame->exclusive = (dep_ex & (1u << 31)) != 0;
    frame->weight = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE + 4, 1);
    if(size != 5) {
        throw h2_error("malformed PRIORITY frame", h2_code::FRAME_SIZE_ERROR);
    }
    return frame;
}

std::unique_ptr<h2_rst_stream> deserialise_RST_STREAM(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    auto frame = std::make_unique<h2_rst_stream>();
    set_base_frame_values(*frame, frame_bytes);
    frame->error_code = (h2_code)try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE, 4);
    if(size != 4) {
        throw h2_error("malformed RST_STREAM frame", h2_code::FRAME_SIZE_ERROR);
    }
    return frame;
}

std::unique_ptr<h2_settings> deserialise_SETTINGS(const ustring& frame_bytes) {
    auto size = uint32_t(try_bigend_read(frame_bytes, 0, 3));
    auto frame = std::make_unique<h2_settings>();
    set_base_frame_values(*frame, frame_bytes);
    if(frame->flags & h2_flags::ACK and size != 0) {
        throw h2_error("malformed SETTINGS ack frame", h2_code::FRAME_SIZE_ERROR);
    }
    if(size % 6 != 0) {
        throw h2_error("malformed SETTINGS frame", h2_code::FRAME_SIZE_ERROR);
    }
    for(uint32_t i = 0; i < size; i+=6) {
        h2_setting_value setting;
        setting.identifier = static_cast<h2_settings_code>(try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE + i, 2));
        setting.value = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE + 2 + i, 4);
        if(setting.value > INT32_MAX) {
            throw h2_error("value too large", h2_code::PROTOCOL_ERROR);
        }
        frame->settings.push_back(setting);
    }
    return frame;
}

std::unique_ptr<h2_push_promise> deserialise_PUSH_PROMISE(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    auto frame = std::make_unique<h2_push_promise>();
    set_base_frame_values(*frame, frame_bytes);
    size_t idx = 0;
    if(frame->flags & h2_flags::PADDED) {
        frame->pad_length = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE + idx, 1);
        idx += 1;
    }
    frame->promised_stream_id = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE + idx, 4);
    auto begin = frame_bytes.begin() + H2_FRAME_HEADER_SIZE + idx + 4;
    frame->field_block_fragment.assign(begin, begin + size - idx - frame->pad_length);
    return frame;
}

std::unique_ptr<h2_ping> deserialise_PING(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    if(size != 8) {
        throw h2_error("malformed PING frame", h2_code::FRAME_SIZE_ERROR);
    }
    auto frame = std::make_unique<h2_ping>();
    set_base_frame_values(*frame, frame_bytes);
    frame->opaque = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE, 8);
    return frame;
}

std::unique_ptr<h2_goaway> deserialise_GOAWAY(const ustring& frame_bytes) {
    auto frame = std::make_unique<h2_goaway>();
    set_base_frame_values(*frame, frame_bytes);
    const uint32_t lastidres = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE, 4);
    frame->last_stream_id = lastidres & ~(1u << 31);
    frame->error_code = (h2_code)try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE + 4, 4);
    frame->additional_debug_data.assign(frame_bytes.begin() + H2_FRAME_HEADER_SIZE + 8, frame_bytes.end());
    return frame;
}

std::unique_ptr<h2_window_update> deserialise_WINDOW_UPDATE(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    if(size != 4) {
        throw h2_error("malformed WINDOW_UPDATE frame", h2_code::FRAME_SIZE_ERROR);
    }
    auto frame = std::make_unique<h2_window_update>();
    set_base_frame_values(*frame, frame_bytes);
    const uint32_t incres = try_bigend_read(frame_bytes, H2_FRAME_HEADER_SIZE, 4);
    frame->window_size_increment = incres & ~(1u << 31);
    return frame;
}

std::unique_ptr<h2_continuation> deserialise_CONTINUATION(const ustring& frame_bytes) {
    auto frame = std::make_unique<h2_continuation>();
    set_base_frame_values(*frame, frame_bytes);
    frame->field_block_fragment.assign(frame_bytes.begin() + H2_FRAME_HEADER_SIZE, frame_bytes.end());
    return frame;
}

std::string pretty_flags(uint8_t flags, bool can_ack) {
    std::stringstream out;
    if(flags & h2_flags::END_HEADERS) {
        out << " END_HEADERS";
    }
    if(flags & (h2_flags::END_STREAM | h2_flags::ACK)) {
        if(can_ack) {
            out << " ACK";
        } else {
            out << " END_STREAM";
        }
    }
    if(flags & h2_flags::PADDED) {
        out << " PADDED";
    }
    if(flags & h2_flags::PRIORITY) {
        out << " PRIORITY";
    }
    return out.str();
}

ustring h2frame::serialise_common(size_t reserved) const {
    std::cout << "sent:     " << pretty() << std::endl;
    ustring out;
    out.reserve(reserved);
    out.insert(out.end(), {0,0,0});
    out.push_back((uint8_t)type);
    out.push_back(flags);
    out.insert(out.end(), {0,0,0,0});
    checked_bigend_write(stream_id, out, 5, 4);
    return out;
}

ustring h2_data::serialise() const { 
    ustring out = serialise_common();
    if(flags & h2_flags::PADDED) {
        out.push_back(pad_length);
    }
    out.insert(out.end(), contents.begin(), contents.end());
    out.resize(out.size() + pad_length);
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_data::pretty() const {
    std::stringstream out;
    out << "type: DATA,          stream id: " << stream_id << " data size: " << contents.size();
    /*
    out << " data: ";
    uint32_t non_ascii_char_count = 0;
    for(uint8_t c : contents) {
        if((c >= 32 and c <= 126) or c == 10) {
            out << char(c);
        } else {
            non_ascii_char_count++;
            out << '.';
            if(non_ascii_char_count > 10) {
                out << " ... etc. binary data";
                break;
            }
        }
    }
    */
    out << pretty_flags(flags, false);
    return out.str();
}

ustring h2_headers::serialise() const { 
    ustring out = serialise_common();
    if(flags & h2_flags::PADDED) {
        out.push_back(pad_length);
    }
    if(flags & h2_flags::PRIORITY) {
        out.insert(out.end(), {0,0,0,0});
        checked_bigend_write(stream_dependency, out, out.size() - 4, 4);
        out[out.size() - 4] |= (uint8_t(exclusive) << 7);
        out.push_back(weight);
    }
    out.insert(out.end(), field_block_fragment.begin(), field_block_fragment.end());
    out.resize(out.size() + pad_length);
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_headers::pretty() const {
    std::stringstream out;
    out << "type: HEADERS,       stream id: " << stream_id;
    out << " field block fragment size: " << field_block_fragment.size();
    if(exclusive) {
        out << " exclusive";
    }
    out << pretty_flags(flags, false);
    return out.str();
}

ustring h2_priority::serialise() const {
    ustring out = serialise_common(12);
    out.insert(out.end(), {0,0,0,0});
    checked_bigend_write(stream_dependency, out, out.size() - 4, 4);
    out[out.size()-4] |= (uint8_t(exclusive) << 7);
    out.push_back(weight);
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_priority::pretty() const {
    std::stringstream out;
    out << "type: PRIORITY" << pretty_flags(flags, false);
    if(exclusive) {
        out << " exclusive";
    }
    return out.str();
}

ustring h2_rst_stream::serialise() const {
    ustring out = serialise_common();
    out.insert(out.end(), {0,0,0,0});
    checked_bigend_write(uint32_t(error_code), out, out.size() - 4, 4);
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_rst_stream::pretty() const {
    std::stringstream out;
    out << "type: RST_STREAM,           id: " << stream_id << " " << "error code: " << std::hex << unsigned(error_code) << pretty_flags(flags, false);
    return out.str();
}

ustring h2_settings::serialise() const {
    ustring out = serialise_common(9 + settings.size() * 6);
    for(auto setting : settings) {
        out.insert(out.end(), {0,0,0,0,0,0});
        checked_bigend_write(uint32_t(setting.identifier), out, out.size() - 6, 2);
        checked_bigend_write(uint32_t(setting.value), out, out.size() - 4, 4);
    }
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_settings::pretty() const {
    std::stringstream out;
    out << "type: SETTINGS,      stream id: " << stream_id;
    if(!settings.empty()) {
        out << " settings:";
    }
    for(auto setting : settings) {
        out << " id: " << unsigned(setting.identifier) << " v: " << unsigned(setting.value) << ",";
    }
    out << pretty_flags(flags, true);
    return out.str();
}

ustring h2_push_promise::serialise() const { 
    ustring out = serialise_common();
    if(flags & h2_flags::PADDED) {
        out.push_back(pad_length);
    }
    out.insert(out.end(), {0,0,0,0});
    checked_bigend_write(promised_stream_id, out, out.size() - 4, 4);
    out.insert(out.end(), field_block_fragment.begin(), field_block_fragment.end());
    out.resize(out.size() + pad_length);
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}


std::string h2_push_promise::pretty() const {
    std::stringstream out;
    out << "type: PUSH PROMISE,  stream id: " << stream_id << " " << pretty_flags(flags, false);
    return out.str();
}

ustring h2_ping::serialise() const { 
    ustring out = serialise_common(17);
    out.insert(out.end(), {0,0,0,0,0,0,0,0});
    checked_bigend_write(opaque, out, out.size() - 8, 8);
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_ping::pretty() const {
    std::stringstream out;
    out << "type: PING,          stream id: " << stream_id << " opaque: " << opaque << pretty_flags(flags, true);
    return out.str();
}

ustring h2_goaway::serialise() const { 
    ustring out = serialise_common();
    out.insert(out.end(), {0,0,0,0});
    checked_bigend_write(last_stream_id, out, out.size() - 4, 4);
    out.insert(out.end(), {0,0,0,0});
    checked_bigend_write(uint32_t(error_code), out, out.size() - 4, 4);
    out.insert(out.end(), additional_debug_data.begin(), additional_debug_data.end());
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_goaway::pretty() const {
    std::stringstream out;
    out << "type: GOAWAY,        stream id: " << stream_id << " error code: " << unsigned(error_code);
    out << " last stream id: " << last_stream_id;
    if(!additional_debug_data.empty()) {
        out << " error: " << additional_debug_data;
    }
    out << pretty_flags(flags, false);
    return out.str();
}

ustring h2_window_update::serialise() const { 
    ustring out = serialise_common();
    out.insert(out.end(), {0,0,0,0});
    checked_bigend_write(window_size_increment, out, out.size() - 4, 4);
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_window_update::pretty() const {
    std::stringstream out;
    out << "type: WINDOW UPDATE, stream id: " << stream_id << " increment: " << window_size_increment << pretty_flags(flags, false);
    return out.str();
}

ustring h2_continuation::serialise() const {
    ustring out = serialise_common(13);
    out.insert(out.end(), field_block_fragment.begin(), field_block_fragment.end());
    checked_bigend_write(out.size() - H2_FRAME_HEADER_SIZE, out, 0, 3);
    return out;
}

std::string h2_continuation::pretty() const {
    std::stringstream out;
    out << "type: CONTINUATION, stream id: " << stream_id << " field block fragment:";
    for(unsigned c : field_block_fragment) {
        out << ' ' << std::hex << std::setfill(' ') << std::setw(2) << c;
    }
    out << pretty_flags(flags, false);
    return out.str();
}

void set_base_frame_values(h2frame& frame, const ustring& frame_bytes) {
    frame.type = (h2_type)try_bigend_read(frame_bytes, 3, 1);
    frame.flags = try_bigend_read(frame_bytes, 4, 1);
    const uint32_t idres = try_bigend_read(frame_bytes, 5, 4);
    frame.stream_id  = idres & ~(1u << 31);
}

h2_settings construct_settings_frame(setting_values desired_settings, setting_values current_settings) {
    h2_settings server_settings_frame;
    if(desired_settings.header_table_size != current_settings.header_table_size) {
        server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_HEADER_TABLE_SIZE, desired_settings.header_table_size});
    }
    if(desired_settings.max_concurrent_streams != current_settings.max_concurrent_streams ) {
        server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_MAX_CONCURRENT_STREAMS, desired_settings.max_concurrent_streams });
    }
    if(desired_settings.initial_window_size != current_settings.initial_window_size) {
        server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_INITIAL_WINDOW_SIZE, desired_settings.initial_window_size});
    }
    if(desired_settings.max_frame_size != current_settings.max_frame_size) {
        server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_MAX_FRAME_SIZE, desired_settings.max_frame_size});
    }
    if(desired_settings.max_header_size != current_settings.max_header_size) {
        server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_MAX_HEADER_LIST_SIZE, desired_settings.max_header_size});
    }
    if(desired_settings.push_promise_enabled != current_settings.push_promise_enabled) {
        server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_ENABLE_PUSH, desired_settings.push_promise_enabled});
    }
    if(desired_settings.no_rfc7540_priorities != current_settings.no_rfc7540_priorities) {
        server_settings_frame.settings.push_back({h2_settings_code::SETTINGS_ENABLE_PUSH, desired_settings.no_rfc7540_priorities});
    }
    return server_settings_frame;
}

}