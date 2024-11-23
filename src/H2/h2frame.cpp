
#include "h2frame.hpp"
#include "../global.hpp"


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

std::unique_ptr<h2frame> h2frame::deserialise(const ustring& frame_bytes) { // todo, span
    assert(frame_bytes.size() >= H2_IDX_0);
    auto type = static_cast<h2_type>(frame_bytes[3]);
    try {
        auto size = try_bigend_read(frame_bytes, 0, 3);
        assert(size == frame_bytes.size() - H2_IDX_0);
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
        return nullptr;
    } catch(const std::out_of_range& e) {
        throw h2_error("malformed frame", h2_code::FRAME_SIZE_ERROR);
    }
}

std::unique_ptr<h2_data> deserialise_DATA(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    auto frame = std::make_unique<h2_data>();
    set_base_frame_values(*frame, frame_bytes);
    if(frame->flags % h2_flags::PADDED) {
        frame->pad_length = try_bigend_read(frame_bytes, H2_IDX_0, 1);
        frame->contents = frame_bytes.substr(H2_IDX_0+1, size-1 - frame->pad_length);
    } else {
        frame->pad_length = 0;
        frame->contents = frame_bytes.substr(H2_IDX_0);
    }
    return frame;
}

std::unique_ptr<h2_headers> deserialise_HEADERS(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    assert(size + H2_IDX_0 == frame_bytes.size());
    auto frame = std::make_unique<h2_headers>();
    set_base_frame_values(*frame, frame_bytes);
    size_t idx = 0;
    if(frame->flags & h2_flags::PADDED) {
        frame->pad_length = try_bigend_read(frame_bytes, H2_IDX_0, 1);
        idx += 1;
    } else {
        frame->pad_length = 0;
    }
    if(frame->flags & h2_flags::PRIORITY) {
        const uint32_t dep_ex = try_bigend_read(frame_bytes, H2_IDX_0 + idx, 4);
        frame->stream_dependency = dep_ex & ~(1u << 31);
        frame->exclusive = (dep_ex & (1u << 31)) != 0;
        frame->weight = try_bigend_read(frame_bytes, H2_IDX_0 + idx + 4, 1);
        idx += 5;
    }
    frame->field_block_fragment = frame_bytes.substr(H2_IDX_0 + idx, size - idx - frame->pad_length);
    assert(frame->field_block_fragment.size() + idx + frame->pad_length == size);
    return frame;
}

std::unique_ptr<h2_priority> deserialise_PRIORITY(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    auto frame = std::make_unique<h2_priority>();
    set_base_frame_values(*frame, frame_bytes);
    const uint32_t dep_ex = try_bigend_read(frame_bytes, H2_IDX_0, 4);
    frame->stream_dependency = dep_ex & ~(1u << 31);
    frame->exclusive = (dep_ex & (1u << 31)) != 0;
    frame->weight = try_bigend_read(frame_bytes, H2_IDX_0 + 4, 1);
    if(size != 5) {
        throw h2_error("malformed PRIORITY frame", h2_code::FRAME_SIZE_ERROR);
    }
    return frame;
}

std::unique_ptr<h2_rst_stream> deserialise_RST_STREAM(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    auto frame = std::make_unique<h2_rst_stream>();
    set_base_frame_values(*frame, frame_bytes);
    frame->error_code = (h2_code)try_bigend_read(frame_bytes, H2_IDX_0, 4);
    if(size != 4) {
        throw h2_error("malformed RST_STREAM frame", h2_code::FRAME_SIZE_ERROR);
    }
    return frame;
}

std::unique_ptr<h2_settings> deserialise_SETTINGS(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    auto frame = std::make_unique<h2_settings>();
    set_base_frame_values(*frame, frame_bytes);
    if(frame->flags & h2_flags::ACK and size != 0) {
        throw h2_error("malformed SETTINGS ack frame", h2_code::FRAME_SIZE_ERROR);
    }
    if(size % 6 != 0) {
        throw h2_error("malformed SETTINGS frame", h2_code::FRAME_SIZE_ERROR);
    }
    for(uint64_t i = 0; i < size; i+=6) {
        h2_setting setting;
        setting.identifier = static_cast<h2_settings_code>(try_bigend_read(frame_bytes, H2_IDX_0 + i, 2));
        setting.value = try_bigend_read(frame_bytes, H2_IDX_0 + 2 + i, 4);
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
        frame->pad_length = try_bigend_read(frame_bytes, H2_IDX_0 + idx, 1);
        idx += 1;
    }
    frame->promised_stream_id = try_bigend_read(frame_bytes, idx, 4);
    frame->field_block_fragment = frame_bytes.substr(H2_IDX_0 + idx + 4, size - idx - frame->pad_length);
    return frame;
}

std::unique_ptr<h2_ping> deserialise_PING(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    if(size != 8) {
        throw h2_error("malformed PRIORITY frame", h2_code::FRAME_SIZE_ERROR);
    }
    auto frame = std::make_unique<h2_ping>();
    set_base_frame_values(*frame, frame_bytes);
    frame->opaque = try_bigend_read(frame_bytes, H2_IDX_0, 8);
    return frame;
}

std::unique_ptr<h2_goaway> deserialise_GOAWAY(const ustring& frame_bytes) {
    auto frame = std::make_unique<h2_goaway>();
    set_base_frame_values(*frame, frame_bytes);
    const uint32_t lastidres = try_bigend_read(frame_bytes, H2_IDX_0, 4);
    frame->last_stream_id = lastidres & ~(1u << 31);
    frame->error_code = (h2_code)try_bigend_read(frame_bytes, H2_IDX_0 + 4, 4);
    frame->additional_debug_data = to_signed(frame_bytes.substr(H2_IDX_0 + 8));
    return frame;
}

std::unique_ptr<h2_window_update> deserialise_WINDOW_UPDATE(const ustring& frame_bytes) {
    auto size = try_bigend_read(frame_bytes, 0, 3);
    if(size != 4) {
        throw h2_error("malformed WINDOW_UPDATE frame", h2_code::FRAME_SIZE_ERROR);
    }
    auto frame = std::make_unique<h2_window_update>();
    set_base_frame_values(*frame, frame_bytes);
    const uint32_t incres = try_bigend_read(frame_bytes, H2_IDX_0, 4);
    frame->window_size_increment = incres & ~(1u << 31);
    return frame;
}

std::unique_ptr<h2_continuation> deserialise_CONTINUATION(const ustring& frame_bytes) {
    auto frame = std::make_unique<h2_continuation>();
    set_base_frame_values(*frame, frame_bytes);
    frame->field_block_fragment = frame_bytes.substr(H2_IDX_0);
    return frame;
}

ustring h2_data::serialise() const { 
    ustring out;
    out.append({0,0,0});
    out.push_back((uint8_t)type);
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, 5, 4);
    if(flags & h2_flags::PADDED) {
        out.push_back(pad_length);
    }
    out.append(contents);
    out.resize(out.size() + pad_length);
    checked_bigend_write(out.size() - 9, out, 0, 3);
    return out;
}

ustring h2_headers::serialise() const { 
    ustring out;
    out.append({0,0,0});
    out.push_back((uint8_t)type);
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, 5, 4);
    if(flags & h2_flags::PADDED) {
        out.push_back(pad_length);
    }
    if(flags & h2_flags::PRIORITY) {
        out.append({0,0,0,0});
        checked_bigend_write(stream_dependency, out, out.size() - 4, 4);
        out[out.size() - 4] |= (uint8_t(exclusive) << 7);
        out.push_back(weight);
    }
    out.append(field_block_fragment.begin(), field_block_fragment.end());
    out.resize(out.size() + pad_length);
    checked_bigend_write(out.size() - H2_IDX_0, out, 0, 3);
    return out;
}

ustring h2_priority::serialise() const {
    ustring out;
    out.reserve(12);
    out.append({0,0,5});
    out.push_back((uint8_t)type);
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, out.size() - 4, 4);
    out.append({0,0,0,0});
    checked_bigend_write(stream_dependency, out, out.size() - 4, 4);
    out[out.size()-4] |= (uint8_t(exclusive) << 7);
    out.push_back(weight);
    return out;
}

ustring h2_rst_stream::serialise() const {
    ustring out;
    out.reserve(11);
    out.append({0,0,4});
    out.push_back((uint8_t)type);
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, out.size() - 4, 4);
    out.append({0,0,0,0});
    checked_bigend_write(uint32_t(error_code), out, out.size() - 4, 4);
    return out;
}

ustring h2_settings::serialise() const {
    ustring out;
    out.reserve(9 + settings.size()*6);
    out.append({0,0,0});
    out.push_back((uint8_t)type);
    out.push_back(flags);
    out.append({0,0,0,0});
    for(auto setting : settings) {
        out.append({0,0,0,0,0,0});
        checked_bigend_write(uint32_t(setting.identifier), out, out.size() - 6, 2);
        checked_bigend_write(uint32_t(setting.value), out, out.size() - 4, 4);
    }
    checked_bigend_write(out.size() - 9, out, 0, 3);
    return out;
}

ustring h2_push_promise::serialise() const { 
    ustring out;
    out.append({0,0,0});
    out.push_back(uint8_t(type));
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, out.size() - 4, 4);
    if(flags & h2_flags::PADDED) {
        out.push_back(pad_length);
    }
    out.append({0,0,0,0});
    checked_bigend_write(promised_stream_id, out, out.size() - 4, 4);
    out.append(field_block_fragment);
    out.resize(out.size() + pad_length);
    checked_bigend_write(out.size() - 9, out, 0, 3);
    return out;
}

ustring h2_ping::serialise() const { 
    ustring out;
    out.reserve(17);
    out.append({0,0,8});
    out.push_back(uint8_t(type));
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, out.size() - 4, 4);
    out.append({0,0,0,0,0,0,0,0});
    checked_bigend_write(opaque, out, out.size() - 8, 8);
    return out;
}

ustring h2_goaway::serialise() const { 
    ustring out;
    out.append({0,0,0});
    out.push_back(uint8_t(type));
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, out.size() - 4, 4);
    out.append({0,0,0,0});
    checked_bigend_write(last_stream_id, out, out.size() - 4, 4);
    out.append({0,0,0,0});
    checked_bigend_write(uint32_t(error_code), out, out.size() - 4, 4);
    out.append(to_unsigned(additional_debug_data));
    checked_bigend_write(out.size() - 9, out, 0, 3);
    return out;
}

ustring h2_window_update::serialise() const { 
    ustring out;
    out.reserve(13);
    out.append({0,0,4});
    out.push_back(uint8_t(type));
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, out.size() - 4, 4);
    out.append({0,0,0,0});
    checked_bigend_write(window_size_increment, out, out.size() - 4, 4);
    return {};
}

ustring h2_continuation::serialise() const {
    ustring out;
    out.append({0,0,0});
    out.push_back((uint8_t)type);
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, out.size() - 4, 4);
    out.append(field_block_fragment.begin(), field_block_fragment.end());
    checked_bigend_write(out.size() - 9, out, 0, 3);
    return out;
}

void set_base_frame_values(h2frame& frame, const ustring& frame_bytes) {
    frame.type = (h2_type)try_bigend_read(frame_bytes, 3, 1);
    frame.flags = try_bigend_read(frame_bytes, 4, 1);
    const uint32_t idres = try_bigend_read(frame_bytes, 5, 4);
    frame.stream_id  = idres & ~(1u << 31);
}

}