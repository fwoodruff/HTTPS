
#include "h2frame.hpp"
#include "../global.hpp"


namespace fbw {

using enum h2_code;

std::unique_ptr<h2frame> h2frame::deserialise(ustring frame) {
    assert(frame.size() > 9);
    //h2_type type = (h2_type)frame[3];

    return {};
}

ustring h2_data::serialise() const { 
    ustring out;
    out.append({0,0,0});
    out.push_back((uint8_t)type);
    out.push_back(flags);
    out.append({0,0,0,0});
    checked_bigend_write(stream_id, out, 5, 4);
    if(flags & h2_flags::padded) {
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
    if(flags & h2_flags::padded) {
        out.push_back(pad_length);
    }
    out.append({0,0,0,0});
    checked_bigend_write(stream_dependency, out, out.size()-4, 4);
    out[out.size()-4] |= (uint8_t(exclusive) << 7);
    out.push_back(weight);
    out.append(field_block_fragment.begin(), field_block_fragment.end());
    out.resize(out.size() + pad_length);
    checked_bigend_write(out.size() - 9, out, 0, 3);
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
    if(flags & h2_flags::padded) {
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
    out.append(additional_debug_data);
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

}