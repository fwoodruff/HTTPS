//
//  hpack.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 3/11/2024.
//

#include "hpack.hpp"
#include "h2frame.hpp"
#include "h2proto.hpp"

#include "../common/string_utils.hpp"

namespace fbw {

extern const std::unordered_map<hpack_huffman_bit_pattern, uint8_t> huffman_decode;

uint32_t decode_integer(const std::vector<uint8_t>& encoded, size_t& offset, uint8_t prefix_bits);
std::vector<uint8_t> encode_integer(uint32_t value, uint8_t prefix_bits);

std::string decode_huffman(std::span<const uint8_t> encoded_str);
std::vector<uint8_t> encode_string_literal(std::string str);
std::vector<uint8_t> encode_string_efficient(std::string str);

std::vector<uint8_t> indexed_field(uint32_t idx);
std::vector<uint8_t> indexed_name_new_value(uint32_t idx, std::string value);
std::vector<uint8_t> new_name_new_value(std::string name, std::string value);
std::vector<uint8_t> indexed_name_new_value_without_dynamic(uint32_t idx, std::string value);
std::vector<uint8_t> new_name_new_value_without_dynamic(std::string name, std::string value);
std::vector<uint8_t> indexed_name_new_value_never_dynamic(uint32_t idx, std::string value);
std::vector<uint8_t> new_name_new_value_never_dynamic(std::string name, std::string value);
std::vector<uint8_t> dynamic_table_size_update(size_t size);

constexpr std::array<hpack_huffman_bit_pattern, 256> huffman_table = {
    hpack_huffman_bit_pattern{0x1ff8, 13},  {0x7fffd8, 23}, {0xfffffe2, 28}, {0xfffffe3, 28},
    {0xfffffe4, 28}, {0xfffffe5, 28}, {0xfffffe6, 28}, {0xfffffe7, 28},
    {0xfffffe8, 28}, {0xffffea, 24}, {0x3ffffffc, 30}, {0xfffffe9, 28},
    {0xfffffea, 28}, {0x3ffffffd, 30}, {0xfffffeb, 28}, {0xfffffec, 28},
    {0xfffffed, 28}, {0xfffffee, 28}, {0xfffffef, 28}, {0xffffff0, 28},
    {0xffffff1, 28}, {0xffffff2, 28}, {0x3ffffffe, 30}, {0xffffff3, 28},
    {0xffffff4, 28}, {0xffffff5, 28}, {0xffffff6, 28}, {0xffffff7, 28},
    {0xffffff8, 28}, {0xffffff9, 28}, {0xffffffa, 28}, {0xffffffb, 28},
    {0x14, 6},      {0x3f8, 10},    {0x3f9, 10},    {0xffa, 12},
    {0x1ff9, 13},   {0x15, 6},      {0xf8, 8},      {0x7fa, 11},
    {0x3fa, 10},    {0x3fb, 10},    {0xf9, 8},      {0x7fb, 11},
    {0xfa, 8},      {0x16, 6},      {0x17, 6},      {0x18, 6},
    {0x0, 5},       {0x1, 5},       {0x2, 5},       {0x19, 6},
    {0x1a, 6},      {0x1b, 6},      {0x1c, 6},      {0x1d, 6},
    {0x1e, 6},      {0x1f, 6},      {0x5c, 7},      {0xfb, 8},
    {0x7ffc, 15},   {0x20, 6},      {0xffb, 12},    {0x3fc, 10},
    {0x1ffa, 13},   {0x21, 6},      {0x5d, 7},      {0x5e, 7},
    {0x5f, 7},      {0x60, 7},      {0x61, 7},      {0x62, 7},
    {0x63, 7},      {0x64, 7},      {0x65, 7},      {0x66, 7},
    {0x67, 7},      {0x68, 7},      {0x69, 7},      {0x6a, 7},
    {0x6b, 7},      {0x6c, 7},      {0x6d, 7},      {0x6e, 7},
    {0x6f, 7},      {0x70, 7},      {0x71, 7},      {0x72, 7},
    {0xfc, 8},      {0x73, 7},      {0xfd, 8},      {0x1ffb, 13},
    {0x7fff0, 19},  {0x1ffc, 13},   {0x3ffc, 14},   {0x22, 6},
    {0x7ffd, 15},   {0x3, 5},       {0x23, 6},      {0x4, 5},
    {0x24, 6},      {0x5, 5},       {0x25, 6},      {0x26, 6},
    {0x27, 6},      {0x6, 5},       {0x74, 7},      {0x75, 7},
    {0x28, 6},      {0x29, 6},      {0x2a, 6},      {0x7, 5},
    {0x2b, 6},      {0x76, 7},      {0x2c, 6},      {0x8, 5},
    {0x9, 5},       {0x2d, 6},      {0x77, 7},      {0x78, 7},
    {0x79, 7},      {0x7a, 7},      {0x7b, 7},      {0x7ffe, 15},
    {0x7fc, 11},    {0x3ffd, 14},   {0x1ffd, 13},   {0xffffffc, 28},
    {0xfffe6, 20},  {0x3fffd2, 22}, {0xfffe7, 20},  {0xfffe8, 20},
    {0x3fffd3, 22}, {0x3fffd4, 22}, {0x3fffd5, 22}, {0x7fffd9, 23},
    {0x3fffd6, 22}, {0x7fffda, 23}, {0x7fffdb, 23}, {0x7fffdc, 23},
    {0x7fffdd, 23}, {0x7fffde, 23}, {0xffffeb, 24}, {0x7fffdf, 23},
    {0xffffec, 24}, {0xffffed, 24}, {0x3fffd7, 22}, {0x7fffe0, 23},
    {0xffffee, 24}, {0x7fffe1, 23}, {0x7fffe2, 23}, {0x7fffe3, 23},
    {0x7fffe4, 23}, {0x1fffdc, 21}, {0x3fffd8, 22}, {0x7fffe5, 23},
    {0x3fffd9, 22}, {0x7fffe6, 23}, {0x7fffe7, 23}, {0xffffef, 24},
    {0x3fffda, 22}, {0x1fffdd, 21}, {0xfffe9, 20},  {0x3fffdb, 22},
    {0x3fffdc, 22}, {0x7fffe8, 23}, {0x7fffe9, 23}, {0x1fffde, 21},
    {0x7fffea, 23}, {0x3fffdd, 22}, {0x3fffde, 22}, {0xfffff0, 24},
    {0x1fffdf, 21}, {0x3fffdf, 22}, {0x7fffeb, 23}, {0x7fffec, 23},
    {0x1fffe0, 21}, {0x1fffe1, 21}, {0x3fffe0, 22}, {0x1fffe2, 21},
    {0x7fffed, 23}, {0x3fffe1, 22}, {0x7fffee, 23}, {0x7fffef, 23},
    {0xfffea, 20},  {0x3fffe2, 22}, {0x3fffe3, 22}, {0x3fffe4, 22},
    {0x7ffff0, 23}, {0x3fffe5, 22}, {0x3fffe6, 22}, {0x7ffff1, 23},
    {0x3ffffe0, 26}, {0x3ffffe1, 26}, {0xfffeb, 20}, {0x7fff1, 19},
    {0x3fffe7, 22}, {0x7ffff2, 23}, {0x3fffe8, 22}, {0x1ffffec, 25},
    {0x3ffffe2, 26}, {0x3ffffe3, 26}, {0x3ffffe4, 26}, {0x7ffffde, 27},
    {0x7ffffdf, 27}, {0x3ffffe5, 26}, {0xfffff1, 24}, {0x1ffffed, 25},
    {0x7fff2, 19},  {0x1fffe3, 21}, {0x3ffffe6, 26}, {0x7ffffe0, 27},
    {0x7ffffe1, 27}, {0x3ffffe7, 26}, {0x7ffffe2, 27}, {0xfffff2, 24},
    {0x1fffe4, 21}, {0x1fffe5, 21}, {0x3ffffe8, 26}, {0x3ffffe9, 26},
    {0xffffffd, 28}, {0x7ffffe3, 27}, {0x7ffffe4, 27}, {0x7ffffe5, 27},
    {0xfffec, 20},  {0xfffff3, 24}, {0xfffed, 20},  {0x1fffe6, 21},
    {0x3fffe9, 22}, {0x1fffe7, 21}, {0x1fffe8, 21}, {0x7ffff3, 23},
    {0x3fffea, 22}, {0x3fffeb, 22}, {0x1ffffee, 25}, {0x1ffffef, 25},
    {0xfffff4, 24}, {0xfffff5, 24}, {0x3ffffea, 26}, {0x7ffff4, 23},
    {0x3ffffeb, 26}, {0x7ffffe6, 27}, {0x3ffffec, 26}, {0x3ffffed, 26},
    {0x7ffffe7, 27}, {0x7ffffe8, 27}, {0x7ffffe9, 27}, {0x7ffffea, 27},
    {0x7ffffeb, 27}, {0xffffffe, 28}, {0x7ffffec, 27}, {0x7ffffed, 27},
    {0x7ffffee, 27}, {0x7ffffef, 27}, {0x7fffff0, 27}, {0x3ffffee, 26} // , {3fffffff, 30} implicit
};

std::vector<uint8_t> hpack::generate_field_block(const std::vector<entry_t>& headers) {
    std::vector<uint8_t> encoded_block;

    if(encoder_max_capacity != m_encode_table.m_capacity) {
        auto update = dynamic_table_size_update(encoder_max_capacity);
        encoded_block.insert(encoded_block.end(), update.begin(), update.end());
        m_encode_table.set_capacity(encoder_max_capacity);
    }
    for (auto header : headers) {
        header.name = to_lower(header.name);
        auto index = m_encode_table.index(header);
        if (index != 0) {
            auto field = indexed_field(index);
            encoded_block.insert(encoded_block.end(), field.begin(), field.end());
        } else {
            auto name_index = m_encode_table.name_index(header.name);
            if (name_index != 0) {
                if(header.do_index == do_indexing::never) {
                    auto field = indexed_name_new_value_never_dynamic(name_index, header.value);
                    encoded_block.insert(encoded_block.end(), field.begin(), field.end());
                } else if (header.do_index == do_indexing::without) {
                    auto field = indexed_name_new_value_without_dynamic(name_index, header.value);
                    encoded_block.insert(encoded_block.end(), field.begin(), field.end());
                } else {
                    auto field = indexed_name_new_value(name_index, header.value);
                    encoded_block.insert(encoded_block.end(), field.begin(), field.end());
                    m_encode_table.add_entry(header.name, header.value);
                }
            } else {
                if(header.do_index == do_indexing::never) {
                    auto field = new_name_new_value_never_dynamic(header.name, header.value);
                    encoded_block.insert(encoded_block.end(), field.begin(), field.end());
                } else if (header.do_index == do_indexing::without) {
                    auto field = new_name_new_value_without_dynamic(header.name, header.value);
                    encoded_block.insert(encoded_block.end(), field.begin(), field.end());
                } else {
                    auto field = new_name_new_value(header.name, header.value);
                    encoded_block.insert(encoded_block.end(), field.begin(), field.end());
                    m_encode_table.add_entry(header.name, header.value);
                }
            }
        }
    }
    return encoded_block;
}

table::table() : next_idx(first_dynamic_idx) {}

size_t table::index(entry_t entry) {
    for(size_t i = 0; i < s_static_table.size(); i++) {
        auto& ent = s_static_table[i];
        if(ent.name == entry.name and ent.value == entry.value) {
            return i + 1;
        }
    }
    for(size_t i = 0; i < entries_ordered.size(); i++) { // todo: optimise
        auto& ent = entries_ordered[i];
        if(ent.name == entry.name and ent.value == entry.value) {
            return i + first_dynamic_idx;
        }
    }
    return 0;
}

size_t table::name_index(const std::string& name) {
    for(size_t i = 0; i < s_static_table.size(); i++) {
        auto& ent = s_static_table[i];
        if(ent.name == name) {
            return i + 1;
        }
    }
    for(size_t i = 0; i < entries_ordered.size(); i++) { // todo: optimise
        if(entries_ordered[i].name == name) {
            return i + first_dynamic_idx;
        }
    }
    return 0;
}

std::string table::field_name(size_t key) {
    assert(key != 0);
    if(key <= s_static_table.size()) {
        return s_static_table[ key - 1 ].name;
    }
    if(key - first_dynamic_idx >= entries_ordered.size()) {
        throw h2_error("decoding indexed name but index not found", h2_code::COMPRESSION_ERROR);
    }
    return entries_ordered[key - first_dynamic_idx].name;
}

std::string table::field_value(size_t key) {
    assert(key != 0);
    if(key <= s_static_table.size()) {
        return s_static_table[ key - 1 ].value;
    }
    if(key - first_dynamic_idx >= entries_ordered.size()) {
        throw h2_error("decoding indexed value but index not found", h2_code::COMPRESSION_ERROR);
    }
    return entries_ordered[key - first_dynamic_idx].value;
}

constexpr size_t entry_overhead = 32;

void table::pop_entry() {
    auto old_entry = entries_ordered.back();
    const auto old_size = old_entry.name.size() + old_entry.value.size() + entry_overhead;
    m_size -= old_size;
    entries_ordered.pop_back();
}

void table::add_entry(const std::string& name, const std::string& value) {
    auto size = name.size() + value.size() + entry_overhead;
    m_size += size;
    entries_ordered.push_front({name, value});
    while(m_size > m_capacity and !entries_ordered.empty()) {
        pop_entry();
    }
    next_idx++;
}

void table::set_capacity(size_t capacity) {
    m_capacity = capacity;
    while(m_size > m_capacity and !entries_ordered.empty()) {
        pop_entry();
    }
}

void hpack::set_encoder_max_capacity(uint32_t capacity) {
    encoder_max_capacity = capacity;
}

void hpack::set_decoder_max_capacity(uint32_t capacity) {
    decoder_max_capacity = capacity;
}

std::string decode_string(const std::vector<uint8_t>& encoded, size_t& offset) {
    bool is_huffman = (encoded[offset] & 0x80) != 0;
    uint32_t size = decode_integer(encoded, offset, 7);
    if(is_huffman) {
        if(offset + size > encoded.size()) {
            throw h2_error("bad Huffman decode", h2_code::COMPRESSION_ERROR);
        }
        auto ret = decode_huffman({encoded.begin() + offset, size});
        offset += size;
        return ret;
    } else {
        std::string out;
        if(offset + size > encoded.size()) {
            throw h2_error("bad Huffman decode", h2_code::COMPRESSION_ERROR);
        }
        out.append(encoded.begin() + offset, encoded.begin() + offset + size);
        offset += size;
        return out;
    }
}

std::string decode_huffman(std::span<const uint8_t> encoded_str) {
    std::string result;
    uint32_t current_bits = 0;
    uint8_t bit_size = 0;
    for (uint8_t byte : encoded_str) {
        for (int bit = 7; bit >= 0; --bit) {
            current_bits <<= 1;
            current_bits |= ((byte >> bit) & 1);
            bit_size++;
            if(auto it = huffman_decode.find(hpack_huffman_bit_pattern{current_bits, bit_size}); it != huffman_decode.end()) {
                result.push_back(char(it->second));
                current_bits = 0;
                bit_size = 0;
            }
            if(bit_size > 32) {
                throw h2_error("bad Huffman encoding", h2_code::COMPRESSION_ERROR);
            }
        }
    }
    return result;
}

std::vector<entry_t> hpack::parse_field_block(const std::vector<uint8_t>& field_block_fragment) {
    size_t offset = 0;
    std::vector<entry_t> entries;
    while(offset < field_block_fragment.size()) {
        auto entry = decode_hpack_string(field_block_fragment, offset);
        if(!entry) {
            continue;
        }
        entries.push_back(std::move(*entry));
    }
    if(offset != field_block_fragment.size()) {
        throw h2_error("extra data in field block fragment", h2_code::COMPRESSION_ERROR);
    }
    return entries;
}

std::vector<uint8_t> encode_huffman(std::string str_literal) {
    std::vector<uint8_t> out;
    uint8_t bit_idx = 0;
    uint8_t current_byte = 0;

    for (uint8_t ch : str_literal) {
        auto [bit_pattern, num_bits] = huffman_table[ch];
        while (num_bits > 0) {
            uint8_t available_bits = 8 - bit_idx;
            uint8_t bits_to_write = std::min(num_bits, available_bits);
            uint8_t shift = num_bits - bits_to_write;
            uint8_t bits = (bit_pattern >> shift) & ((1 << bits_to_write) - 1);
            current_byte |= bits << (available_bits - bits_to_write);
            bit_idx += bits_to_write;
            num_bits -= bits_to_write;

            if (bit_idx == 8) {
                out.push_back(current_byte);
                current_byte = 0;
                bit_idx = 0;
            }
        }
    }

    if (bit_idx > 0) { // EOS
        //current_byte |=  (0xff >> bit_idx);
        current_byte |= ((1 << (8 - bit_idx)) - 1);
        out.push_back(current_byte);
    }

    return out;
}

std::vector<uint8_t> encode_integer(uint32_t value, uint8_t prefix_bits) {
    assert(prefix_bits <= 8);
    std::vector<uint8_t> encoded;
    uint64_t prefix = (1 << prefix_bits) - 1;
    if(value < prefix) {
        encoded.push_back(value);
        return encoded;
    }
    encoded.push_back(static_cast<uint8_t>(prefix));
    uint64_t remainder = static_cast<uint64_t>(value) - prefix;
    do {
        uint8_t byte = remainder & 0x7F;
        remainder >>= 7;
        if (remainder != 0) {
            byte |= 0x80;
        }
        encoded.push_back(byte);
    } while (remainder != 0);
    return encoded;
}

uint32_t decode_integer(const std::vector<uint8_t>& encoded, size_t& offset, uint8_t prefix_bits) {
    uint32_t prefix = (1 << prefix_bits) - 1;
    if(offset >= encoded.size()) {
        throw h2_error("bounds check", h2_code::COMPRESSION_ERROR);
    }
    const uint32_t value_pre = encoded[offset] & prefix;
    if(value_pre != prefix) {
        offset++;
        return value_pre;
    }
    uint64_t value = 0;

    for(size_t i = 1; i < 7; i++) {
        if(offset + i >= encoded.size()) [[unlikely]] { 
            throw h2_error("integer encoding incomplete", h2_code::COMPRESSION_ERROR);
        }
        uint8_t byte = encoded[offset + i];

        const uint64_t seven_bits = (byte & 0x7F);
        value += (seven_bits << (7*(i-1)));

        if (value > ((1ull << 31) - prefix)) [[unlikely]] {
            throw h2_error("encoded integer is too large", h2_code::COMPRESSION_ERROR);
        }
        if ((byte & 0x80) == 0) {
            value += prefix;
            offset += (i + 1);
            return value;
        }
    }
    throw h2_error("integer encoding incomplete", h2_code::COMPRESSION_ERROR);
}

std::vector<uint8_t> encode_string_literal(std::string str) {
    auto lit = encode_integer(str.size(), 7);
    lit.insert(lit.end(), str.begin(), str.end());
    return lit;
}

std::vector<uint8_t> encode_string_efficient(std::string str) {
    std::vector<uint8_t> hstr = encode_huffman(str);
    if(hstr.size() < str.size()) {
        auto lit = encode_integer(hstr.size(), 7);
        lit[0] |= 0x80;
        lit.insert(lit.end(), hstr.begin(), hstr.end());
        return lit;
    } else {
        auto lit = encode_integer(str.size(), 7);
        lit.insert(lit.end(), str.begin(), str.end());
        return lit;
    }
}

std::vector<uint8_t> indexed_field(uint32_t idx) {
    std::vector<uint8_t> rep = encode_integer(idx, 7);
    rep[0] |= 0x80;
    return rep;
}

std::vector<uint8_t> indexed_name_new_value(uint32_t idx, std::string value) {
    std::vector<uint8_t> rep = encode_integer(idx, 6);
    rep[0] |= 0x40;
    const auto string_encoded = encode_string_efficient(value);
    rep.insert(rep.end(), string_encoded.begin(), string_encoded.end());
    return rep;
}

std::vector<uint8_t> new_name_new_value(std::string name, std::string value) {
    std::vector<uint8_t> rep {0x40};
    const auto name_encoded = encode_string_efficient(name);
    const auto value_encoded = encode_string_efficient(value);
    rep.insert(rep.end(), name_encoded.begin(), name_encoded.end());
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    return rep;
}

std::vector<uint8_t> indexed_name_new_value_without_dynamic(uint32_t idx, std::string value) {
    std::vector<uint8_t> rep = encode_integer(idx, 4);
    const auto value_encoded = encode_string_efficient(value);
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    return rep;
}

std::vector<uint8_t> new_name_new_value_without_dynamic(std::string name, std::string value) {
    std::vector<uint8_t> rep {0};
    const auto name_encoded = encode_string_efficient(name);
    const auto value_encoded = encode_string_efficient(value);
    rep.insert(rep.end(), name_encoded.begin(), name_encoded.end());
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    return rep;
}

std::vector<uint8_t> indexed_name_new_value_never_dynamic(uint32_t idx, std::string value) {
    std::vector<uint8_t> rep = encode_integer(idx, 4);
    const auto value_encoded = encode_string_literal(value);
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    rep[0] |= 0x10;
    return rep;
}

std::vector<uint8_t> new_name_new_value_never_dynamic(std::string name, std::string value) {
    std::vector<uint8_t> rep {0x10};
    const auto name_encoded = encode_string_literal(name);
    const auto value_encoded = encode_string_literal(value);
    rep.insert(rep.end(), name_encoded.begin(), name_encoded.end());
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    return rep;
}

std::vector<uint8_t> dynamic_table_size_update(size_t size) {
    std::vector<uint8_t> rep = encode_integer(size, 5);
    rep[0] |= 0x20;
    return rep;
}

std::pair<hpack::prefix_type, uint32_t> hpack::decode_prefix(const std::vector<uint8_t>& encoded, size_t& offset) {
    assert(offset < encoded.size());
    uint8_t byte = encoded[offset];
    int prefix_bytes = 0;
    prefix_type type;
    using enum prefix_type;
    if(byte & 0x80) {
        prefix_bytes = 7;
        type = indexed_header;
    } else if(byte & 0x40) {
        prefix_bytes = 6;
        type = literal_header_incremental_indexing;
    } else if(byte & 0x20) {
        prefix_bytes = 5;
        type = table_size_update;
    } else if(byte & 0x10) {
        prefix_bytes = 4;
        type = literal_header_never_indexing;
    } else {
        prefix_bytes = 4;
        type = literal_header_without_indexing;
    }
    auto idx = decode_integer(encoded, offset, prefix_bytes);
    return {type, idx};
}

std::optional<entry_t> hpack::decode_hpack_string(const std::vector<uint8_t>& encoded, size_t& offset) {
    assert(offset < encoded.size());
    auto [type, idx] = decode_prefix(encoded, offset);
    using enum prefix_type;

    auto decode_name = [this, &encoded, &offset](uint32_t index) -> std::string {
        if (index == 0) {
            return decode_string(encoded, offset);
        }
        return m_decode_table.field_name(index);
    };

    switch(type) {
        case indexed_header: {
            auto name = m_decode_table.field_name(idx);
            auto value = m_decode_table.field_value(idx);
            return {{name, value, do_indexing::incremental}};
        }
        case literal_header_incremental_indexing: {
            auto name = decode_name(idx);
            auto value = decode_string(encoded, offset);
            m_decode_table.add_entry(name, value);
            return {{name, value, do_indexing::incremental}};
        }
        case literal_header_never_indexing: {
            auto name = decode_name(idx);
            auto value = decode_string(encoded, offset);
            return {{name, value, do_indexing::never}};
        }
        case literal_header_without_indexing: {
            auto name = decode_name(idx);
            auto value = decode_string(encoded, offset);
            return {{name, value, do_indexing::without}};
        }
        case table_size_update:
            if(idx > decoder_max_capacity) {
                throw h2_error("could not update decoder", h2_code::COMPRESSION_ERROR);
            }
            m_decode_table.set_capacity(idx);
            return std::nullopt;
        default:
            return std::nullopt;
    }
}

const std::array<entry_t, static_entries> table::s_static_table = {
    entry_t{":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", ""},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""}
};

const std::unordered_map<hpack_huffman_bit_pattern, uint8_t> huffman_decode = [](){
    std::unordered_map<hpack_huffman_bit_pattern, uint8_t> out;
    for(size_t i = 0; i < huffman_table.size(); i++) {
        out.insert({huffman_table[i], i});
    }
    return out;
}();

}
