//
//  hpack.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 3/11/2024.
//

#include "hpack.hpp"

#include <utility>
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
    hpack_huffman_bit_pattern{.bits=0x1ff8, .bit_length=13},  {.bits=0x7fffd8, .bit_length=23}, {.bits=0xfffffe2, .bit_length=28}, {.bits=0xfffffe3, .bit_length=28},
    {.bits=0xfffffe4, .bit_length=28}, {.bits=0xfffffe5, .bit_length=28}, {.bits=0xfffffe6, .bit_length=28}, {.bits=0xfffffe7, .bit_length=28},
    {.bits=0xfffffe8, .bit_length=28}, {.bits=0xffffea, .bit_length=24}, {.bits=0x3ffffffc, .bit_length=30}, {.bits=0xfffffe9, .bit_length=28},
    {.bits=0xfffffea, .bit_length=28}, {.bits=0x3ffffffd, .bit_length=30}, {.bits=0xfffffeb, .bit_length=28}, {.bits=0xfffffec, .bit_length=28},
    {.bits=0xfffffed, .bit_length=28}, {.bits=0xfffffee, .bit_length=28}, {.bits=0xfffffef, .bit_length=28}, {.bits=0xffffff0, .bit_length=28},
    {.bits=0xffffff1, .bit_length=28}, {.bits=0xffffff2, .bit_length=28}, {.bits=0x3ffffffe, .bit_length=30}, {.bits=0xffffff3, .bit_length=28},
    {.bits=0xffffff4, .bit_length=28}, {.bits=0xffffff5, .bit_length=28}, {.bits=0xffffff6, .bit_length=28}, {.bits=0xffffff7, .bit_length=28},
    {.bits=0xffffff8, .bit_length=28}, {.bits=0xffffff9, .bit_length=28}, {.bits=0xffffffa, .bit_length=28}, {.bits=0xffffffb, .bit_length=28},
    {.bits=0x14, .bit_length=6},      {.bits=0x3f8, .bit_length=10},    {.bits=0x3f9, .bit_length=10},    {.bits=0xffa, .bit_length=12},
    {.bits=0x1ff9, .bit_length=13},   {.bits=0x15, .bit_length=6},      {.bits=0xf8, .bit_length=8},      {.bits=0x7fa, .bit_length=11},
    {.bits=0x3fa, .bit_length=10},    {.bits=0x3fb, .bit_length=10},    {.bits=0xf9, .bit_length=8},      {.bits=0x7fb, .bit_length=11},
    {.bits=0xfa, .bit_length=8},      {.bits=0x16, .bit_length=6},      {.bits=0x17, .bit_length=6},      {.bits=0x18, .bit_length=6},
    {.bits=0x0, .bit_length=5},       {.bits=0x1, .bit_length=5},       {.bits=0x2, .bit_length=5},       {.bits=0x19, .bit_length=6},
    {.bits=0x1a, .bit_length=6},      {.bits=0x1b, .bit_length=6},      {.bits=0x1c, .bit_length=6},      {.bits=0x1d, .bit_length=6},
    {.bits=0x1e, .bit_length=6},      {.bits=0x1f, .bit_length=6},      {.bits=0x5c, .bit_length=7},      {.bits=0xfb, .bit_length=8},
    {.bits=0x7ffc, .bit_length=15},   {.bits=0x20, .bit_length=6},      {.bits=0xffb, .bit_length=12},    {.bits=0x3fc, .bit_length=10},
    {.bits=0x1ffa, .bit_length=13},   {.bits=0x21, .bit_length=6},      {.bits=0x5d, .bit_length=7},      {.bits=0x5e, .bit_length=7},
    {.bits=0x5f, .bit_length=7},      {.bits=0x60, .bit_length=7},      {.bits=0x61, .bit_length=7},      {.bits=0x62, .bit_length=7},
    {.bits=0x63, .bit_length=7},      {.bits=0x64, .bit_length=7},      {.bits=0x65, .bit_length=7},      {.bits=0x66, .bit_length=7},
    {.bits=0x67, .bit_length=7},      {.bits=0x68, .bit_length=7},      {.bits=0x69, .bit_length=7},      {.bits=0x6a, .bit_length=7},
    {.bits=0x6b, .bit_length=7},      {.bits=0x6c, .bit_length=7},      {.bits=0x6d, .bit_length=7},      {.bits=0x6e, .bit_length=7},
    {.bits=0x6f, .bit_length=7},      {.bits=0x70, .bit_length=7},      {.bits=0x71, .bit_length=7},      {.bits=0x72, .bit_length=7},
    {.bits=0xfc, .bit_length=8},      {.bits=0x73, .bit_length=7},      {.bits=0xfd, .bit_length=8},      {.bits=0x1ffb, .bit_length=13},
    {.bits=0x7fff0, .bit_length=19},  {.bits=0x1ffc, .bit_length=13},   {.bits=0x3ffc, .bit_length=14},   {.bits=0x22, .bit_length=6},
    {.bits=0x7ffd, .bit_length=15},   {.bits=0x3, .bit_length=5},       {.bits=0x23, .bit_length=6},      {.bits=0x4, .bit_length=5},
    {.bits=0x24, .bit_length=6},      {.bits=0x5, .bit_length=5},       {.bits=0x25, .bit_length=6},      {.bits=0x26, .bit_length=6},
    {.bits=0x27, .bit_length=6},      {.bits=0x6, .bit_length=5},       {.bits=0x74, .bit_length=7},      {.bits=0x75, .bit_length=7},
    {.bits=0x28, .bit_length=6},      {.bits=0x29, .bit_length=6},      {.bits=0x2a, .bit_length=6},      {.bits=0x7, .bit_length=5},
    {.bits=0x2b, .bit_length=6},      {.bits=0x76, .bit_length=7},      {.bits=0x2c, .bit_length=6},      {.bits=0x8, .bit_length=5},
    {.bits=0x9, .bit_length=5},       {.bits=0x2d, .bit_length=6},      {.bits=0x77, .bit_length=7},      {.bits=0x78, .bit_length=7},
    {.bits=0x79, .bit_length=7},      {.bits=0x7a, .bit_length=7},      {.bits=0x7b, .bit_length=7},      {.bits=0x7ffe, .bit_length=15},
    {.bits=0x7fc, .bit_length=11},    {.bits=0x3ffd, .bit_length=14},   {.bits=0x1ffd, .bit_length=13},   {.bits=0xffffffc, .bit_length=28},
    {.bits=0xfffe6, .bit_length=20},  {.bits=0x3fffd2, .bit_length=22}, {.bits=0xfffe7, .bit_length=20},  {.bits=0xfffe8, .bit_length=20},
    {.bits=0x3fffd3, .bit_length=22}, {.bits=0x3fffd4, .bit_length=22}, {.bits=0x3fffd5, .bit_length=22}, {.bits=0x7fffd9, .bit_length=23},
    {.bits=0x3fffd6, .bit_length=22}, {.bits=0x7fffda, .bit_length=23}, {.bits=0x7fffdb, .bit_length=23}, {.bits=0x7fffdc, .bit_length=23},
    {.bits=0x7fffdd, .bit_length=23}, {.bits=0x7fffde, .bit_length=23}, {.bits=0xffffeb, .bit_length=24}, {.bits=0x7fffdf, .bit_length=23},
    {.bits=0xffffec, .bit_length=24}, {.bits=0xffffed, .bit_length=24}, {.bits=0x3fffd7, .bit_length=22}, {.bits=0x7fffe0, .bit_length=23},
    {.bits=0xffffee, .bit_length=24}, {.bits=0x7fffe1, .bit_length=23}, {.bits=0x7fffe2, .bit_length=23}, {.bits=0x7fffe3, .bit_length=23},
    {.bits=0x7fffe4, .bit_length=23}, {.bits=0x1fffdc, .bit_length=21}, {.bits=0x3fffd8, .bit_length=22}, {.bits=0x7fffe5, .bit_length=23},
    {.bits=0x3fffd9, .bit_length=22}, {.bits=0x7fffe6, .bit_length=23}, {.bits=0x7fffe7, .bit_length=23}, {.bits=0xffffef, .bit_length=24},
    {.bits=0x3fffda, .bit_length=22}, {.bits=0x1fffdd, .bit_length=21}, {.bits=0xfffe9, .bit_length=20},  {.bits=0x3fffdb, .bit_length=22},
    {.bits=0x3fffdc, .bit_length=22}, {.bits=0x7fffe8, .bit_length=23}, {.bits=0x7fffe9, .bit_length=23}, {.bits=0x1fffde, .bit_length=21},
    {.bits=0x7fffea, .bit_length=23}, {.bits=0x3fffdd, .bit_length=22}, {.bits=0x3fffde, .bit_length=22}, {.bits=0xfffff0, .bit_length=24},
    {.bits=0x1fffdf, .bit_length=21}, {.bits=0x3fffdf, .bit_length=22}, {.bits=0x7fffeb, .bit_length=23}, {.bits=0x7fffec, .bit_length=23},
    {.bits=0x1fffe0, .bit_length=21}, {.bits=0x1fffe1, .bit_length=21}, {.bits=0x3fffe0, .bit_length=22}, {.bits=0x1fffe2, .bit_length=21},
    {.bits=0x7fffed, .bit_length=23}, {.bits=0x3fffe1, .bit_length=22}, {.bits=0x7fffee, .bit_length=23}, {.bits=0x7fffef, .bit_length=23},
    {.bits=0xfffea, .bit_length=20},  {.bits=0x3fffe2, .bit_length=22}, {.bits=0x3fffe3, .bit_length=22}, {.bits=0x3fffe4, .bit_length=22},
    {.bits=0x7ffff0, .bit_length=23}, {.bits=0x3fffe5, .bit_length=22}, {.bits=0x3fffe6, .bit_length=22}, {.bits=0x7ffff1, .bit_length=23},
    {.bits=0x3ffffe0, .bit_length=26}, {.bits=0x3ffffe1, .bit_length=26}, {.bits=0xfffeb, .bit_length=20}, {.bits=0x7fff1, .bit_length=19},
    {.bits=0x3fffe7, .bit_length=22}, {.bits=0x7ffff2, .bit_length=23}, {.bits=0x3fffe8, .bit_length=22}, {.bits=0x1ffffec, .bit_length=25},
    {.bits=0x3ffffe2, .bit_length=26}, {.bits=0x3ffffe3, .bit_length=26}, {.bits=0x3ffffe4, .bit_length=26}, {.bits=0x7ffffde, .bit_length=27},
    {.bits=0x7ffffdf, .bit_length=27}, {.bits=0x3ffffe5, .bit_length=26}, {.bits=0xfffff1, .bit_length=24}, {.bits=0x1ffffed, .bit_length=25},
    {.bits=0x7fff2, .bit_length=19},  {.bits=0x1fffe3, .bit_length=21}, {.bits=0x3ffffe6, .bit_length=26}, {.bits=0x7ffffe0, .bit_length=27},
    {.bits=0x7ffffe1, .bit_length=27}, {.bits=0x3ffffe7, .bit_length=26}, {.bits=0x7ffffe2, .bit_length=27}, {.bits=0xfffff2, .bit_length=24},
    {.bits=0x1fffe4, .bit_length=21}, {.bits=0x1fffe5, .bit_length=21}, {.bits=0x3ffffe8, .bit_length=26}, {.bits=0x3ffffe9, .bit_length=26},
    {.bits=0xffffffd, .bit_length=28}, {.bits=0x7ffffe3, .bit_length=27}, {.bits=0x7ffffe4, .bit_length=27}, {.bits=0x7ffffe5, .bit_length=27},
    {.bits=0xfffec, .bit_length=20},  {.bits=0xfffff3, .bit_length=24}, {.bits=0xfffed, .bit_length=20},  {.bits=0x1fffe6, .bit_length=21},
    {.bits=0x3fffe9, .bit_length=22}, {.bits=0x1fffe7, .bit_length=21}, {.bits=0x1fffe8, .bit_length=21}, {.bits=0x7ffff3, .bit_length=23},
    {.bits=0x3fffea, .bit_length=22}, {.bits=0x3fffeb, .bit_length=22}, {.bits=0x1ffffee, .bit_length=25}, {.bits=0x1ffffef, .bit_length=25},
    {.bits=0xfffff4, .bit_length=24}, {.bits=0xfffff5, .bit_length=24}, {.bits=0x3ffffea, .bit_length=26}, {.bits=0x7ffff4, .bit_length=23},
    {.bits=0x3ffffeb, .bit_length=26}, {.bits=0x7ffffe6, .bit_length=27}, {.bits=0x3ffffec, .bit_length=26}, {.bits=0x3ffffed, .bit_length=26},
    {.bits=0x7ffffe7, .bit_length=27}, {.bits=0x7ffffe8, .bit_length=27}, {.bits=0x7ffffe9, .bit_length=27}, {.bits=0x7ffffea, .bit_length=27},
    {.bits=0x7ffffeb, .bit_length=27}, {.bits=0xffffffe, .bit_length=28}, {.bits=0x7ffffec, .bit_length=27}, {.bits=0x7ffffed, .bit_length=27},
    {.bits=0x7ffffee, .bit_length=27}, {.bits=0x7ffffef, .bit_length=27}, {.bits=0x7fffff0, .bit_length=27}, {.bits=0x3ffffee, .bit_length=26} // , {3fffffff, 30} implicit
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

table::table()  {}

size_t table::index(const entry_t& entry) {
    for(size_t i = 0; i < s_static_table.size(); i++) {
        const auto& ent = s_static_table[i];
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
        const auto& ent = s_static_table[i];
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
    bool const is_huffman = (encoded[offset] & 0x80) != 0;
    uint32_t const size = decode_integer(encoded, offset, 7);
    if(is_huffman) {
        if(offset + size > encoded.size()) {
            throw h2_error("bad Huffman decode", h2_code::COMPRESSION_ERROR);
        }
        auto ret = decode_huffman({encoded.begin() + offset, size});
        offset += size;
        return ret;
    }         std::string out;
        if(offset + size > encoded.size()) {
            throw h2_error("bad Huffman decode", h2_code::COMPRESSION_ERROR);
        }
        out.append(encoded.begin() + offset, encoded.begin() + offset + size);
        offset += size;
        return out;
   
}

std::string decode_huffman(std::span<const uint8_t> encoded_str) {
    std::string result;
    uint32_t current_bits = 0;
    uint8_t bit_size = 0;
    for (uint8_t const byte : encoded_str) {
        for (int bit = 7; bit >= 0; --bit) {
            current_bits <<= 1;
            current_bits |= ((byte >> bit) & 1);
            bit_size++;
            if(auto it = huffman_decode.find(hpack_huffman_bit_pattern{.bits=current_bits, .bit_length=bit_size}); it != huffman_decode.end()) {
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

std::vector<uint8_t> encode_huffman(const std::string& str_literal) {
    std::vector<uint8_t> out;
    uint8_t bit_idx = 0;
    uint8_t current_byte = 0;

    for (uint8_t const ch : str_literal) {
        auto [bit_pattern, num_bits] = huffman_table[ch];
        while (num_bits > 0) {
            uint8_t const available_bits = 8 - bit_idx;
            uint8_t const bits_to_write = std::min(num_bits, available_bits);
            uint8_t const shift = num_bits - bits_to_write;
            uint8_t const bits = (bit_pattern >> shift) & ((1 << bits_to_write) - 1);
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
    uint32_t const prefix = (1 << prefix_bits) - 1;
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
        uint8_t const byte = encoded[offset + i];

        const uint64_t seven_bits = (byte & 0x7F);
        value += (seven_bits << (7*(i-1)));

        if (value > ((1ULL << 31) - prefix)) [[unlikely]] {
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
    }         auto lit = encode_integer(str.size(), 7);
        lit.insert(lit.end(), str.begin(), str.end());
        return lit;
   
}

std::vector<uint8_t> indexed_field(uint32_t idx) {
    std::vector<uint8_t> rep = encode_integer(idx, 7);
    rep[0] |= 0x80;
    return rep;
}

std::vector<uint8_t> indexed_name_new_value(uint32_t idx, std::string value) {
    std::vector<uint8_t> rep = encode_integer(idx, 6);
    rep[0] |= 0x40;
    const auto string_encoded = encode_string_efficient(std::move(value));
    rep.insert(rep.end(), string_encoded.begin(), string_encoded.end());
    return rep;
}

std::vector<uint8_t> new_name_new_value(std::string name, std::string value) {
    std::vector<uint8_t> rep {0x40};
    const auto name_encoded = encode_string_efficient(std::move(name));
    const auto value_encoded = encode_string_efficient(std::move(value));
    rep.insert(rep.end(), name_encoded.begin(), name_encoded.end());
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    return rep;
}

std::vector<uint8_t> indexed_name_new_value_without_dynamic(uint32_t idx, std::string value) {
    std::vector<uint8_t> rep = encode_integer(idx, 4);
    const auto value_encoded = encode_string_efficient(std::move(value));
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    return rep;
}

std::vector<uint8_t> new_name_new_value_without_dynamic(std::string name, std::string value) {
    std::vector<uint8_t> rep {0};
    const auto name_encoded = encode_string_efficient(std::move(name));
    const auto value_encoded = encode_string_efficient(std::move(value));
    rep.insert(rep.end(), name_encoded.begin(), name_encoded.end());
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    return rep;
}

std::vector<uint8_t> indexed_name_new_value_never_dynamic(uint32_t idx, std::string value) {
    std::vector<uint8_t> rep = encode_integer(idx, 4);
    const auto value_encoded = encode_string_literal(std::move(value));
    rep.insert(rep.end(), value_encoded.begin(), value_encoded.end());
    rep[0] |= 0x10;
    return rep;
}

std::vector<uint8_t> new_name_new_value_never_dynamic(std::string name, std::string value) {
    std::vector<uint8_t> rep {0x10};
    const auto name_encoded = encode_string_literal(std::move(name));
    const auto value_encoded = encode_string_literal(std::move(value));
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
    uint8_t const byte = encoded[offset];
    int prefix_bytes = 0;
    prefix_type type;
    using enum prefix_type;
    if((byte & 0x80) != 0) {
        prefix_bytes = 7;
        type = indexed_header;
    } else if((byte & 0x40) != 0) {
        prefix_bytes = 6;
        type = literal_header_incremental_indexing;
    } else if((byte & 0x20) != 0) {
        prefix_bytes = 5;
        type = table_size_update;
    } else if((byte & 0x10) != 0) {
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
            return {{.name=name, .value=value, .do_index=do_indexing::incremental}};
        }
        case literal_header_incremental_indexing: {
            auto name = decode_name(idx);
            auto value = decode_string(encoded, offset);
            m_decode_table.add_entry(name, value);
            return {{.name=name, .value=value, .do_index=do_indexing::incremental}};
        }
        case literal_header_never_indexing: {
            auto name = decode_name(idx);
            auto value = decode_string(encoded, offset);
            return {{.name=name, .value=value, .do_index=do_indexing::never}};
        }
        case literal_header_without_indexing: {
            auto name = decode_name(idx);
            auto value = decode_string(encoded, offset);
            return {{.name=name, .value=value, .do_index=do_indexing::without}};
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
    entry_t{.name=":authority", .value=""},
    {.name=":method", .value="GET"},
    {.name=":method", .value="POST"},
    {.name=":path", .value="/"},
    {.name=":path", .value="/index.html"},
    {.name=":scheme", .value="http"},
    {.name=":scheme", .value="https"},
    {.name=":status", .value="200"},
    {.name=":status", .value="204"},
    {.name=":status", .value="206"},
    {.name=":status", .value="304"},
    {.name=":status", .value="400"},
    {.name=":status", .value="404"},
    {.name=":status", .value="500"},
    {.name="accept-charset", .value=""},
    {.name="accept-encoding", .value="gzip, deflate"},
    {.name="accept-language", .value=""},
    {.name="accept-ranges", .value=""},
    {.name="accept", .value=""},
    {.name="access-control-allow-origin", .value=""},
    {.name="age", .value=""},
    {.name="allow", .value=""},
    {.name="authorization", .value=""},
    {.name="cache-control", .value=""},
    {.name="content-disposition", .value=""},
    {.name="content-encoding", .value=""},
    {.name="content-language", .value=""},
    {.name="content-length", .value=""},
    {.name="content-location", .value=""},
    {.name="content-range", .value=""},
    {.name="content-type", .value=""},
    {.name="cookie", .value=""},
    {.name="date", .value=""},
    {.name="etag", .value=""},
    {.name="expect", .value=""},
    {.name="expires", .value=""},
    {.name="from", .value=""},
    {.name="host", .value=""},
    {.name="if-match", .value=""},
    {.name="if-modified-since", .value=""},
    {.name="if-none-match", .value=""},
    {.name="if-range", .value=""},
    {.name="if-unmodified-since", .value=""},
    {.name="last-modified", .value=""},
    {.name="link", .value=""},
    {.name="location", .value=""},
    {.name="max-forwards", .value=""},
    {.name="proxy-authenticate", .value=""},
    {.name="proxy-authorization", .value=""},
    {.name="range", .value=""},
    {.name="referer", .value=""},
    {.name="refresh", .value=""},
    {.name="retry-after", .value=""},
    {.name="server", .value=""},
    {.name="set-cookie", .value=""},
    {.name="strict-transport-security", .value=""},
    {.name="transfer-encoding", .value=""},
    {.name="user-agent", .value=""},
    {.name="vary", .value=""},
    {.name="via", .value=""},
    {.name="www-authenticate", .value=""}
};

const std::unordered_map<hpack_huffman_bit_pattern, uint8_t> huffman_decode = [](){
    std::unordered_map<hpack_huffman_bit_pattern, uint8_t> out;
    for(size_t i = 0; i < huffman_table.size(); i++) {
        out.insert({huffman_table[i], i});
    }
    return out;
}();

}
