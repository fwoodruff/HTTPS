//
//  hpack.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 3/11/2024.
//

#ifndef hpack_hpp
#define hpack_hpp

#include "../global.hpp"

#include <unordered_map>
#include <vector>
#include <string>
#include <deque>
#include <array>
#include <utility>
#include <span>

namespace fbw {

struct hpack_huffman_bit_pattern {
    uint32_t bits;
    uint8_t bit_length;
    auto operator<=>(const hpack_huffman_bit_pattern&) const = default;
};

struct setting_values;
constexpr size_t static_entries = 61;

struct entry_t {
    std::string name;
    std::string value;
    auto operator<=>(const entry_t&) const = default;
};
} 

template<>
struct std::hash<fbw::entry_t> {
    size_t operator()(const fbw::entry_t& s) const noexcept {
        size_t seed = 0;
        fbw::hash_combine(seed, s.name, s.value);
        return seed;
    }
};

template<>
struct std::hash<fbw::hpack_huffman_bit_pattern> {
    size_t operator()(const fbw::hpack_huffman_bit_pattern& s) const noexcept {
        size_t seed = s.bits;
        fbw::hash_combine(seed, s.bits, s.bit_length);
        return seed;
    }
};

namespace fbw {


struct logged_entry {
    entry_t entry;
    uint32_t idx;
};

class table {
    using cont_t = std::deque<logged_entry>;
    std::unordered_map<entry_t, cont_t::iterator> lookup_idx;
    std::unordered_map<size_t, cont_t::iterator> lookup_field;
    cont_t entries_ordered;
    size_t m_capacity;
    uint32_t next_idx = static_entries + 1;
    void pop_entry();
public:
    table();
    void set_capacity(size_t capacity);
    size_t index(const entry_t& entry);
    std::optional<entry_t> field(size_t entry);
    void add_entry(const entry_t& entry);
};

class hpack {
private:
    static const std::array<entry_t, static_entries> s_static_table;
    table m_client_table;
    table m_server_table;

    size_t client_table_index(const entry_t& entry);
    

public:
    void set_client_capacity(uint32_t);
    void set_server_capacity(uint32_t);
    std::vector<entry_t> parse_field_block_fragment(const ustring& field_block_fragment);
    ustring generate_field_block_fragment(const std::vector<entry_t>& headers);
};

}

#endif // hpack_hpp