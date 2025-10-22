//
//  hpack.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 3/11/2024.
//

#ifndef hpack_hpp
#define hpack_hpp

#include "../../global.hpp"
#include "../common/http_ctx.hpp"
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
constexpr size_t first_dynamic_idx = static_entries + 1;
}

template<>
struct std::hash<fbw::hpack_huffman_bit_pattern> {
    size_t operator()(const fbw::hpack_huffman_bit_pattern& pattern) const noexcept {
        size_t seed = pattern.bits;
        fbw::hash_combine(seed, pattern.bits, pattern.bit_length);
        return seed;
    }
};

namespace fbw {

struct logged_entry {
    std::string name;
    std::string value;
};

class table { // todo consider structure
    using cont_t = std::deque<logged_entry>;
    cont_t entries_ordered;
    
    size_t m_size = 0;
    uint32_t next_idx = first_dynamic_idx;
    void pop_entry();
public:
    static const std::array<entry_t, static_entries> s_static_table;
    table();
    size_t m_capacity = 4096;
    void set_capacity(size_t capacity);
    size_t index(entry_t entry);
    size_t name_index(const std::string& entry);
    std::string field_name(size_t entry);
    std::string field_value(size_t entry);
    void add_entry(const std::string& name, const std::string& value);
};

class hpack {
private:

    table m_encode_table;
    table m_decode_table;

    enum class prefix_type : uint8_t {
        indexed_header,
        literal_header_incremental_indexing,
        table_size_update,
        literal_header_without_indexing,
        literal_header_never_indexing,
    };

    std::optional<entry_t> decode_hpack_string(const std::vector<uint8_t>& data, size_t& offset);
    std::pair<hpack::prefix_type, uint32_t> decode_prefix(const std::vector<uint8_t>& encoded, size_t& offset);
public:
    size_t encoder_max_capacity = 4096;
    size_t decoder_max_capacity = 4096;

    void set_encoder_max_capacity(uint32_t);
    void set_decoder_max_capacity(uint32_t);
    std::vector<entry_t> parse_field_block(const std::vector<uint8_t>& field_block_fragment);
    std::vector<uint8_t> generate_field_block(const std::vector<entry_t>& headers);
};

}

#endif // hpack_hpp