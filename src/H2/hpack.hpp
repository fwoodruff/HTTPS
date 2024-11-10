//
//  hpack.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 3/11/2024.
//

#ifndef hpack_hpp
#define hpack_hpp

#include <unordered_map>
#include <vector>
#include <string>

class hpack {
private:
    std::unordered_map<uint32_t, std::string> known_headers;
public:
    std::unordered_map<std::string, std::string> parse_field_block_fragment(const std::vector<uint8_t>& field_block_fragment);
};

#endif // hpack_hpp