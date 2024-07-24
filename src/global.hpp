//
//  global.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//

#ifndef global_hpp
#define global_hpp

#include <cassert>
#include <string>
#include <array>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <optional>
#include <vector>
#include <filesystem>

namespace fbw {

using ustring = std::basic_string<uint8_t>;

struct options {
    std::string redirect_port;
    std::string server_port;
    std::vector<std::string> domain_names;
    std::filesystem::path certificate_file;
    std::filesystem::path key_file;
    std::filesystem::path webpage_folder;
    std::filesystem::path mime_folder;
    bool http_strict_transport_security;
    std::chrono::milliseconds session_timeout;
    std::chrono::milliseconds keep_alive;
    std::chrono::milliseconds error_timeout;
    std::chrono::milliseconds handshake_timeout;
};

const options& option_singleton();

template<typename T>
[[nodiscard]] inline uint64_t try_bigend_read(const T& container, size_t idx, size_t nbytes) {
    uint64_t len = 0;
    for(size_t i = idx; i < idx + nbytes; i ++) {
        len <<= 8;
        len |= container.at(i);
    }
    return len;
}

template<typename T>
inline void checked_bigend_write(uint64_t x, T& container, ssize_t idx, short nbytes) {
    assert(static_cast<ssize_t>(container.size()) > idx + nbytes - 1);
    assert(nbytes >= 1);
    assert(nbytes <= 8);
    assert(nbytes == 8 or x < (1ull << nbytes*8));
    assert(idx >= 0);
    for(ssize_t i = idx+nbytes-1; i >= idx; i--) {
        container[i] = static_cast<uint8_t>(x) & 0xffU;
        x >>= 8;
    }
}

[[nodiscard]] inline ustring to_unsigned(std::string s) {
    ustring out;
    out.append(s.cbegin(), s.cend());
    return out;
}

[[nodiscard]] inline std::string to_signed(ustring s) {
    std::string out;
    out.append(s.cbegin(), s.cend());
    return out;
}

void remove_whitespace(std::string& str);

} // namespace fbw

#endif // global_hpp
