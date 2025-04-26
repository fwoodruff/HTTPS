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
#include <span>

namespace fbw {

using ustring = std::vector<uint8_t>;

constexpr size_t TLS_RECORD_SIZE = (1u << 14);
constexpr size_t TLS_EXPANSION_MAX = 2048;
constexpr size_t TLS_HEADER_SIZE = 5;
constexpr size_t WRITE_RECORD_SIZE = 2899;
constexpr size_t DECRYPTED_TLS_RECORD_GIVE = 1024;
constexpr ssize_t FILE_READ_SIZE = 11401;
constexpr long MAX_HEADER_SIZE = 6000;
constexpr long MAX_HEADER_FIELD_SIZE = 5000;
constexpr long MAX_URI_SIZE = 5000;
constexpr long MAX_BODY_SIZE = 8192;

struct options {
    std::string redirect_port;
    std::string server_port;
    std::vector<std::string> domain_names;
    std::filesystem::path certificate_file;
    std::filesystem::path key_file;
    std::filesystem::path key_folder;
    std::filesystem::path webpage_folder;
    std::filesystem::path default_subfolder;
    std::filesystem::path mime_folder;
    std::filesystem::path tld_file;
    bool http_strict_transport_security;
    std::chrono::milliseconds session_timeout;
    std::chrono::milliseconds keep_alive;
    std::chrono::milliseconds error_timeout;
    std::chrono::milliseconds handshake_timeout;
};

extern options project_options;
void init_options();

template<typename T>
[[nodiscard("returns read integer")]] inline uint64_t try_bigend_read(const T& container, size_t idx, size_t nbytes) {
    uint64_t len = 0;
    for(size_t i = idx; i < idx + nbytes; i ++) {
        len <<= 8;
        if(i >= container.size()) {
            throw std::out_of_range{"std::out_of_range: pos >= size()"};
        }
        len |= container[i];
    }
    return len;
}

template<typename T>
[[nodiscard("returns span")]] inline std::span<const uint8_t> der_span_read(const T& container, size_t idx, size_t nbytes) {
    auto size = try_bigend_read(container, idx, nbytes );
    if(container.size() < idx + nbytes + size) {
        throw std::out_of_range{"out of range"};
    }
    std::span<const uint8_t> a_view( container.begin() + idx + nbytes, size);
    return  a_view;
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

[[nodiscard("returns unsigned string")]] inline ustring to_unsigned(std::string s) {
    ustring out;
    out.assign(s.cbegin(), s.cend());
    return out;
}

[[nodiscard("returns signed string")]] inline std::string to_signed(ustring s) {
    std::string out;
    out.append(s.cbegin(), s.cend());
    return out;
}

inline void hash_combine(std::size_t& seed) { }

template <typename T, typename... Rest>
inline void hash_combine(std::size_t& seed, const T& v, Rest... rest) {
    std::hash<T> hasher;
    seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
    hash_combine(seed, rest...);
}

void remove_whitespace(std::string& str);

std::vector<std::string> split(const std::string& line, const std::string& delim);

} // namespace fbw

#endif // global_hpp
