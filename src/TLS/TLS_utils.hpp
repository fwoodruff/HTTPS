//
//  TLS_utils.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//


#ifndef tls_utils_hpp
#define tls_utils_hpp



#include "../global.hpp"
#include "TLS_enums.hpp"


#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>

namespace fbw {

struct tls_record {
public:
    ContentType m_type;
private:
    uint8_t m_major_version;
    uint8_t m_minor_version;
    struct der_headers {
        ssize_t idx_start;
        ssize_t num_bytes;
    };
    std::vector<der_headers> heads;
public:
    std::vector<uint8_t> m_contents;
    
    inline ContentType get_type() const { return static_cast<ContentType>(m_type); }
    inline uint8_t get_major_version() const { return m_major_version; }
    inline uint8_t get_minor_version() const { return m_minor_version; }

    inline tls_record(ContentType type = ContentType::Invalid, uint8_t major_version = 3, uint8_t minor_version = 3) :
        m_type(type),
        m_major_version(major_version),
        m_minor_version(minor_version),
        m_contents()
    {}
    
    template<typename T>
    void write1(T value) {
        m_contents.push_back(static_cast<uint8_t>(value));
    }
    inline void write1(uint8_t value) {
        m_contents.push_back(value);
    }

    template<typename T>
    inline void write2(T value) {
        m_contents.insert(m_contents.cend(), { 0, 0 });
        checked_bigend_write(static_cast<uint16_t>(value), m_contents, m_contents.size() - 2, 2);
    }

    inline void write2(uint16_t value) {
        m_contents.insert(m_contents.cend(), { 0, 0 });
        checked_bigend_write(value, m_contents, m_contents.size() - 2, 2);
    }

    template<typename T>
    void write(const T& value) {
        m_contents.insert(m_contents.cend(), value.cbegin(), value.cend());
    }
    inline void write(const std::vector<uint8_t>& value) {
        m_contents.insert(m_contents.cend(), value.cbegin(), value.cend());
    }

    // record items with variable length include a header and are sometimes nested
    // append data and then figure out the header size
    inline void start_size_header(ssize_t bytes) {
        heads.push_back({static_cast<ssize_t>(m_contents.size()), bytes});
        auto size = std::vector<uint8_t>(bytes, 0);
        m_contents.insert(m_contents.cend(), size.cbegin(), size.cend());
    }

    inline void end_size_header() {
        auto [idx_start, num_bytes] = heads.back();
        heads.pop_back();
        checked_bigend_write(m_contents.size() - idx_start - num_bytes, m_contents, idx_start, num_bytes);
    }
    
    inline std::vector<uint8_t> serialise() const {
        assert(m_contents.size() != 0);
        std::vector<uint8_t> out;
        out.insert(out.end(), {static_cast<uint8_t>(m_type), m_major_version, m_minor_version, 0,0});
        checked_bigend_write(m_contents.size(), out, 3, 2);
        out.insert(out.end(), m_contents.cbegin(), m_contents.cend());
        return out;
    }
};

void certificates_serial(tls_record& record, std::string domain, bool use_tls13);
std::optional<tls_record> try_extract_record(std::vector<uint8_t>& input);

} // namespace


#endif // tls_utils_hpp