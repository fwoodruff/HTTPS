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
    
    [[nodiscard]] ContentType get_type() const { return static_cast<ContentType>(m_type); }
    [[nodiscard]] uint8_t get_major_version() const noexcept { return m_major_version; }
    [[nodiscard]] uint8_t get_minor_version() const noexcept { return m_minor_version; }

    tls_record(ContentType type = ContentType::Invalid, uint8_t major_version = 3, uint8_t minor_version = 3) :
        m_type(type),
        m_major_version(major_version),
        m_minor_version(minor_version)
    {}
    
    template<typename T>
    void write1(T value) {
        m_contents.push_back(static_cast<uint8_t>(value));
    }
    void write1(uint8_t value) {
        m_contents.push_back(value);
    }

    template<typename T>
    void write2(T value) {
        m_contents.insert(m_contents.cend(), { 0, 0 });

        auto size_unsigned = m_contents.size();
        assert(size_unsigned <= static_cast<size_t>(std::numeric_limits<ssize_t>::max()));

        auto size = static_cast<ssize_t>(size_unsigned);
        checked_bigend_write(static_cast<uint16_t>(value), m_contents, size - 2, 2);
    }

    void write2(uint16_t value) {
        m_contents.insert(m_contents.cend(), {0, 0});

        auto size_unsigned = m_contents.size();
        assert(size_unsigned <= static_cast<size_t>(std::numeric_limits<ssize_t>::max()));

        auto size = static_cast<ssize_t>(size_unsigned);
        checked_bigend_write(value, m_contents, size - 2, 2);
    }

    template<typename T>
    void write(const T& value) {
        m_contents.insert(m_contents.cend(), value.cbegin(), value.cend());
    }
    void write(const std::vector<uint8_t>& value) {
        m_contents.insert(m_contents.cend(), value.cbegin(), value.cend());
    }

    // record items with variable length include a header and are sometimes nested
    // append data and then figure out the header size
    void start_size_header(ssize_t bytes) {
        heads.push_back({static_cast<ssize_t>(m_contents.size()), bytes});
        auto size = std::vector<uint8_t>(bytes, 0);
        m_contents.insert(m_contents.cend(), size.cbegin(), size.cend());
    }

    void end_size_header() {
        auto [idx_start, num_bytes] = heads.back();
        heads.pop_back();
        assert(num_bytes <= 8);
        auto short_num_bytes = static_cast<short>(num_bytes);
        checked_bigend_write(m_contents.size() - idx_start - num_bytes, m_contents, idx_start, short_num_bytes);
    }
    
    [[nodiscard]] std::vector<uint8_t> serialise() const {
        assert(!m_contents.empty());
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