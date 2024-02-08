//
//  TLS_enums.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 05/12/2021.
//

#ifndef TLS_enums_hpp
#define TLS_enums_hpp


#include "../global.hpp"
#include <span>

enum class HandshakeStage {
    client_hello,
    server_hello,
    server_certificate,
    server_key_exchange,
    server_hello_done,
    client_key_exchange,
    client_change_cipher_spec,
    client_handshake_finished,
    server_change_cipher_spec,
    server_handshake_finished,
    application_data
};


namespace fbw {
enum class NamedCurve : uint16_t {
    secp256r1 = 23,
    secp384r1 = 24,
    secp521r1 = 25,
    x25519 = 29,
    x448 = 30
};

enum class ContentType : uint8_t {
    ChangeCipherSpec = 0x14,
    Alert,
    Handshake,
    Application,
    Heartbeat
};

enum class ECCurveType : uint8_t{
    named_curve = 3
};

enum class ChangeCipherSpec : uint8_t {
    change_cipher_spec = 1
};

enum class AlertLevel : uint8_t {
    warning = 1,
    fatal = 2
};

enum class AlertDescription : uint8_t {
    close_notify = 0,
    unexpected_message = 10,
    bad_record_mac = 20,
    decryption_failed_RESERVED = 21,
    record_overflow = 22,
    decompression_failure = 30,
    handshake_failure = 40,
    no_certificate_RESERVED = 41,
    bad_certificate = 42,
    unsupported_certificate = 43,
    certificate_revoked = 44,
    certificate_expired = 45,
    certificate_unknown = 46,
    illegal_parameter = 47,
    unknown_ca = 48,
    access_denied = 49,
    decode_error = 50,
    decrypt_error = 51,
    export_restriction_RESERVED = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    user_canceled = 90,
    no_renegotiation = 100,
    unsupported_extension = 110
};

enum class HandshakeType : uint8_t {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20
};

enum class HashAlgorithm : uint8_t {
    none = 0,
    md5 = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,
    sha512 = 6
};

enum class SignatureAlgorithm : uint8_t {
    anonymous = 0,
    rsa = 1,
    dsa = 2,
    ecdsa = 3,
};

enum class cipher_suites : uint16_t {
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
    TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
    TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
    TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
    TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
};


class ssl_error : public std::runtime_error {
public:
    AlertLevel m_l;
    AlertDescription m_d;

    ssl_error(const std::string& what_arg,
              AlertLevel l,
              AlertDescription d) :
    std::runtime_error(what_arg), m_l(l), m_d(d) {}
};

struct tls_record {

private:
    uint8_t m_type;
    uint8_t m_major_version;
    uint8_t m_minor_version;
public:
    //tls_record() = default; // remove this line then fix task.hpp
    ustring m_contents;
    
    inline uint8_t get_type() const { return m_type; }
    inline uint8_t get_major_version() const { return m_major_version; }
    inline uint8_t get_minor_version() const { return m_minor_version; }
    
    
    inline tls_record(ContentType type, uint8_t major_version = 3, uint8_t minor_version = 3) :
        m_type(static_cast<uint8_t>(type)),
        m_major_version(major_version),
        m_minor_version(minor_version),
        m_contents()
    {}
    
    inline ustring serialise() const {
        assert(m_contents.size() != 0);
        ustring out;
        out.append({m_type, m_major_version, m_minor_version, 0,0});
        checked_bigend_write(m_contents.size(), out, 3, 2);
        out.append(m_contents);
        return out;
    }
};



} // namespace fbw

#endif // TLS_enums_hpp
