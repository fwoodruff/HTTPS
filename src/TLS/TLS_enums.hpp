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
    server_encrypted_extensions,
    server_certificate_verify,
    client_handshake_finished,
    server_change_cipher_spec,
    server_handshake_finished,
    application_data
};


namespace fbw {
enum class NamedGroup : uint16_t {
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    x25519 = 0x001D,
    x448 = 0x001E,

    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
};

enum class PskKeyExchangeMode : uint8_t { 
    psk_ke = 0,
    psk_dhe_ke = 1
};

enum class CertificateType : uint8_t {
    X509 = 0,
    RawPublicKey = 2,
};

enum class KeyUpdateRequest : uint8_t {
    update_not_requested = 0,
    update_requested = 1,
};

enum class ContentType : uint8_t {
    Invalid = 0,
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
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100,
    unsupported_extension = 110
};

enum class HandshakeType : uint8_t {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    encrypted_extensions = 8,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    finished = 20
};

enum class ExtensionType : uint16_t{
    server_name = 0,
    max_fragment_length = 1,
    status_request = 5,
    supported_groups = 10,
    signature_algorithms = 13,
    use_srtp = 14,
    heartbeat = 15,
    application_layer_protocol_negotiation = 16,
    signed_certificate_timestamp = 18,
    client_certificate_type = 19,
    server_certificate_type= 20,
    padding= 21,
    pre_shared_key=41,
    early_data=42,
    supported_versions=43,
    cookie=44,
    psk_key_exchange_modes=45,
    certificate_authorities=47,
    oid_filters=48,
    post_handshake_auth=49,
    signature_algorithms_cert=50,
    key_share=51,
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
    TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a,
    TLS_FALLBACK_SCSV = 0x0056,
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_GCM_SHA256 = 0x1301,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff
};

enum class SignatureScheme : uint16_t {
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    ed448 = 0x0808,
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,
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
public:
    uint8_t m_type; // todo: should be a content type not a byte
private:
    uint8_t m_major_version;
    uint8_t m_minor_version;
    struct der_headers {
        ssize_t idx_start;
        ssize_t num_bytes;
    };
    std::vector<der_headers> heads;
public:
    tls_record() = default; // remove this line then fix task.hpp
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
    
    template<typename T>
    void write1(T value) {
        m_contents.push_back(static_cast<uint8_t>(value));
    }
    inline void write1(uint8_t value) {
        m_contents.push_back(value);
    }

    template<typename T>
    inline void write2(T value) {
        m_contents.append({ 0, 0 });
        checked_bigend_write(static_cast<uint16_t>(value), m_contents, m_contents.size() - 2, 2);
    }

    inline void write2(uint16_t value) {
        m_contents.append({ 0, 0 });
        checked_bigend_write(value, m_contents, m_contents.size() - 2, 2);
    }

    template<typename T>
    void write(const T& value) {
        m_contents.append(value.begin(), value.end());
    }
    inline void write(const ustring& value) {
        m_contents.append(value);
    }

    // record items with variable length include a header and are sometimes nested
    // append data and then figure out the header size
    inline void push_der(ssize_t bytes) {
        heads.push_back({static_cast<ssize_t>(m_contents.size()), bytes});
        auto size = ustring(bytes, 0);
        m_contents.append(size);
    }

    inline void pop_der() {
        auto [idx_start, num_bytes] = heads.back();
        heads.pop_back();
        checked_bigend_write(m_contents.size() - idx_start - num_bytes, m_contents, idx_start, num_bytes);
    }
    
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
