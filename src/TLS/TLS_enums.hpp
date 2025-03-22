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

constexpr uint16_t TLS10 = 0x0301;
constexpr uint16_t TLS11 = 0x0302;
constexpr uint16_t TLS12 = 0x0303;
constexpr uint16_t TLS13 = 0x0304;

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
    client_early_data,
    client_handshake_finished,
    server_change_cipher_spec,
    server_handshake_finished,
    application_data
};

namespace fbw {
enum class NamedGroup : uint16_t {
    sect163k1 = 0x0001,
    sect163r1 = 0x0002,
    sect163r2 = 0x0003,
    sect193r1 = 0x0004,
    sect193r2 = 0x0005,
    sect233k1 = 0x0006,
    sect233r1 = 0x0007,
    sect239k1 = 0x0008,
    sect283k1 = 0x0009,
    sect283r1 = 0x000A,
    sect409k1 = 0x000B,
    sect409r1 = 0x000C,
    sect571k1 = 0x000D,
    sect571r1 = 0x000E,
    secp160k1 = 0x000F,
    secp160r1 = 0x0010,
    secp160r2 = 0x0011,
    secp192k1 = 0x0012,
    secp192r1 = 0x0013,
    secp224k1 = 0x0014,
    secp224r1 = 0x0015,
    secp256k1 = 0x0016,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
    secp521r1 = 0x0019,
    brainpoolP256r1 = 0x001A,
    brainpoolP384r1 = 0x001B, 
    brainpoolP512r1 = 0x001C,
    x25519 = 0x001D,
    x448 = 0x001E,
    brainpoolP256r1tls13 = 0x001F,
    brainpoolP384r1tls13 = 0x0020,
    brainpoolP512r1tls13 = 0x0021,
    GC256A = 0x0022,
    GC256B = 0x0023,
    GC256C = 0x0024,
    GC256D = 0x0025,
    GC512A = 0x0026,
    GC512B = 0x0027,
    GC512C = 0x0028,
    curveSM2 = 0x0029,
    X25519Kyber768Draft00 = 0x6399,
    SecP256r1Kyber768Draft00 = 0x639A,
    ffdhe2048 = 0x0100,
    ffdhe3072 = 0x0101,
    ffdhe4096 = 0x0102,
    ffdhe6144 = 0x0103,
    ffdhe8192 = 0x0104,
    arbitrary_explicit_prime_curves = 0xFF01,
    arbitrary_explicit_char2_curves = 0xFF02,
    // GREASE values deliberately excluded RFC 8701
};

enum class PskKeyExchangeMode : uint8_t { 
    psk_ke = 0,
    psk_dhe_ke = 1
};

// rfc 6066 - Maximum Fragment Length Negotiation
enum class MaxFragmentLength : uint8_t {
    s2_9 = 1,
    s2_10 = 2,
    s2_11 = 3,
    s2_12 = 4
};

// rfc 6066 - Client Certificate URLs
enum class CertChainType : uint8_t {
    individual_certs = 0,
    pkipath = 1
};
struct URLAndHash{
    ustring url;
    // uint8_t padding;
    std::array<uint8_t, 20> SHA1Hash;
};
struct CertificateURL {
    CertChainType type;
    std::vector<URLAndHash> url_and_hash_list;
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
    Heartbeat,
    tls12_cid,
    ACK
};

enum class ECCurveType : uint8_t{
    named_curve = 3
};

enum class EnumChangeCipherSpec : uint8_t {
    change_cipher_spec = 1
};

enum class AlertLevel : uint8_t {
    warning = 1,
    fatal = 2
};

enum class IdentifierType : uint8_t {
    pre_agreed = 0,
    key_sha1_hash = 1,
    x509_name = 2,
    cert_sha1_hash = 3
};

struct OCSPStatusRequest {
    std::vector<ustring> responderID;
    ustring extensions;
};

enum class CertificateStatusType : uint8_t {
    ocsp = 1
};

struct CertificateStatusRequest {
    CertificateStatusType status_type;
    OCSPStatusRequest request;
};

struct CertificateStatus {
    CertificateStatusType status_type;
    ustring response;
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
    too_many_cids_requested = 52,
    export_restriction_RESERVED = 60,
    protocol_version = 70,
    insufficient_security = 71,
    internal_error = 80,
    inappropriate_fallback = 86,
    user_canceled = 90,
    no_renegotiation = 100,
    missing_extension = 109,
    unsupported_extension = 110,
    certificate_unobtainable = 111,
    unrecognized_name = 112,
    bad_certificate_status_response = 113,
    bad_certificate_hash_value = 114,
    unknown_psk_identity = 115,
    certificate_required = 116,
    no_application_protocol = 120,
};

enum class HandshakeType : uint8_t {
    hello_request = 0,
    client_hello = 1,
    server_hello = 2,
    hello_verify_request = 3,
    new_session_ticket = 4,
    end_of_early_data = 5,
    hello_retry_request = 6,
    encrypted_extensions = 8,
    request_connection_id = 9,
    new_connection_id = 10,
    certificate = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_hello_done = 14,
    certificate_verify = 15,
    client_key_exchange = 16,
    client_certificate_request = 17,
    finished = 20,
    certificate_url = 21,
    certificate_status = 22,
    supplemental_data = 23,
    key_update = 24,
    compressed_certificate = 25,
    ekt_key = 26,
    message_hash = 254
};

enum class ExtensionType : uint16_t{
    server_name = 0,
    max_fragment_length = 1,
    client_certificate_url = 2,
    trusted_ca_keys = 3,
    truncated_hmac = 4,
    status_request = 5,
    user_mapping = 6,
    client_authz = 7,
    server_authz = 8,
    cert_type = 9,
    supported_groups = 10,
    ec_point_formats = 11,
    srp = 12,
    signature_algorithms = 13,
    use_srtp = 14,
    heartbeat = 15,
    application_layer_protocol_negotiation = 16,
    status_request_v2 = 17,
    signed_certificate_timestamp = 18,
    client_certificate_type = 19,
    server_certificate_type= 20,
    padding = 21,
    encrypt_then_mac = 22,
    extended_master_secret = 23,
    token_binding = 24,
    cached_info = 25,
    tls_lts = 26,
    compressed_certificate = 27,
    record_size_limit = 28,
    pwd_protect = 29,
    pwd_clear = 30,
    password_salt = 31,
    ticket_pinning = 32,
    tls_cert_with_extern_psk = 33,
    delegated_credential = 34,
    session_ticket = 35,
    TLMSP = 36,
    TLMSP_proxying = 37,
    TLMSP_delegate = 38,
    supported_ekt_ciphers = 39,
    pre_shared_key = 41,
    early_data = 42,
    supported_versions = 43,
    cookie = 44,
    psk_key_exchange_modes = 45,
    certificate_authorities = 47,
    oid_filters = 48,
    post_handshake_auth = 49,
    signature_algorithms_cert = 50,
    key_share = 51,
    transparency_info = 52,
    connection_id_deprecated = 53,
    connection_id = 54,
    external_id_hash = 55,
    external_session_id = 56,
    quic_transport_parameters = 57,
    ticket_request = 58,
    dnssec_chain = 59,
    sequence_number_encryption_algorithms = 60,
    rrc = 61,
    ech_outer_extesions = 64768,
    renegotiation_info = 65281
};

enum class CertificateCompressionAlgorithm : uint16_t {
    zlib = 1,
    brotli = 2,
    zstd = 3,
};

enum class HashAlgorithm : uint8_t {
    none = 0,
    md5 = 1,
    sha1 = 2,
    sha224 = 3,
    sha256 = 4,
    sha384 = 5,
    sha512 = 6,
    intrinsic = 8,
};

enum class SignatureAlgorithm : uint8_t {
    anonymous = 0,
    rsa = 1,
    dsa = 2,
    ecdsa = 3,
    ed25519	= 7,
    ed448 = 8,
    gostr34102012_256 = 64,
    gostr34102012_512 = 65,
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

enum class cipher_suites : uint16_t {
    TLS_NULL_WITH_NULL_NULL=0x0000,
    TLS_RSA_WITH_NULL_MD5=0x0001,
    TLS_RSA_WITH_NULL_SHA=0x0002,
    TLS_RSA_EXPORT_WITH_RC4_40_MD5=0x0003,
    TLS_RSA_WITH_RC4_128_MD5=0x0004,
    TLS_RSA_WITH_RC4_128_SHA=0x0005,
    TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5=0x0006,
    TLS_RSA_WITH_IDEA_CBC_SHA=0x0007,
    TLS_RSA_EXPORT_WITH_DES40_CBC_SHA=0x0008,
    TLS_RSA_WITH_DES_CBC_SHA=0x0009,
    TLS_RSA_WITH_3DES_EDE_CBC_SHA=0x000A,
    TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA=0x000B,
    TLS_DH_DSS_WITH_DES_CBC_SHA=0x000C,
    TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA=0x000D,
    TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA=0x000E,
    TLS_DH_RSA_WITH_DES_CBC_SHA=0x000F,
    TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA=0x0010,
    TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA=0x0011,
    TLS_DHE_DSS_WITH_DES_CBC_SHA=0x0012,
    TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA=0x0013,
    TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA=0x0014,
    TLS_DHE_RSA_WITH_DES_CBC_SHA=0x0015,
    TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA=0x0016,
    TLS_DH_anon_EXPORT_WITH_RC4_40_MD5=0x0017,
    TLS_DH_anon_WITH_RC4_128_MD5=0x0018,
    TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA=0x0019,
    TLS_DH_anon_WITH_DES_CBC_SHA=0x001A,
    TLS_DH_anon_WITH_3DES_EDE_CBC_SHA=0x001B,
    TLS_KRB5_WITH_DES_CBC_SHA=0x001E,
    TLS_KRB5_WITH_3DES_EDE_CBC_SHA=0x001F,
    TLS_KRB5_WITH_RC4_128_SHA=0x0020,
    TLS_KRB5_WITH_IDEA_CBC_SHA=0x0021,
    TLS_KRB5_WITH_DES_CBC_MD5=0x0022,
    TLS_KRB5_WITH_3DES_EDE_CBC_MD5=0x0023,
    TLS_KRB5_WITH_RC4_128_MD5=0x0024,
    TLS_KRB5_WITH_IDEA_CBC_MD5=0x0025,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA=0x0026,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA=0x0027,
    TLS_KRB5_EXPORT_WITH_RC4_40_SHA=0x0028,
    TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5=0x0029,
    TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5=0x002A,
    TLS_KRB5_EXPORT_WITH_RC4_40_MD5=0x002B,
    TLS_PSK_WITH_NULL_SHA=0x002C,
    TLS_DHE_PSK_WITH_NULL_SHA=0x002D,
    TLS_RSA_PSK_WITH_NULL_SHA=0x002E,
    TLS_RSA_WITH_AES_128_CBC_SHA=0x002F,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA=0x0030,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA=0x0031,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA=0x0032,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA=0x0033,
    TLS_DH_anon_WITH_AES_128_CBC_SHA=0x0034,
    TLS_RSA_WITH_AES_256_CBC_SHA=0x0035,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA=0x0036,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA=0x0037,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA=0x0038,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA=0x0039,
    TLS_DH_anon_WITH_AES_256_CBC_SHA=0x003A,
    TLS_RSA_WITH_NULL_SHA256=0x003B,
    TLS_RSA_WITH_AES_128_CBC_SHA256=0x003C,
    TLS_RSA_WITH_AES_256_CBC_SHA256=0x003D,
    TLS_DH_DSS_WITH_AES_128_CBC_SHA256=0x003E,
    TLS_DH_RSA_WITH_AES_128_CBC_SHA256=0x003F,
    TLS_DHE_DSS_WITH_AES_128_CBC_SHA256=0x0040,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA=0x0041,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA=0x0042,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA=0x0043,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA=0x0044,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA=0x0045,
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA=0x0046,
    TLS_DHE_RSA_WITH_AES_128_CBC_SHA256=0x0067,
    TLS_DH_DSS_WITH_AES_256_CBC_SHA256=0x0068,
    TLS_DH_RSA_WITH_AES_256_CBC_SHA256=0x0069,
    TLS_DHE_DSS_WITH_AES_256_CBC_SHA256=0x006A,
    TLS_DHE_RSA_WITH_AES_256_CBC_SHA256=0x006B,
    TLS_DH_anon_WITH_AES_128_CBC_SHA256=0x006C,
    TLS_DH_anon_WITH_AES_256_CBC_SHA256=0x006D,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA=0x0084,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA=0x0085,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA=0x0086,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA=0x0087,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA=0x0088,
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA=0x0089,
    TLS_PSK_WITH_RC4_128_SHA=0x008A,
    TLS_PSK_WITH_3DES_EDE_CBC_SHA=0x008B,
    TLS_PSK_WITH_AES_128_CBC_SHA=0x008C,
    TLS_PSK_WITH_AES_256_CBC_SHA=0x008D,
    TLS_DHE_PSK_WITH_RC4_128_SHA=0x008E,
    TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA=0x008F,
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA=0x0090,
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA=0x0091,
    TLS_RSA_PSK_WITH_RC4_128_SHA=0x0092,
    TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA=0x0093,
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA=0x0094,
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA=0x0095,
    TLS_RSA_WITH_SEED_CBC_SHA=0x0096,
    TLS_DH_DSS_WITH_SEED_CBC_SHA=0x0097,
    TLS_DH_RSA_WITH_SEED_CBC_SHA=0x0098,
    TLS_DHE_DSS_WITH_SEED_CBC_SHA=0x0099,
    TLS_DHE_RSA_WITH_SEED_CBC_SHA=0x009A,
    TLS_DH_anon_WITH_SEED_CBC_SHA=0x009B,
    TLS_RSA_WITH_AES_128_GCM_SHA256=0x009C,
    TLS_RSA_WITH_AES_256_GCM_SHA384=0x009D,
    TLS_DHE_RSA_WITH_AES_128_GCM_SHA256=0x009E,
    TLS_DHE_RSA_WITH_AES_256_GCM_SHA384=0x009F,
    TLS_DH_RSA_WITH_AES_128_GCM_SHA256=0x00A0,
    TLS_DH_RSA_WITH_AES_256_GCM_SHA384=0x00A1,
    TLS_DHE_DSS_WITH_AES_128_GCM_SHA256=0x00A2,
    TLS_DHE_DSS_WITH_AES_256_GCM_SHA384=0x00A3,
    TLS_DH_DSS_WITH_AES_128_GCM_SHA256=0x00A4,
    TLS_DH_DSS_WITH_AES_256_GCM_SHA384=0x00A5,
    TLS_DH_anon_WITH_AES_128_GCM_SHA256=0x00A6,
    TLS_DH_anon_WITH_AES_256_GCM_SHA384=0x00A7,
    TLS_PSK_WITH_AES_128_GCM_SHA256=0x00A8,
    TLS_PSK_WITH_AES_256_GCM_SHA384=0x00A9,
    TLS_DHE_PSK_WITH_AES_128_GCM_SHA256=0x00AA,
    TLS_DHE_PSK_WITH_AES_256_GCM_SHA384=0x00AB,
    TLS_RSA_PSK_WITH_AES_128_GCM_SHA256=0x00AC,
    TLS_RSA_PSK_WITH_AES_256_GCM_SHA384=0x00AD,
    TLS_PSK_WITH_AES_128_CBC_SHA256=0x00AE,
    TLS_PSK_WITH_AES_256_CBC_SHA384=0x00AF,
    TLS_PSK_WITH_NULL_SHA256=0x00B0,
    TLS_PSK_WITH_NULL_SHA384=0x00B1,
    TLS_DHE_PSK_WITH_AES_128_CBC_SHA256=0x00B2,
    TLS_DHE_PSK_WITH_AES_256_CBC_SHA384=0x00B3,
    TLS_DHE_PSK_WITH_NULL_SHA256=0x00B4,
    TLS_DHE_PSK_WITH_NULL_SHA384=0x00B5,
    TLS_RSA_PSK_WITH_AES_128_CBC_SHA256=0x00B6,
    TLS_RSA_PSK_WITH_AES_256_CBC_SHA384=0x00B7,
    TLS_RSA_PSK_WITH_NULL_SHA256=0x00B8,
    TLS_RSA_PSK_WITH_NULL_SHA384=0x00B9,
    TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256=0x00BA,
    TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256=0x00BB,
    TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256=0x00BC,
    TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256=0x00BD,
    TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256=0x00BE,
    TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256=0x00BF,
    TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256=0x00C0,
    TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256=0x00C1,
    TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256=0x00C2,
    TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256=0x00C3,
    TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256=0x00C4,
    TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256=0x00C5,
    TLS_SM4_GCM_SM3=0x00C6,
    TLS_SM4_CCM_SM3=0x00C7,
    TLS_EMPTY_RENEGOTIATION_INFO_SCSV=0x00FF,
    TLS_AES_128_GCM_SHA256=0x1301,
    TLS_AES_256_GCM_SHA384=0x1302,
    TLS_CHACHA20_POLY1305_SHA256=0x1303,
    TLS_AES_128_CCM_SHA256=0x1304,
    TLS_AES_128_CCM_8_SHA256=0x1305,
    TLS_AEGIS_256_SHA512=0x1306,
    TLS_AEGIS_128L_SHA256=0x1307,
    TLS_FALLBACK_SCSV=0x5600,
    TLS_ECDH_ECDSA_WITH_NULL_SHA=0xC001,
    TLS_ECDH_ECDSA_WITH_RC4_128_SHA=0xC002,
    TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA=0xC003,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA=0xC004,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA=0xC005,
    TLS_ECDHE_ECDSA_WITH_NULL_SHA=0xC006,
    TLS_ECDHE_ECDSA_WITH_RC4_128_SHA=0xC007,
    TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA=0xC008,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA=0xC009,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA=0xC00A,
    TLS_ECDH_RSA_WITH_NULL_SHA=0xC00B,
    TLS_ECDH_RSA_WITH_RC4_128_SHA=0xC00C,
    TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA=0xC00D,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA=0xC00E,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA=0xC00F,
    TLS_ECDHE_RSA_WITH_NULL_SHA=0xC010,
    TLS_ECDHE_RSA_WITH_RC4_128_SHA=0xC011,
    TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA=0xC012,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA=0xC013,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA=0xC014,
    TLS_ECDH_anon_WITH_NULL_SHA=0xC015,
    TLS_ECDH_anon_WITH_RC4_128_SHA=0xC016,
    TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA=0xC017,
    TLS_ECDH_anon_WITH_AES_128_CBC_SHA=0xC018,
    TLS_ECDH_anon_WITH_AES_256_CBC_SHA=0xC019,
    TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA=0xC01A,
    TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA=0xC01B,
    TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA=0xC01C,
    TLS_SRP_SHA_WITH_AES_128_CBC_SHA=0xC01D,
    TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA=0xC01E,
    TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA=0xC01F,
    TLS_SRP_SHA_WITH_AES_256_CBC_SHA=0xC020,
    TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA=0xC021,
    TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA=0xC022,
    TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256=0xC023,
    TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384=0xC024,
    TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256=0xC025,
    TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384=0xC026,
    TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256=0xC027,
    TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384=0xC028,
    TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256=0xC029,
    TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384=0xC02A,
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256=0xC02B,
    TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384=0xC02C,
    TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256=0xC02D,
    TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384=0xC02E,
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256=0xC02F,
    TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384=0xC030,
    TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256=0xC031,
    TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384=0xC032,
    TLS_ECDHE_PSK_WITH_RC4_128_SHA=0xC033,
    TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA=0xC034,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA=0xC035,
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA=0xC036,
    TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256=0xC037,
    TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384=0xC038,
    TLS_ECDHE_PSK_WITH_NULL_SHA=0xC039,
    TLS_ECDHE_PSK_WITH_NULL_SHA256=0xC03A,
    TLS_ECDHE_PSK_WITH_NULL_SHA384=0xC03B,
    TLS_RSA_WITH_ARIA_128_CBC_SHA256=0xC03C,
    TLS_RSA_WITH_ARIA_256_CBC_SHA384=0xC03D,
    TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256=0xC03E,
    TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384=0xC03F,
    TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256=0xC040,
    TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384=0xC041,
    TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256=0xC042,
    TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384=0xC043,
    TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256=0xC044,
    TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384=0xC045,
    TLS_DH_anon_WITH_ARIA_128_CBC_SHA256=0xC046,
    TLS_DH_anon_WITH_ARIA_256_CBC_SHA384=0xC047,
    TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256=0xC048,
    TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384=0xC049,
    TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256=0xC04A,
    TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384=0xC04B,
    TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256=0xC04C,
    TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384=0xC04D,
    TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256=0xC04E,
    TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384=0xC04F,
    TLS_RSA_WITH_ARIA_128_GCM_SHA256=0xC050,
    TLS_RSA_WITH_ARIA_256_GCM_SHA384=0xC051,
    TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256=0xC052,
    TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384=0xC053,
    TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256=0xC054,
    TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384=0xC055,
    TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256=0xC056,
    TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384=0xC057,
    TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256=0xC058,
    TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384=0xC059,
    TLS_DH_anon_WITH_ARIA_128_GCM_SHA256=0xC05A,
    TLS_DH_anon_WITH_ARIA_256_GCM_SHA384=0xC05B,
    TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256=0xC05C,
    TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384=0xC05D,
    TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256=0xC05E,
    TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384=0xC05F,
    TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256=0xC060,
    TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384=0xC061,
    TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256=0xC062,
    TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384=0xC063,
    TLS_PSK_WITH_ARIA_128_CBC_SHA256=0xC064,
    TLS_PSK_WITH_ARIA_256_CBC_SHA384=0xC065,
    TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256=0xC066,
    TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384=0xC067,
    TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256=0xC068,
    TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384=0xC069,
    TLS_PSK_WITH_ARIA_128_GCM_SHA256=0xC06A,
    TLS_PSK_WITH_ARIA_256_GCM_SHA384=0xC06B,
    TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256=0xC06C,
    TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384=0xC06D,
    TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256=0xC06E,
    TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384=0xC06F,
    TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256=0xC070,
    TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384=0xC071,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256=0xC072,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384=0xC073,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256=0xC074,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384=0xC075,
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256=0xC076,
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384=0xC077,
    TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256=0xC078,
    TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384=0xC079,
    TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256=0xC07A,
    TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384=0xC07B,
    TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256=0xC07C,
    TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384=0xC07D,
    TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256=0xC07E,
    TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384=0xC07F,
    TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256=0xC080,
    TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384=0xC081,
    TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256=0xC082,
    TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384=0xC083,
    TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256=0xC084,
    TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384=0xC085,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256=0xC086,
    TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384=0xC087,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256=0xC088,
    TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384=0xC089,
    TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256=0xC08A,
    TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384=0xC08B,
    TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256=0xC08C,
    TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384=0xC08D,
    TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256=0xC08E,
    TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384=0xC08F,
    TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256=0xC090,
    TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384=0xC091,
    TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256=0xC092,
    TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384=0xC093,
    TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256=0xC094,
    TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384=0xC095,
    TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256=0xC096,
    TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384=0xC097,
    TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256=0xC098,
    TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384=0xC099,
    TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256=0xC09A,
    TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384=0xC09B,
    TLS_RSA_WITH_AES_128_CCM=0xC09C,
    TLS_RSA_WITH_AES_256_CCM=0xC09D,
    TLS_DHE_RSA_WITH_AES_128_CCM=0xC09E,
    TLS_DHE_RSA_WITH_AES_256_CCM=0xC09F,
    TLS_RSA_WITH_AES_128_CCM_8=0xC0A0,
    TLS_RSA_WITH_AES_256_CCM_8=0xC0A1,
    TLS_DHE_RSA_WITH_AES_128_CCM_8=0xC0A2,
    TLS_DHE_RSA_WITH_AES_256_CCM_8=0xC0A3,
    TLS_PSK_WITH_AES_128_CCM=0xC0A4,
    TLS_PSK_WITH_AES_256_CCM=0xC0A5,
    TLS_DHE_PSK_WITH_AES_128_CCM=0xC0A6,
    TLS_DHE_PSK_WITH_AES_256_CCM=0xC0A7,
    TLS_PSK_WITH_AES_128_CCM_8=0xC0A8,
    TLS_PSK_WITH_AES_256_CCM_8=0xC0A9,
    TLS_PSK_DHE_WITH_AES_128_CCM_8=0xC0AA,
    TLS_PSK_DHE_WITH_AES_256_CCM_8=0xC0AB,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM=0xC0AC,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM=0xC0AD,
    TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8=0xC0AE,
    TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8=0xC0AF,
    TLS_ECCPWD_WITH_AES_128_GCM_SHA256=0xC0B0,
    TLS_ECCPWD_WITH_AES_256_GCM_SHA384=0xC0B1,
    TLS_ECCPWD_WITH_AES_128_CCM_SHA256=0xC0B2,
    TLS_ECCPWD_WITH_AES_256_CCM_SHA384=0xC0B3,
    TLS_SHA256_SHA256=0xC0B4,
    TLS_SHA384_SHA384=0xC0B5,
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_CTR_OMAC=0xC100,
    TLS_GOSTR341112_256_WITH_MAGMA_CTR_OMAC=0xC101,
    TLS_GOSTR341112_256_WITH_28147_CNT_IMIT=0xC102,
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_L=0xC103,
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_L=0xC104,
    TLS_GOSTR341112_256_WITH_KUZNYECHIK_MGM_S=0xC105,
    TLS_GOSTR341112_256_WITH_MAGMA_MGM_S=0xC106,
    TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256=0xCCA8,
    TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256=0xCCA9,
    TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256=0xCCAA,
    TLS_PSK_WITH_CHACHA20_POLY1305_SHA256=0xCCAB,
    TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256=0xCCAC,
    TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256=0xCCAD,
    TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256=0xCCAE,
    TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256=0xD001,
    TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384=0xD002,
    TLS_ECDHE_PSK_WITH_AES_128_CCM_8_SHA256=0xD003,
    TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256=0xD005,
};



} // namespace fbw

#endif // TLS_enums_hpp
