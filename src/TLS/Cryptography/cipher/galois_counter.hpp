//
//  galois_counter.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef galois_counter_hpp
#define galois_counter_hpp

#include <stdio.h>
#include "cipher_base.hpp"
#include "AES.hpp"

#include <vector>
#include <array>

namespace fbw::aes {



struct AES_GCM_SHA2_ctx {
    roundkey client_write_round_keys;
    roundkey server_write_round_keys;
    std::vector<uint8_t> client_implicit_write_IV;
    std::vector<uint8_t> server_implicit_write_IV;
    uint64_t seqno_server = 0;
    uint64_t seqno_client = 0;
    void set_server_key(const std::vector<uint8_t>& key, size_t key_size, size_t iv_size, const hash_base& hash_ctor);
    void set_client_key(const std::vector<uint8_t>& key, size_t key_size, size_t iv_size, const hash_base& hash_ctor);
};

class AES_128_GCM_SHA256 : public cipher_base_tls12 {
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t KEY_SIZE = 16;
    AES_GCM_SHA2_ctx ctx;
public:
    AES_128_GCM_SHA256() = default;
    void set_key_material_12(std::vector<uint8_t> material) override;
    tls_record protect(tls_record record) noexcept override;
    tls_record deprotect(tls_record record) override;
};

class AES_128_GCM_SHA256_tls13 : public cipher_base_tls13 {
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t KEY_SIZE = 16;
    AES_GCM_SHA2_ctx ctx;
public:
    AES_128_GCM_SHA256_tls13() = default;
    void set_server_traffic_key(const std::vector<uint8_t>& key) override;
    void set_client_traffic_key(const std::vector<uint8_t>& key) override;
    bool do_key_reset() override;
    tls_record protect(tls_record record) noexcept override;
    tls_record deprotect(tls_record record) override;
};

class AES_256_GCM_SHA384 : public cipher_base_tls13 {
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t KEY_SIZE = 32;
    AES_GCM_SHA2_ctx ctx;
public:
    AES_256_GCM_SHA384() = default;
    void set_server_traffic_key(const std::vector<uint8_t>& key) override;
    void set_client_traffic_key(const std::vector<uint8_t>& key) override;
    bool do_key_reset() override;
    tls_record protect(tls_record record) noexcept override;
    tls_record deprotect(tls_record record) override;
};

// QUIC packet-number-space AEAD context using AES-128-GCM + AES-128-ECB HP
// (RFC 9001 §5.3 and §5.4.3).  Used for Initial and Handshake spaces when
// the negotiated cipher suite is TLS_AES_128_GCM_SHA256.
struct quic_aes_128_gcm_ctx {
    static constexpr size_t KEY_SIZE = 16;
    static constexpr size_t IV_SIZE  = 12;
    static constexpr size_t TAG_SIZE = 16;

    void set_key(const std::vector<uint8_t>& key,
                 const std::vector<uint8_t>& iv,
                 const std::vector<uint8_t>& hp_key);

    // Result of removing header protection and AEAD-decrypting a long-header packet.
    struct deprotected {
        std::vector<uint8_t> plaintext;
        uint32_t packet_number {};
        uint8_t  pn_length {};
    };

    // Remove AES-128-ECB long-header protection then AEAD-decrypt.
    // header_bytes: raw on-wire bytes before raw_payload (for AAD construction).
    // Throws std::runtime_error on truncated input or AEAD tag mismatch.
    deprotected deprotect(const std::vector<uint8_t>& header_bytes,
                          uint8_t protected_first_byte,
                          const std::vector<uint8_t>& raw_payload) const;

    // AEAD-encrypt plaintext then apply AES-128-ECB long-header protection.
    // Returns the full on-wire packet bytes (header + encrypted payload).
    std::vector<uint8_t> protect(const std::vector<uint8_t>& header_bytes,
                                 uint32_t packet_number,
                                 uint8_t  pn_length,
                                 const std::vector<uint8_t>& plaintext) const;

private:
    roundkey             m_aead_rk; // precomputed AES key schedule for AEAD
    std::vector<uint8_t> m_iv;      // 12-byte nonce base
    roundkey             m_hp_rk;   // precomputed AES key schedule for HP
};

} // namespace fbw::aes

#endif // galois_counter_hpp
