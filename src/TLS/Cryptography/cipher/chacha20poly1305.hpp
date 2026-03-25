//
//  chacha20poly1305.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 12/02/2022.
//

#ifndef chacha20poly1305_hpp
#define chacha20poly1305_hpp

#include <stdio.h>
#include <span>

#include "cipher_base.hpp"
#include "../key_derivation.hpp"

#include <vector>
#include <array>

namespace fbw::cha {

constexpr size_t TAG_SIZE = 16;
constexpr size_t IV_SIZE = 12;
constexpr size_t KEY_SIZE = 32;

struct ChaCha20_Poly1305_ctx {
    std::array<uint8_t, KEY_SIZE> client_write_key;
    std::array<uint8_t, KEY_SIZE> server_write_key;
    std::array<uint8_t, IV_SIZE> client_implicit_write_IV;
    std::array<uint8_t, IV_SIZE> server_implicit_write_IV;
    uint64_t seqno_server = 0;
    uint64_t seqno_client = 0;
    std::vector<uint8_t> encrypt(const std::span<uint8_t> plaintext, const std::vector<uint8_t>& additional_data);
    std::vector<uint8_t> decrypt(std::vector<uint8_t> ciphertext, const std::vector<uint8_t>& additional_data);
};

class ChaCha20_Poly1305_tls13 : public cipher_base_tls13 {
private:
    ChaCha20_Poly1305_ctx ctx;
public:
    ChaCha20_Poly1305_tls13() = default;
    void set_server_traffic_key(const std::vector<uint8_t>& key) override;
    void set_client_traffic_key(const std::vector<uint8_t>& key) override;
    bool do_key_reset() override;
    tls_record protect(tls_record record) noexcept override;
    tls_record deprotect(tls_record record) override;
};

class ChaCha20_Poly1305_tls12 : public cipher_base_tls12 {
private:
    ChaCha20_Poly1305_ctx ctx;
public:
    ChaCha20_Poly1305_tls12() = default;
    void set_key_material_12(std::vector<uint8_t> material) override;
    tls_record protect(tls_record record) noexcept override;
    tls_record deprotect(tls_record record) override;
};

// QUIC packet-number-space AEAD context using ChaCha20-Poly1305 + ChaCha20 HP
// (RFC 9001 §5.3 and §5.4.4).  Used when the negotiated cipher suite is
// TLS_CHACHA20_POLY1305_SHA256.
struct quic_chacha20_poly1305_ctx {
    static constexpr size_t KEY_SIZE = 32;
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

    // Remove ChaCha20 long-header protection then AEAD-decrypt.
    // Throws std::runtime_error on truncated input or Poly1305 tag mismatch.
    deprotected deprotect(const std::vector<uint8_t>& header_bytes,
                          uint8_t protected_first_byte,
                          const std::vector<uint8_t>& raw_payload) const;

    // AEAD-encrypt plaintext then apply ChaCha20 long-header protection.
    // Returns the full on-wire packet bytes (header + encrypted payload).
    std::vector<uint8_t> protect(const std::vector<uint8_t>& header_bytes,
                                 uint32_t packet_number,
                                 uint8_t  pn_length,
                                 const std::vector<uint8_t>& plaintext) const;

private:
    std::array<uint8_t, KEY_SIZE> m_key {};
    std::array<uint8_t, IV_SIZE>  m_iv {};
    std::array<uint8_t, KEY_SIZE> m_hp_key {};
};

} // namespace fbw::cha


#endif // chacha20poly1305_hpp
