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

} // namespace fbw


#endif // chacha20poly1305_hpp
