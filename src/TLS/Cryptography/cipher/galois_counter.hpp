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
    ustring client_implicit_write_IV;
    ustring server_implicit_write_IV;
    uint64_t seqno_server = 0;
    uint64_t seqno_client = 0;
    void set_server_key(const ustring& key, size_t key_size, size_t iv_size, const hash_base& hash_ctor);
    void set_client_key(const ustring& key, size_t key_size, size_t iv_size, const hash_base& hash_ctor);
};

class AES_128_GCM_SHA256 : public cipher_base_tls12 {
    static constexpr size_t TAG_SIZE = 16;
    static constexpr size_t IV_SIZE = 12;
    static constexpr size_t KEY_SIZE = 16;
    AES_GCM_SHA2_ctx ctx;
public:
    AES_128_GCM_SHA256() = default;
    void set_key_material_12(ustring material) override;
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
    void set_server_traffic_key(const ustring& key) override;
    void set_client_traffic_key(const ustring& key) override;
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
    void set_server_traffic_key(const ustring& key) override;
    void set_client_traffic_key(const ustring& key) override;
    bool do_key_reset() override;
    tls_record protect(tls_record record) noexcept override;
    tls_record deprotect(tls_record record) override;
};


} // namespace fbw

#endif // galois_counter_hpp
