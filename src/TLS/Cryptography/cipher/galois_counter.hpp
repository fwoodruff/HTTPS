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


class AES_128_GCM_SHA256 : public cipher_base_tls12 {
    roundkey client_write_round_keys;
    roundkey server_write_round_keys;
    ustring client_implicit_write_IV;
    ustring server_implicit_write_IV;
    uint64_t seqno_server = 0;
    uint64_t seqno_client = 0;
public:
    AES_128_GCM_SHA256() = default;
    void set_key_material_12(ustring material) override;
    tls_record encrypt(tls_record record) noexcept override;
    tls_record decrypt(tls_record record) override;
};

} // namespace fbw

#endif // galois_counter_hpp
