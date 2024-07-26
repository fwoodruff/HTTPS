//
//  block_chain.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 12/12/2021.
//

#ifndef block_chain_hpp
#define block_chain_hpp

#include "AES.hpp"
#include "cipher_base.hpp"
#include "../../../global.hpp"

#include <vector>
#include <stdio.h>

namespace fbw::aes {

class AES_CBC_SHA : public cipher_base {
private:
    roundkey server_write_round_keys;
    roundkey client_write_round_keys;
    std::array<uint8_t, 20> server_MAC_key;
    std::array<uint8_t, 20> client_MAC_key;

    uint64_t seqno_server;
    uint64_t seqno_client;
    
public:
    AES_CBC_SHA();
    
    void set_key_material_12(ustring material) override;
    tls_record encrypt(tls_record record) noexcept override;
    tls_record decrypt(tls_record record) override;
};

} // namespace fbw

#endif // block_chain_hpp
