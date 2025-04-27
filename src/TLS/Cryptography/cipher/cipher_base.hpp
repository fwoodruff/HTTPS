//
//  cipher_base.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef cipher_base_hpp
#define cipher_base_hpp

#include "../../../global.hpp"
#include "../../TLS_utils.hpp"
#include "../key_derivation.hpp"

#include <cstdio>

namespace fbw {
class cipher_base {
    // A cipher is chosen in TLS Handshake Hello.
    // Ciphers share an interface
public:
    virtual tls_record protect(tls_record record) noexcept = 0;
    virtual tls_record deprotect(tls_record record) = 0;
    virtual ~cipher_base() noexcept = default;
};

class cipher_base_tls12 : public cipher_base {
public:
    virtual void set_key_material_12(std::vector<uint8_t> material) = 0;
};

class cipher_base_tls13 : public cipher_base {
public:
    virtual void set_server_traffic_key(const std::vector<uint8_t>& key) = 0;
    virtual void set_client_traffic_key(const std::vector<uint8_t>& key) = 0;
    virtual bool do_key_reset() { return false; }
};



tls_record wrap13(tls_record record);
tls_record unwrap13(tls_record record);
std::vector<uint8_t> make_additional_13(const std::vector<uint8_t>& record, size_t tag_size);

} // namespace fbw


#endif // cipher_base_hpp
