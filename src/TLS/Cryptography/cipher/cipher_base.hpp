//
//  cipher_base.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef cipher_base_hpp
#define cipher_base_hpp

#include "../../../global.hpp"
#include "../../TLS_enums.hpp"
#include "../key_derivation.hpp"

#include <cstdio>

namespace fbw {
class cipher_base {
    // A cipher is chosen in TLS Handshake Hello.
    // Ciphers share an interface
public:
    virtual void set_key_material_12(ustring material) = 0;
    virtual void set_key_material_13_handshake(const key_schedule& key_sche) {};
    virtual void set_key_material_13_application(const key_schedule& key_sche) {};
    virtual tls_record encrypt(tls_record record) noexcept = 0;
    virtual tls_record decrypt(tls_record record) = 0;
    virtual ~cipher_base() noexcept = default;
    cipher_base() = default;
    cipher_base(const cipher_base& other) = default; // rule of 3
    cipher_base& operator=(const cipher_base& other) = default;
};
} // namespace fbw

#endif // cipher_base_hpp
