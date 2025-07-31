//
//  x25519mlkem768.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 20/07/2025.
//

#ifndef xlkem_hpp
#define xlkem_hpp

#include "mlkem.hpp"
#include "x25519.hpp"
#include <array>


namespace fbw::xkem {

    constexpr int32_t pub_key_size = mlkem::dk768size + curve25519::PUBKEY_SIZE;
    constexpr int32_t priv_key_size = mlkem::ek768size + curve25519::PRIVKEY_SIZE;
    constexpr int32_t ciphertext_size = mlkem::ciphertext768size + curve25519::PUBKEY_SIZE;
    constexpr int32_t shared_secret_size = mlkem::seed_len + curve25519::PUBKEY_SIZE;
    
    using pubkey = std::array<uint8_t, pub_key_size>;
    using privkey = std::array<uint8_t, priv_key_size>;
    using ciphertext = std::array<uint8_t, ciphertext_size>;
    using shared_secret = std::array<uint8_t, shared_secret_size>;

    shared_secret process_client_keyshare(pubkey pub);


}

#endif