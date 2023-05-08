//
//  secp256r1.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 08/08/2021.
//

#ifndef secp256r1_hpp
#define secp256r1_hpp

#include "global.hpp"

#include <array>
#include <string>

namespace fbw::secp256r1 {

// Signs the message digest with the certificates privte key and a secret random number
[[nodiscard]] ustring DER_ECDSA(
                     std::array<uint8_t,32> k_random,
                     std::array<uint8_t,32> digest,
                      std::array<uint8_t,32> private_key);

// converts a private key to a public key
// Similar to x25519 base_multiply
[[nodiscard]] std::array<uint8_t,65> get_public_key(std::array<uint8_t,32> private_key) noexcept;

}

#endif // secp256r1_hpp
