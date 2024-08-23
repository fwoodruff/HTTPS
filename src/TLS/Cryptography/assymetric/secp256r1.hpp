//
//  secp256r1.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 08/08/2021.
//

#ifndef secp256r1_hpp
#define secp256r1_hpp

#include "../../../global.hpp"

#include <array>
#include <string>

namespace fbw::secp256r1 {

// Signs the message digest with the certificates privte key and a secret random number in DER encoded format
[[nodiscard]] ustring DER_ECDSA(
                     std::array<uint8_t,32> k_random,
                     std::array<uint8_t,32> digest,
                      std::array<uint8_t,32> private_key);

// converts a private key to a public key
// Similar to x25519 base_multiply
[[nodiscard]] std::array<uint8_t,65> get_public_key(const std::array<uint8_t,32>& private_key) noexcept;

[[nodiscard]] std::array<unsigned char, 65>
    multiply(const std::array<unsigned char,32>& private_key,
                                  const std::array<unsigned char, 65>& peer_public_key) noexcept;

}

#endif // secp256r1_hpp
