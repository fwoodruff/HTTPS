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

constexpr size_t PUBKEY_SIZE = 65;
constexpr size_t PRIVKEY_SIZE = 32;
constexpr size_t SECRET_SIZE = 32;

// Signs the message digest with the certificates privte key and a secret random number in DER encoded format
[[nodiscard]] ustring DER_ECDSA(
                     std::array<uint8_t,32> k_random,
                     std::array<uint8_t, 32> digest,
                      std::array<uint8_t, PRIVKEY_SIZE> private_key);

// converts a private key to a public key
// Similar to x25519 base_multiply
[[nodiscard]] std::array<uint8_t, PUBKEY_SIZE> get_public_key(std::array<uint8_t, PRIVKEY_SIZE> private_key) noexcept;

[[nodiscard]] std::array<unsigned char, SECRET_SIZE>
    multiply(const std::array<unsigned char, PRIVKEY_SIZE>& private_key,
                                  const std::array<unsigned char, PUBKEY_SIZE>& peer_public_key) noexcept;

}

#endif // secp256r1_hpp
