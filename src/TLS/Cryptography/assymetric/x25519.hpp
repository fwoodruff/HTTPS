//
//  x25519.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 08/08/2021.
//

#ifndef curve25519_hpp
#define curve25519_hpp

#include <array>

// Performs elliptic curve Diffie Hellman

// get secret
namespace fbw::curve25519 {

constexpr size_t PUBKEY_SIZE = 32;
constexpr size_t PRIVKEY_SIZE = 32;
constexpr size_t SECRET_SIZE = 32;

[[nodiscard]] std::array<unsigned char, SECRET_SIZE>
    multiply(std::array<unsigned char, PRIVKEY_SIZE> num,
                                  std::array<unsigned char, PUBKEY_SIZE> pnt) noexcept;
// make key pair
[[nodiscard]] std::array<unsigned char, PUBKEY_SIZE>
    base_multiply(std::array<unsigned char, PRIVKEY_SIZE> num) noexcept;

}

#endif // curve25519_hpp
