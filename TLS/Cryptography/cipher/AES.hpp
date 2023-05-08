//
//  AES.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 03/09/2021.
//

#ifndef AES_hpp
#define AES_hpp

#include <cstdio>
#include <array>
#include <vector>
#include <cstdint>

namespace fbw::aes {

using byte_word  = std::array<uint8_t,4>;
using aes_block = std::array<uint8_t, 16>;

using roundkey = typename std::vector<byte_word>;
using aeskey = typename std::vector<uint8_t>;


[[nodiscard]] roundkey aes_key_schedule(const aeskey& AESkey);

// used by the AES-GCM and AES-CBC ciphers (and others)
// to encrypt blocks of text. The same plain text will always
// generate the same cipher text for a given AES key
[[nodiscard]] aes_block aes_encrypt(aes_block plaintext, const roundkey& roundkeys) noexcept;

[[nodiscard]] aes_block aes_decrypt(aes_block ciphertext, const roundkey& roundkeys) noexcept;


} // namespace fbw




#endif /* AES_hpp */
