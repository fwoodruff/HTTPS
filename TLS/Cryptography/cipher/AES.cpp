//
//  AES.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 03/09/2021.
//
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

#include "AES.hpp"
#include "global.hpp"

#include <cassert>
#include <stdint.h>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <vector>

// This performs AES encryption and decryption on 16 byte blocks of data, using 128 bit, 192 bit and 256 bit keys

namespace fbw::aes {

constexpr int Nb = 4;

void AddRoundKey(aes_block& b, const byte_word* const roundkey) noexcept;
void InvMixColumns(aes_block&) noexcept;
void InvShiftRows(aes_block&) noexcept;
void InvSubBytes(aes_block&) noexcept;
void MixColumns(aes_block&) noexcept;
void ShiftRows(aes_block&) noexcept;
void SubBytes(aes_block&) noexcept;

[[nodiscard]] roundkey key_expansion(const aeskey& AESkey);
[[nodiscard]] aes_block cipher(aes_block plaintext, const roundkey&) noexcept;
[[nodiscard]] aes_block InvCipher(aes_block ciphertext, const roundkey& roundkeys) noexcept;

// rotates left the bits of a byte e.g.  10001001 -> 00010011
// this is one of the steps in AES
constexpr uint8_t ROTL8(uint8_t x, int shift) {
    return (x << shift) | (x >> (8 - shift));
}

// AES has a reversible substitution step
constexpr std::array<uint8_t,256> SBOX = [](){
    // https://en.wikipedia.org/wiki/Rijndael_S-box
    std::array<uint8_t,256> sbox {0};
    uint8_t p = 1, q = 1;
    do {
        // multiply p by 3
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
        // divide q by 3 (equals multiplication by 0xf6)
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;
         
        // compute the affine transformation
        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
        sbox[p] = xformed ^ 0x63;
    } while (p != 1);

    // 0 is a special case since it has no inverse
    sbox[0] = 0x63;
    return sbox;
}();

// This inverts the array computed above
constexpr std::array<uint8_t,256> INVSBOX = [](){
    std::array<uint8_t,256> invsbox {0};
    for(int i = 0; i < 256; i++) {
        invsbox[SBOX[i]] = i;
    }
    return invsbox;
}();


// performs the SBOX substitution
void SubBytes(aes_block& state) noexcept {
    for(auto& val : state) {
        val = SBOX[val];
    }
}


// reverses the SBOX substitution
void InvSubBytes(aes_block& state) noexcept {
    for(auto& val : state) {
        val = INVSBOX[val];
    }
}

// performs the row rotation
void ShiftRows(aes_block& b) noexcept {
    std::array<uint8_t,Nb> temp {};
    for(int i = 1; i < 4; i++) {
        for(int j = 0; j < Nb; j++) {
            temp[j] = b[(4*(i+j)+i)%(4*Nb)];
        }
        for(int j = 0; j < 4; j++) {
            b[i + 4*j] = temp[j];
        }
    }
}

// inverts the row rotation
void InvShiftRows(aes_block& b) noexcept {
    std::array<uint8_t,Nb> temp {};
    for(int i = 1; i < 4; i++) {
        for(int j = 0; j < Nb; j++) {
            temp[j] = b[(4*((Nb-i)+j)+i)%(4*Nb)];
        }
        for(int j = 0; j < 4; j++) {
            b[i + 4*j] = temp[j];
        }
    }
}

// performs all Galois field multiplications at runtime
constexpr uint8_t GMul_explicit(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if ((b & 1) != 0) {
            p ^= a;
        }
        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }
    return p;
}


// Caches the Galois field multiplications and retrieves from the cache
constexpr auto GMULRES = []() {
    std::array<std::array<uint8_t,256>,16> resa {{}};
    for(int i = 0; i < 16; i++) {
        for(int j = 0; j < 256; j++) {
            resa[i][j] = GMul_explicit(i,j);
        }
    }
    return resa;
}();
uint8_t GMul(uint8_t a, uint8_t b) {
    assert(a < 16);
    // I moved the table outside of function scope.
    // Without optimisation flags the compiler was copying
    // the whole table every call
    // which was inconvenient for debug performance
    return GMULRES[a][b];
}


// Used in the mix columns function
void mult_columns(aes_block& b, std::array<uint8_t,4> a) {
    for (int c = 0; c < Nb; c++) {
        std::array<uint8_t,4> col {0};
        for(int j = 0; j < 4; j++) {
            for(int k = 0; k < 4; k++) {
                col[j] ^= GMul(a[(3-j+k)%4], b[c*4 + k]);
            }
        }
        for(int j = 0; j < 4; j++) {
            b[c*Nb + j] = col[j];
        }
    }
}

// Mix columns is the Galois field multiplication of each column in an AES block
void MixColumns(aes_block& b) noexcept {
    mult_columns(b, {3,1,1,2});
}

// reverses the Mix column function.
void InvMixColumns(aes_block& b) noexcept {
    mult_columns(b, {11,13,9,14});
}

// xor a round key with the block
void AddRoundKey(aes_block& b, const byte_word* const roundkey) noexcept {
    for(int i = 0; i < Nb; i++) {
        for(int j = 0; j < 4; j++) {
            b[i + j*Nb] ^= roundkey[j][i];
        }
    }
}

// Round constants used in the key expansion
constexpr auto Rcon = [](){
    std::array<uint8_t,32> res {0};
    uint8_t c = 1;
    for(int i = 1; i < 32; i ++) {
        res[i] = c;
        c = GMul_explicit(2, c);
    }
    return res;
}();

// converts a secure key into a large random value (with the same entropy as the input key)
// each of the keys is used at each AES round
roundkey aes_key_schedule(const aeskey& AESkey) {
    roundkey keybytes;
    keybytes.resize(28 + AESkey.size());

    const ssize_t Nka = AESkey.size()/4;
    const ssize_t Nra = Nka + 6;
    
    for(int i = 0; i < Nka; i++) {
        for(int j = 0; j < 4; j++) {
            keybytes[i][j] = AESkey[4*i +j];
        }
    }
    for(ssize_t i = Nka; i < Nb * (Nra+1); i++) {
        byte_word temp {};
        temp = keybytes[i-1];
        assert( Nka != 0);
        if (i % Nka == 0) {
            std::rotate(temp.begin(), &temp[1], temp.end());
            std::transform(temp.cbegin(), temp.cend(), temp.begin(), [](uint8_t c) { return SBOX[c]; });
            temp[0] ^= Rcon[i/Nka];
        } else if (Nka > 6 and i % Nka == 4) {
            std::transform(temp.cbegin(), temp.cend(), temp.begin(), [](uint8_t c) { return SBOX[c]; });
        }
        const auto& kb = keybytes[i-Nka];
        std::transform(kb.cbegin(), kb.cend(), temp.cbegin(), keybytes[i].begin(), std::bit_xor<uint8_t>());
    }
    return keybytes;
}


// performs the encryption on a block
aes_block aes_encrypt(aes_block plain_block, const roundkey& roundkeys) noexcept {
    static_assert(Nb == 4, "bad AES block size");
    const ssize_t Nra = roundkeys.size()/Nb - 1;
    
    AddRoundKey(plain_block, &roundkeys[0]);
    for (int i = 1; i < Nra; i++) {
        SubBytes(plain_block);
        ShiftRows(plain_block);
        MixColumns(plain_block);
        AddRoundKey(plain_block, &roundkeys[Nb*i]);
    }
    SubBytes(plain_block);
    ShiftRows(plain_block);
    AddRoundKey(plain_block, &roundkeys[Nb*Nra]);
    return plain_block;
}


aes_block aes_decrypt(aes_block ciphertext, const roundkey& roundkeys) noexcept {
    const ssize_t Nra = roundkeys.size()/4 - 1;

    AddRoundKey(ciphertext, &roundkeys[Nb*Nra]);
    for (ssize_t i = Nra-1; i >= 1; i--) {
        InvShiftRows(ciphertext);
        InvSubBytes(ciphertext);
        AddRoundKey(ciphertext, &roundkeys[Nb*i]);
        InvMixColumns(ciphertext);
    }
    InvShiftRows(ciphertext);
    InvSubBytes(ciphertext);
    AddRoundKey(ciphertext, &roundkeys[0]);
    return ciphertext;
}

} // namespace fbw::aes
