//
//  secure_hash.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//


#include "sha2.hpp"
#include "../../../global.hpp"

#include <array>
#include <algorithm>
#include <iostream>
#include <cmath>
#include <iomanip>
#include <climits>
#include <cassert>
#include <vector>
#include <string>

namespace fbw {


template<typename T>
T rotate_right(T a, size_t b) noexcept {
    size_t m = CHAR_BIT * sizeof(T);
    assert(b < m);
    return (a >> b) | (a << (m - b));
}

template<typename T>
T CH(T x, T y, T z) noexcept {
    return (x & y) ^ (~x & z);
}
template<typename T>
T MAJ(T x, T y, T z) noexcept {
    return (x & y) ^ (x & z) ^ (y & z);
}

uint32_t EP0(uint32_t x) noexcept {
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22);
}

uint32_t EP1(uint32_t x) noexcept {
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25);
}

uint32_t SIG0(uint32_t x) noexcept {
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3);
}

uint32_t SIG1(uint32_t x) noexcept {
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10);
}

uint64_t EP0(uint64_t x) noexcept {
    return rotate_right(x, 28) ^ rotate_right(x, 34) ^ rotate_right(x, 39);
}

uint64_t EP1(uint64_t x) noexcept {
    return rotate_right(x, 14) ^ rotate_right(x, 18) ^ rotate_right(x, 41);
}

uint64_t SIG0(uint64_t x) noexcept {
    return rotate_right(x,  1) ^ rotate_right(x,  8) ^ (x >> 7);
}
uint64_t SIG1(uint64_t x) noexcept {
    return rotate_right(x, 19) ^ rotate_right(x, 61) ^ (x >> 6);
}

consteval double sq_root(double x) noexcept {
    assert(x >= 0);
    constexpr double small = 9 * std::numeric_limits<double>::epsilon();
    double guess = 1;
    double diff = 1;
    while(diff > small or diff < -small) {
        double root = 0.5 * (guess + x/guess);
        diff = guess - root;
        guess = root;
    }
    return guess;
}

/*
constexpr std::array<uint64_t,8> prime_sqrts { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
*/
constexpr std::array<uint64_t,80> prime_cbrts {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
    0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
    0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
    0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
    0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
    0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};


template<typename RADIX, size_t BLOCK_SIZE, size_t INTERNAL_STATE_SIZE>
void sha2_transform(std::array<RADIX, 8 >& state, const std::array<uint8_t, BLOCK_SIZE>& data) noexcept {
    std::array<RADIX, INTERNAL_STATE_SIZE> m{};
    constexpr auto init_blocks = BLOCK_SIZE/sizeof(RADIX);
    for(size_t i = 0; i < init_blocks; i++) {
        auto idx = i * sizeof(RADIX);
        for(size_t j = 0; j < sizeof(RADIX); j++) {
            m[i] |= RADIX(data[idx + j]) << ((CHAR_BIT * (sizeof(RADIX) - 1)) - (j * CHAR_BIT));
        }
    }
    for(size_t i = init_blocks; i < INTERNAL_STATE_SIZE; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    auto vars = state;
    for(size_t i = 0; i < INTERNAL_STATE_SIZE; i++) {
        RADIX k = prime_cbrts[i] >> ((sizeof(prime_cbrts[0]) - sizeof(RADIX))*CHAR_BIT);
        RADIX t1 = vars[7] + EP1(vars[4]) + CH(vars[4], vars[5], vars[6]) + k + m[i];
        RADIX t2 = EP0(vars[0]) + MAJ(vars[0], vars[1], vars[2]);
        for(int j = 7; j > 0; j--) {
            vars[j] = vars[j-1];
        }
        vars[4] += t1;
        vars[0] = t1 + t2;
    }
    for(int i = 0; i < 8; i ++) {
        state[i] += vars[i];
    }
}

template<typename RADIX, size_t BLOCK_SIZE, size_t HASH_SIZE, size_t COUNTER_SIZE, size_t INTERNAL_STATE_SIZE>
std::vector<uint8_t> hash_impl(std::array<uint8_t, BLOCK_SIZE> data, std::array<RADIX, 8> state, uint64_t bitlen, size_t datalen) {
    bitlen += datalen * CHAR_BIT;
    std::vector<uint8_t> hash;
    hash.resize(HASH_SIZE);
    data[datalen] = 0x80;
    datalen++;

    constexpr auto last_block_size = BLOCK_SIZE - COUNTER_SIZE;
    if(datalen > last_block_size) {
        sha2_transform<RADIX, BLOCK_SIZE, INTERNAL_STATE_SIZE> (state, data);
        std::fill(data.begin(), data.end(), 0);
    }
    checked_bigend_write(bitlen, data, BLOCK_SIZE - sizeof(uint64_t), sizeof(uint64_t));
    sha2_transform<RADIX, BLOCK_SIZE, INTERNAL_STATE_SIZE> (state, data);

    for(size_t i = 0; i < HASH_SIZE/ sizeof(RADIX); i ++) {
        for(size_t j = 0; j < sizeof(RADIX); j++) {
            hash[i * sizeof(RADIX) + j] = state[i] >> ((sizeof(RADIX) - 1 - j) * CHAR_BIT);
        }
    }
    return hash;
}



void sha384_transform(std::array<uint64_t,8>& state, const std::array<uint8_t, sha384::block_size> data) noexcept {
    return sha2_transform<uint64_t, sha384::block_size, 80>(state, data);
}

void sha256_transform(std::array<uint32_t,8>& state, const std::array<uint8_t,sha256::block_size> data) noexcept {
    return sha2_transform<uint32_t, sha256::block_size, 64>(state, data);
}



template<typename RADIX, size_t BLOCK_SIZE, size_t HASH_SIZE, size_t INTERNAL_STATE_SIZE>
void update_internal(std::array<uint8_t, BLOCK_SIZE>& data, std::array<RADIX, 8>& state, uint64_t& bitlen, size_t& datalen, 
        const uint8_t* const begin, size_t size) {

    for (size_t i = 0; i < size; ++i) {
        assert(datalen < data.size());
        data[datalen] = begin[i];
        ++datalen;
        if (datalen == BLOCK_SIZE) {
            sha2_transform<RADIX, BLOCK_SIZE, INTERNAL_STATE_SIZE>(state, data);
            bitlen += CHAR_BIT * BLOCK_SIZE;
            datalen = 0;
            std::fill(data.begin(), data.end(),0);
        }
    }
}

sha256& sha256::update_impl(const uint8_t* const begin, size_t size) noexcept {
    update_internal<uint32_t, block_size, hash_size, 64>(m_data, state, bitlen, datalen, begin, size);
    return *this;
}

sha384& sha384::update_impl(const uint8_t* const begin, size_t size) noexcept {
    update_internal<uint64_t, block_size, hash_size, 80>(m_data, state, bitlen, datalen, begin, size);
    return *this;
}

[[nodiscard]] size_t sha384::get_block_size() const noexcept {
    return sha384::block_size;
}
[[nodiscard]] size_t sha384::get_hash_size() const noexcept {
    return sha384::hash_size;
}

std::unique_ptr<hash_base> sha384::clone() const {
    return std::make_unique<sha384>(*this);
}

size_t sha256::get_block_size() const noexcept {
    return block_size;
}

size_t sha256::get_hash_size() const noexcept {
    return hash_size;
}

std::unique_ptr<hash_base> sha256::clone() const {
    return std::make_unique<sha256>(*this);
}

sha384::sha384() noexcept {
    state = {
        0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
        0x9159015a3070dd17, 0x152fecd8f70e5939,
        0x67332667ffc00b31, 0x8eb44a8768581511,
        0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
    };
    m_data.fill(0);
}

sha256::sha256() noexcept  : datalen(0),  bitlen(0), m_data() {
    constexpr auto state0 = []() consteval {
        int idx = 0;
        std::array<uint32_t,8> kl {};
        for (int i = 2; i <= 19; i++) {
            bool flag = true;
            for (int j = 2; j <= i / 2; ++j) {
                if (i % j == 0) {
                    flag = false;
                    break;
                }
            }
            if (flag) {
                auto x = sq_root(i);
                kl[idx++] = unsigned((x - unsigned(x))*(1ULL<<32 ));
            }
        }
        return kl;

    }();
    state = state0;
}

std::vector<uint8_t> sha384::hash() const {
    return hash_impl<uint64_t, 128, 48, 16, 80>(m_data, state, bitlen, datalen);
}

std::vector<uint8_t> sha256::hash() const {
    return hash_impl<uint32_t, 64, 32, 8, 64>(m_data, state, bitlen, datalen);
}

} // namespace fbw


