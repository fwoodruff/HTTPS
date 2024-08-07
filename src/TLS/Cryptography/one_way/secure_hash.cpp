//
//  secure_hash.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//


#include "secure_hash.hpp"
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
T rotate_left(T a,  size_t b) noexcept {
    size_t m = CHAR_BIT * sizeof(T);
    assert(b < m);
    return (a << b) | (a >> (m - b));
}

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

constexpr double sq_root(double x) noexcept {
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


// todo: combine sha256 and sha384 transforms
void sha384_transform(std::array<uint64_t,8>& state, const std::array<uint8_t, sha384::block_size> data) noexcept {
    std::array<uint64_t, 80> m;
    for (int i = 0, j = 0; i < 16; ++i, j += 8) {
        m[i] = (uint64_t(data[j  ]) << 56) | (uint64_t(data[j + 1]) << 48) | (uint64_t(data[j + 2]) << 40) | (uint64_t(data[j + 3]) << 32) |
               (uint64_t(data[j+4]) << 24) | (uint64_t(data[j + 5]) << 16) | (uint64_t(data[j + 6]) << 8 ) | (uint64_t(data[j + 7]));
    }
    for (int i = 16 ; i < 80; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    auto vars = state;
    for (int i = 0; i < 80; ++i) {
        uint64_t t1 = vars[7] + EP1(vars[4]) + CH(vars[4], vars[5], vars[6]) + prime_cbrts[i] + m[i];
        uint64_t t2 = EP0(vars[0]) + MAJ(vars[0], vars[1], vars[2]);
        for(int i = 7; i >0; i--) {
            vars[i] = vars[i-1];
        }
        vars[4] += t1;
        vars[0] = t1 + t2;
    }
    for(int i = 0; i < 8; i ++) {
        state[i] += vars[i];
    }
}

constexpr long double cube_root(long double x) noexcept { // todo: check if long double is sufficient
    // annoyingly this doesn't give enough precision for SHA384 so we have to hard code those...
    assert(x >= 0);
    constexpr double small = 9*std::numeric_limits<double>::epsilon();
    double guess = 1;
    double diff = 1;
    while(diff > small or diff < -small) {
        double root = (2 * guess + x/(guess*guess))/ 3;
        diff = guess - root;
        guess = root;
    }
    return guess;
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

sha384& sha384::update_impl(const uint8_t* const begin, size_t size) noexcept {
    for (size_t i = 0; i < size; ++i) {
        assert(datalen < m_data.size());
        m_data[datalen] = begin[i];
        ++datalen;
        if (datalen == 128) {
            sha384_transform(state, m_data);
            bitlen += 1024;
            datalen = 0;
            std::fill(m_data.begin(), m_data.end(),0);
        }
    }
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



sha256::sha256() noexcept  : datalen(0),  bitlen(0), m_data(), done(false) {
    constexpr auto state0 = [](){
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

ustring sha384::hash() const {
    auto o_data = m_data;
    auto o_state = state;
    auto o_bitlen = bitlen;

    assert(!done);
    ustring hash;
    hash.resize(48);

    size_t dlen = datalen;
    assert(dlen < m_data.size());
    o_data[dlen] = 0x80;
    ++dlen;
    while (dlen < 112) {
        assert(dlen < o_data.size());
        o_data[dlen] = 0x00;
        ++dlen;
    }
    if (datalen >= 112) {
        sha384_transform(o_state, o_data);
        std::fill(o_data.begin(),o_data.end(),0);
    }
    o_bitlen += datalen * CHAR_BIT;
    for (size_t i = 0; i < sizeof(o_bitlen); ++i) {
        o_data[127 - i] = o_bitlen >> (CHAR_BIT * i);
    }
    sha384_transform(o_state, o_data);

    for (size_t i = 0; i < CHAR_BIT; ++i) {
        for (size_t j = 0; j < 6; ++j) {
            hash[i + j*sizeof(o_state[0])] = (o_state[j] >> (56 - i * CHAR_BIT)) & 0xff;
        }
    }
    return hash;
}


void sha256_transform(std::array<uint32_t,8>& state, const std::array<uint8_t,64> data) noexcept {
    static constexpr std::array<uint32_t,64> k = [](){
        int idx = 0;
        std::array<uint32_t,64> kl {};
        for (int i = 2; i <= 311; i++) {
            bool flag = true;
            for (int j = 2; j <= i / 2; ++j) {
                if (i % j == 0) {
                    flag = false;
                    break;
                }
            }
            if (flag) {
                auto x = cube_root(i);
                kl[idx++] = static_cast<uint32_t>((x - static_cast<uint32_t>(x)) * (1ULL << 32));
            }
        }
        return kl;
    }();
    std::array<uint32_t, 64> m {};
    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (uint32_t(data[j]) << 24) | (uint32_t(data[j + 1]) << 16) | (uint32_t(data[j + 2]) << 8) | (uint32_t(data[j + 3]));
    }
    for (int i = 16 ; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    auto vars = state;
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = vars[7] + EP1(vars[4]) + CH(vars[4], vars[5], vars[6]) + k[i] + m[i];
        uint32_t t2 = EP0(vars[0]) + MAJ(vars[0], vars[1], vars[2]);
        for(int i = 7; i >0; i--) {
            vars[i] = vars[i-1];
        }
        vars[4] += t1;
        vars[0] = t1 + t2;
    }
    for(int i = 0; i < 8; i ++) {
        state[i] += vars[i];
    }
}

sha256& sha256::update_impl(const uint8_t* const begin, size_t size) noexcept {
    for (size_t i = 0; i < size; ++i) {
        assert(datalen < m_data.size());
        m_data[datalen] = begin[i];
        ++datalen;
        if (datalen == 64) {
            sha256_transform(state, m_data);
            bitlen += 512;
            datalen = 0;
        }
    }
    return *this;
}


ustring sha256::hash() const{
    // todo: complex logic, should add comments and better name variables

    auto o_data = m_data;
    auto o_state = state;
    auto o_bitlen = bitlen;
    assert(!done);
    ustring hash;
    hash.resize(32);
    size_t dlen = datalen;
    assert(dlen < o_data.size());
    o_data[dlen] = 0x80;
    ++dlen;
    while (dlen < 56) {
        assert(dlen < o_data.size());
        o_data[dlen] = 0x00;
        ++dlen;
    }
    if (datalen >= 56) {
        sha256_transform(o_state, o_data);
        static_assert(decltype(o_data)().size() == 64, "bad context");
        std::fill_n(o_data.begin(),56,0);
    }
    o_bitlen += datalen * sizeof(o_bitlen);
    for(size_t i = 0; i < sizeof(o_bitlen); i++) {
        assert(i <= 63);
        o_data[63-i] = o_bitlen >> (CHAR_BIT * i);
    }
    sha256_transform(o_state, o_data);
    for (size_t i = 0; i < sizeof(o_state[0]); ++i) {
        for(size_t j = 0; j < CHAR_BIT; j++) {
            assert(i + j*sizeof(o_state[0]) < hash.size());
            assert(24 >= i * CHAR_BIT);
            hash[i + j*sizeof(o_state[0])] = (o_state[j] >> (24 - i * CHAR_BIT)) & 0xff;
        }
    }
    return hash;
}



// used in CBC mode
sha1::sha1() : datalen(0), m_data({}), done(false) {
    m_state[0] = 0x67452301;
    m_state[1] = 0xEFCDAB89;
    m_state[2] = 0x98BADCFE;
    m_state[3] = 0x10325476;
    m_state[4] = 0xC3D2E1F0;
}

void sha1_transform(std::array<uint32_t,5>& state, std::array<uint8_t,64>& data) {
    std::array<uint32_t,80> w;
    for(int i = 0; i < 16; i++) {
        w[i] = static_cast<uint32_t>(try_bigend_read(data, i * 4, 4));
    }
    for (int i = 16; i < 80; i++) {
        w[i] = rotate_left((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
    }

    auto a = state[0];
    auto b = state[1];
    auto c = state[2];
    auto d = state[3];
    auto e = state[4];
    for (int i = 0 ; i < 80; i ++) {
        uint32_t f, k;
        switch(i/20) {
            case 0:
                f = (b & c) | (~b & d);
                k = 0x5A827999;
                break;
            case 1:
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
                break;
            case 2:
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
                break;
            case 3:
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
                break;
            default:
                assert (false);
        }
        auto temp = rotate_left(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotate_left(b, 30);
        b = a;
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    data = {0};
}

sha1& sha1::update_impl(const uint8_t* const data, size_t size) noexcept {
    for(size_t i = 0; i < size; i++) {
        m_data[datalen % block_size] = data[i];
        datalen++;
        if(datalen % block_size == 0) {
            sha1_transform(m_state, m_data);
        }
    }
    
    return *this;
}


ustring sha1::hash() const {
    assert(!done);
    auto o_data = m_data;
    auto o_state = m_state;

    o_data[datalen%block_size] = 0x80;
    
    if(datalen%block_size >= 56) {
        sha1_transform(o_state,o_data);
    }
    checked_bigend_write(datalen * 8, o_data, 56, 8);
    sha1_transform(o_state, o_data);
    ustring hash;
    hash.resize(20);
    for(int i = 0; i < 5; i ++) {
        checked_bigend_write(o_state[i], hash, i*4, 4);
    }
    return hash;
}

size_t sha1::get_block_size() const noexcept {
    return block_size;
}

size_t sha1::get_hash_size() const noexcept {
    return hash_size;
}

std::unique_ptr<hash_base> sha1::clone() const {
    return std::make_unique<sha1>(*this);
}

size_t hmac::get_block_size() const noexcept {
    return m_hasher->get_block_size();
}

size_t hmac::get_hash_size() const noexcept {
    return m_hasher->get_block_size();
}

ustring hmac::hash() const {
    std::vector<uint8_t> opadkey;
    opadkey.resize(m_factory->get_block_size());
    std::transform(KeyPrime.cbegin(), KeyPrime.cend(), opadkey.begin(), [](uint8_t c){return c ^ 0x5c;});
    auto hsh = m_hasher->hash();
    assert(!hsh.empty());
    
    auto outsha = m_factory->clone();
    outsha->update(opadkey);
    outsha->update(hsh);
    auto outarr = outsha->hash();
    ustring outvec;
    outvec.append(outarr.cbegin(), outarr.cend());
    return outvec;
}

hmac::hmac(const hmac& other) {
    *this = other;
}

hmac& hmac::operator=(const hmac & other) {
    if (this == &other) return *this;
    m_factory = other.m_factory->clone();
    m_hasher = other.m_hasher->clone();
    KeyPrime = other.KeyPrime;
    return *this;
}


std::unique_ptr<hash_base> hmac::clone() const {
    return std::make_unique<hmac>(*this);
}


hmac& hmac::update_impl(const uint8_t* data, size_t data_len) noexcept {
    m_hasher->update_impl(data, data_len);
    return *this;
}


hmac::hmac(const hash_base& hasher, const uint8_t* key, size_t key_len) {
    m_factory = hasher.clone();
    m_hasher = m_factory->clone();
    KeyPrime.resize(m_factory->get_block_size());
    if(key_len > m_factory->get_block_size()) {
        auto hsh = m_factory->clone()->update_impl(key, key_len).hash();
        std::copy(hsh.cbegin(), hsh.cend(), KeyPrime.begin());
    } else {
        std::copy_n(key, key_len, KeyPrime.begin());
    }
    assert(KeyPrime.size() == hasher.get_block_size());
    ustring ipadkey;
    ipadkey.resize(m_factory->get_block_size());
    assert(ipadkey.size() == hasher.get_block_size());
    std::transform(KeyPrime.cbegin(), KeyPrime.cend(), ipadkey.begin(), [](uint8_t c){return c ^ 0x36;});
    m_hasher->update(ipadkey);
}

} // namespace fbw


