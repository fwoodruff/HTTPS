//
//  secure_hash.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//


#include "sha1.hpp"
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

// used in CBC mode
sha1::sha1() : datalen(0), m_data({}) {
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

std::vector<uint8_t> sha1::hash() const {
    auto o_data = m_data;
    auto o_state = m_state;

    o_data[datalen%block_size] = 0x80;
    
    if(datalen%block_size >= 56) {
        sha1_transform(o_state,o_data);
    }
    checked_bigend_write(datalen * 8, o_data, 56, 8);
    sha1_transform(o_state, o_data);
    std::vector<uint8_t> hash;
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

} // namespace fbw


