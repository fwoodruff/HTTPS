//
//  secure_hash.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//


#include "hmac.hpp"
#include "../../../global.hpp"

#include <array>
#include <algorithm>
#include <cmath>
#include <iomanip>
#include <climits>
#include <cassert>
#include <vector>
#include <string>

namespace fbw {


size_t hmac::get_block_size() const noexcept {
    return m_hasher->get_block_size();
}

size_t hmac::get_hash_size() const noexcept {
    return m_hasher->get_block_size();
}

std::vector<uint8_t> hmac::hash() const {
    std::vector<uint8_t> opadkey;
    opadkey.resize(m_factory->get_block_size());
    std::transform(KeyPrime.cbegin(), KeyPrime.cend(), opadkey.begin(), [](uint8_t c){return c ^ 0x5c;});
    auto hsh = m_hasher->hash();
    assert(!hsh.empty());
    
    auto outsha = m_factory->clone();
    outsha->update(opadkey);
    outsha->update(hsh);
    auto outarr = outsha->hash();
    std::vector<uint8_t> outvec;
    outvec.insert(outvec.cend(), outarr.cbegin(), outarr.cend());
    return outvec;
}

hmac::hmac(const hmac& other) {
    *this = other;
}

hmac& hmac::operator=(const hmac & other) {
    if (this == &other) { return *this;
}
    m_factory = other.m_factory->clone();
    m_hasher = other.m_hasher->clone();
    KeyPrime = other.KeyPrime;
    return *this;
}


std::unique_ptr<hash_base> hmac::clone() const {
    return std::make_unique<hmac>(*this);
}


hmac& hmac::update_impl(const uint8_t* data, size_t data_len) noexcept {
    assert(m_hasher);
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
    std::vector<uint8_t> ipadkey;
    ipadkey.resize(m_factory->get_block_size());
    assert(ipadkey.size() == hasher.get_block_size());
    std::transform(KeyPrime.cbegin(), KeyPrime.cend(), ipadkey.begin(), [](uint8_t c){return c ^ 0x36;});
    m_hasher->update(ipadkey);
}

} // namespace fbw


