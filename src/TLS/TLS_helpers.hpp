//
//  TLS_helpers.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/07/2024.
//


#ifndef TLS_helpers_hpp
#define TLS_helpers_hpp

#include "../global.hpp"
#include "Cryptography/one_way/secure_hash.hpp"

#include <stdio.h>
#include <array>
#include <string>
#include <vector>


namespace fbw {

template<typename T>
ustring P_hash(const hash_base& hash_ctor, const T& secret, const ustring& seed, size_t len) {
    ustring result;
    ustring A = do_hmac(hash_ctor, secret, seed);
    while (result.size() < len) {
        result.append(do_hmac(hash_ctor, secret, A + seed));
        A = do_hmac(hash_ctor, secret, A);
    }
    result.resize(len);
    return result;
}

// TLS 1.2 PRF function
template<typename T, typename U> // todo: label always std::string
ustring prf(const hash_base& hash_ctor, const T& secret, const std::string& label, const U& seed, size_t len) {
    // Concatenate label and seed
    ustring label_seed(label.cbegin(), label.cend());
    label_seed.append(seed.cbegin(), seed.cend());
    return P_hash(hash_ctor, secret, label_seed, len);
}

template<typename T, typename U>
ustring hkdf_expand(const hash_base& hash_ctor, const T& prk, const U& info, size_t length) {
    const size_t hash_len = hash_ctor.get_hash_size();  // Assuming SHA-256
    const size_t N = (length + hash_len - 1) / hash_len;  // Number of blocks needed

    if (N > 255) {
        assert(false);
    }

    ustring okm;
    okm.reserve(length);

    ustring previous_block;
    for (size_t i = 0; i < N; ++i) {
        auto hmac_ctx = hmac(hash_ctor, prk);
        hmac_ctx.update(previous_block);
        hmac_ctx.update(info);
        std::array<uint8_t, 1> val { static_cast<uint8_t>(i + 1) };
        hmac_ctx.update(val);
        okm.insert(okm.end(), previous_block.begin(), previous_block.begin() + std::min(hash_len, length - okm.size()));
    }

    return okm;
}

template<typename T>
ustring hkdf_expand_label(const hash_base& hash_ctor, const T& prk, const std::string& label, const T& context, size_t length) {
    const std::string full_label = "tls13 " + label;

    ustring info(3, 0);
    checked_bigend_write(length, info, 0, 2);
    info[2] =  full_label.size();
    info.append(full_label.begin(), full_label.end());

    info.push_back(static_cast<uint8_t>(context.size()));
    info.append(context);

    return hkdf_expand(hash_ctor, prk, info, length);
}

template<typename T, typename U>
ustring hkdf_extract(const hash_base& hash_ctor, const T& salt, const U& ikm) {
    if (salt.empty()) {
        size_t hash_len = hash_ctor.get_hash_size();
        ustring zero_salt(hash_len, 0);
        return do_hmac(hash_ctor, zero_salt, ikm);
    }
    return do_hmac(hash_ctor, salt, ikm);
}


} //namespace fbw


#endif // TLS_helpers_hpp
