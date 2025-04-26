//
//  key_derivation.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/07/2024.
//


#ifndef key_derivation_hpp
#define key_derivation_hpp

#include "../../global.hpp"
#include "one_way/hmac.hpp"

#include <stdio.h>
#include <array>
#include <string>
#include <vector>


namespace fbw {

struct key_schedule {

    std::vector<uint8_t> early_secret;
    std::vector<uint8_t> resumption_binder_key;
    std::vector<uint8_t> external_binder_key;
    std::vector<uint8_t> client_early_traffic_secret;
    std::vector<uint8_t> early_exporter_master_secret;
    std::vector<uint8_t> early_derived_secret;

    std::vector<uint8_t> handshake_secret;
    std::vector<uint8_t> client_handshake_traffic_secret;
    std::vector<uint8_t> server_handshake_traffic_secret;
    std::vector<uint8_t> handshake_derived_secret;

    std::vector<uint8_t> master_secret;
    std::vector<uint8_t> client_application_traffic_secret;
    std::vector<uint8_t> server_application_traffic_secret;
    std::vector<uint8_t> exporter_master_secret;
    std::vector<uint8_t> resumption_master_secret;
};

std::vector<uint8_t> compute_binder(const hash_base& base, std::vector<uint8_t> resumption_psk, std::span<const uint8_t> hello_prefix);
void tls13_early_key_calc(const hash_base& base, key_schedule& key_sch, std::vector<uint8_t> psk, std::vector<uint8_t> client_hello_hash);
void tls13_handshake_key_calc(const hash_base& base, key_schedule& key_sch, std::vector<uint8_t> ecdh, std::vector<uint8_t> server_hello_hash);
void tls13_application_key_calc(const hash_base& base, key_schedule& key_sch, std::vector<uint8_t> server_finished_hash);
void tls13_resumption_key_calc(const hash_base& base, key_schedule& key_sch, std::vector<uint8_t> client_finished_hash);

template<typename T>
std::vector<uint8_t> P_hash(const hash_base& hash_ctor, const T& secret, const std::vector<uint8_t>& seed, size_t len) {
    std::vector<uint8_t> result;
    std::vector<uint8_t> A = do_hmac(hash_ctor, secret, seed);
    while (result.size() < len) {
        std::vector<uint8_t> A_seed = A;
        A_seed.insert(A_seed.cend(), seed.cbegin(), seed.cend());
        const auto hm = do_hmac(hash_ctor, secret, A_seed);
        result.insert(result.cend(), hm.cbegin(), hm.cend());
        A = do_hmac(hash_ctor, secret, A);
    }
    result.resize(len);
    return result;
}

// TLS 1.2 PRF function
template<typename T, typename U>
std::vector<uint8_t> prf(const hash_base& hash_ctor, const T& secret, const std::string& label, const U& seed, size_t len) {
    // Concatenate label and seed
    std::vector<uint8_t> label_seed(label.cbegin(), label.cend());
    label_seed.insert(label_seed.end(), seed.cbegin(), seed.cend());
    return P_hash(hash_ctor, secret, label_seed, len);
}

template<typename T, typename U>
std::vector<uint8_t> hkdf_expand(const hash_base& hash_ctor, const T& prk, const U& info, size_t length) {
    const size_t hash_len = hash_ctor.get_hash_size();
    const size_t N = (length + hash_len - 1) / hash_len;

    if (N > 255) {
        assert(false);
    }

    std::vector<uint8_t> okm;
    okm.reserve(length); // check this

    std::vector<uint8_t> previous_block;
    for (size_t i = 0; i < N; ++i) {
        auto hmac_ctx = hmac(hash_ctor, prk);
        hmac_ctx.update(previous_block);
        hmac_ctx.update(info);
        std::array<uint8_t, 1> val { static_cast<uint8_t>(i + 1) };
        hmac_ctx.update(val);
        previous_block = hmac_ctx.hash();
        okm.insert(okm.end(), previous_block.begin(), previous_block.begin() + std::min(hash_len, length - okm.size()));
    }
    return okm;
}

template<typename T, typename U>
std::vector<uint8_t> hkdf_expand_label(const hash_base& hash_ctor, const T& prk, const std::string& label, const U& context, size_t length) {
    const std::string full_label = "tls13 " + label;

    std::vector<uint8_t> info(3, 0);
    checked_bigend_write(length, info, 0, 2);
    info[2] =  full_label.size();
    info.insert(info.end(), full_label.begin(), full_label.end());

    info.push_back(static_cast<uint8_t>(context.size()));
    info.insert(info.end(), context.begin(), context.end());

    return hkdf_expand(hash_ctor, prk, info, length);
}

template<typename T, typename U>
std::vector<uint8_t> hkdf_extract(const hash_base& hash_ctor, const T& salt, const U& ikm) {
    return do_hmac(hash_ctor, salt, ikm);
}


} //namespace fbw


#endif // key_derivation_hpp
