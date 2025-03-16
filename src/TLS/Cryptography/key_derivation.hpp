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

    ustring early_secret;
    ustring resumption_binder_key;
    ustring external_binder_key;
    ustring client_early_traffic_secret;
    ustring early_exporter_master_secret;
    ustring early_derived_secret;

    ustring handshake_secret;
    ustring client_handshake_traffic_secret;
    ustring server_handshake_traffic_secret;
    ustring handshake_derived_secret;

    ustring master_secret;
    ustring client_application_traffic_secret;
    ustring server_application_traffic_secret;
    ustring exporter_master_secret;
    ustring resumption_master_secret;
};

ustring compute_binder(const hash_base& base, ustring resumption_psk, std::span<const uint8_t> hello_prefix);
void tls13_early_key_calc(const hash_base& base, key_schedule& key_sch, ustring psk, ustring client_hello_hash);
void tls13_handshake_key_calc(const hash_base& base, key_schedule& key_sch, ustring ecdh, ustring server_hello_hash);
void tls13_application_key_calc(const hash_base& base, key_schedule& key_sch, ustring server_finished_hash);
void tls13_resumption_key_calc(const hash_base& base, key_schedule& key_sch, ustring client_finished_hash);

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
template<typename T, typename U>
ustring prf(const hash_base& hash_ctor, const T& secret, const std::string& label, const U& seed, size_t len) {
    // Concatenate label and seed
    ustring label_seed(label.cbegin(), label.cend());
    label_seed.append(seed.cbegin(), seed.cend());
    return P_hash(hash_ctor, secret, label_seed, len);
}

template<typename T, typename U>
ustring hkdf_expand(const hash_base& hash_ctor, const T& prk, const U& info, size_t length) {
    const size_t hash_len = hash_ctor.get_hash_size();
    const size_t N = (length + hash_len - 1) / hash_len;

    if (N > 255) {
        assert(false);
    }

    ustring okm;
    okm.reserve(length); // check this

    ustring previous_block;
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
ustring hkdf_expand_label(const hash_base& hash_ctor, const T& prk, const std::string& label, const U& context, size_t length) {
    const std::string full_label = "tls13 " + label;

    ustring info(3, 0);
    checked_bigend_write(length, info, 0, 2);
    info[2] =  full_label.size();
    info.append(full_label.begin(), full_label.end());

    info.push_back(static_cast<uint8_t>(context.size()));
    info.append(context.begin(), context.end());

    return hkdf_expand(hash_ctor, prk, info, length);
}

template<typename T, typename U>
ustring hkdf_extract(const hash_base& hash_ctor, const T& salt, const U& ikm) {
    return do_hmac(hash_ctor, salt, ikm);
}


} //namespace fbw


#endif // key_derivation_hpp
