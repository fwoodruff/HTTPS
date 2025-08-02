//
//  x25519mlkem768.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 20/07/2025.
//

#include <algorithm>
#include "x25519mlkem768.hpp"

#include "../one_way/keccak.hpp"

namespace fbw::xkem {

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> process_client_keyshare(std::vector<uint8_t> pub) {
    constexpr auto params = mlkem::params768;
    if(pub.size() != mlkem::dk_size<params> + curve25519::PUBKEY_SIZE) {
        return {};
    }
    mlkem::ml_kem_pub<params> client_ml_pubkey;
    std::array<uint8_t, curve25519::PUBKEY_SIZE> client_x_pubkey;
    std::copy_n(pub.begin(), mlkem::dk_size<params>, client_ml_pubkey.begin());
    std::copy_n(pub.begin() + mlkem::dk_size<params>, curve25519::PUBKEY_SIZE, client_x_pubkey.begin());

    std::array<uint8_t, curve25519::PRIVKEY_SIZE> server_x_privkey;

    randomgen.randgen(server_x_privkey);
    auto server_x_pubkey = curve25519::base_multiply(server_x_privkey);
    auto x25519_shared_secret = curve25519::multiply(server_x_privkey, client_x_pubkey);

    auto [ ml_kem_shared_secret, ml_kem_ciphertext ] = mlkem::ml_kem_encaps<params>(client_ml_pubkey);

    std::vector<uint8_t> server_keyshare(mlkem::ciphertext_size<params> + curve25519::PUBKEY_SIZE);
    std::vector<uint8_t> server_shared_secret(curve25519::PUBKEY_SIZE + mlkem::seed_len);

    std::copy(ml_kem_ciphertext.begin(), ml_kem_ciphertext.end(), server_keyshare.begin());
    std::copy(server_x_pubkey.begin(), server_x_pubkey.end(), server_keyshare.begin() + mlkem::ciphertext_size<params>);

    std::copy(ml_kem_shared_secret.begin(), ml_kem_shared_secret.end(), server_shared_secret.begin());
    std::copy(x25519_shared_secret.begin(), x25519_shared_secret.end(), server_shared_secret.begin() + mlkem::seed_len);

    return { server_shared_secret, server_keyshare };
}

}