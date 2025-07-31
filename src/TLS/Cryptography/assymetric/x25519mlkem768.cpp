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
    // mlkem::ml_kem_768_pub client_ml_pubkey;
    // std::array<uint8_t, curve25519::PUBKEY_SIZE> client_x_pubkey;

    return {};
}

}