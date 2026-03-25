//
//  initial_crypto.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 24/03/2026.
//

#include "initial_crypto.hpp"

#include "../TLS/Cryptography/key_derivation.hpp"
#include "../TLS/Cryptography/one_way/sha2.hpp"
#include "../TLS/Cryptography/one_way/hmac.hpp"

#include <stdexcept>

namespace fbw::quic {

aes::quic_aes_128_gcm_ctx derive_client_initial_ctx(std::span<const uint8_t> dcid) {
    sha256 sha;
    std::array<uint8_t, 0> empty {};

    // initial_secret = HKDF-Extract(QUIC_V1_INITIAL_SALT, dcid)
    const auto initial_secret = hkdf_extract(sha, QUIC_V1_INITIAL_SALT, dcid);

    // client_initial_secret = HKDF-Expand-Label(initial_secret, "client in", "", 32)
    const auto client_secret = hkdf_expand_label(sha, initial_secret, "client in", empty, 32);

    const auto key = hkdf_expand_label(sha, client_secret, "quic key", empty, 16);
    const auto iv  = hkdf_expand_label(sha, client_secret, "quic iv",  empty, 12);
    const auto hp  = hkdf_expand_label(sha, client_secret, "quic hp",  empty, 16);

    aes::quic_aes_128_gcm_ctx ctx;
    ctx.set_key(key, iv, hp);
    return ctx;
}

bool decrypt_initial_packet(initial_packet& p) {
    if (p.version != 0x00000001) {
        return false;
    }
    if (p.header_bytes.empty() || p.raw_payload.size() < 20) {
        return false;
    }
    try {
        const auto ctx = derive_client_initial_ctx(p.destination_connection_id);
        auto [plaintext, pn, pn_len] = ctx.deprotect(p.header_bytes,
                                                      p.first_byte,
                                                      p.raw_payload);
        p.packet_number_length = pn_len;
        p.packet_number        = pn;
        p.packet_payload       = parse_frames(plaintext);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

} // namespace fbw::quic
