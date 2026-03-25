//
//  initial_crypto.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 24/03/2026.
//
//  QUIC Initial packet key derivation (RFC 9001 §5.2).
//
//  QUICv1 Initial packets use a fixed well-known salt and AES-128-GCM AEAD
//  with AES-128-ECB header protection.  Keys are derived from the Destination
//  Connection ID and require no prior shared secret.
//

#ifndef quic_initial_crypto_hpp
#define quic_initial_crypto_hpp

#include "types.hpp"
#include "../TLS/Cryptography/cipher/galois_counter.hpp"

#include <array>
#include <cstdint>
#include <span>

namespace fbw::quic {

// RFC 9001 §5.2 – QUICv1 initial salt.
inline constexpr std::array<uint8_t, 20> QUIC_V1_INITIAL_SALT = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

// Derive the client-side Initial packet-number-space context from the DCID.
// Returns a fully initialised quic_aes_128_gcm_ctx ready for protect/deprotect.
aes::quic_aes_128_gcm_ctx derive_client_initial_ctx(std::span<const uint8_t> dcid);

// Convenience wrapper: derive keys, remove header protection, AEAD-decrypt,
// and populate p.packet_number_length, p.packet_number, and p.packet_payload.
// Returns true on success, false if the packet is dropped (bad tag, too short,
// unsupported version, etc.).
bool decrypt_initial_packet(initial_packet& p);

} // namespace fbw::quic

#endif // quic_initial_crypto_hpp
