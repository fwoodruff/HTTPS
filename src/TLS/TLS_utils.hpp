//
//  TLS_utils.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//


#ifndef tls_utils_hpp
#define tls_utils_hpp


#include "Cryptography/one_way/hash_base.hpp"
#include "Cryptography/cipher/block_chain.hpp"
#include "../global.hpp"
#include "Cryptography/one_way/secure_hash.hpp"

#include "TLS_enums.hpp"
#include "../TCP/tcp_stream.hpp"
#include "../Runtime/task.hpp"
#include "../TCP/stream_base.hpp"

#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>

namespace fbw {

[[nodiscard]] std::array<uint8_t, 32> extract_x25519_key(std::span<const uint8_t> extension);
void certificates_serial(tls_record& record);
bool is_tls13_supported(std::span<const uint8_t> extension);
std::string check_SNI(std::span<const uint8_t> servernames);
std::optional<tls_record> try_extract_record(ustring& input);

} // namespace


#endif // tls_utils_hpp