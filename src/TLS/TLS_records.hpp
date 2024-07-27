//
//  TLS_records.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//

#ifndef tls_records_hpp
#define tls_records_hpp


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
class key_schedule {  
public:
    std::unique_ptr<hash_base> handshake_hasher = nullptr;
    ustring m_client_random {};
    ustring m_server_random {};
    unsigned short cipher {};
    std::unique_ptr<const hash_base> hash_ctor = nullptr;
    std::array<uint8_t,32> server_private_key_ephem {};
    std::array<uint8_t,32> client_public_key {};
    ustring master_secret {};
    ustring server_handshake_hash {};
    std::string alpn;
    bool tls13_available = false;

    bool* p_use_tls13 = nullptr;
    std::unique_ptr<cipher_base>* p_cipher_context;
    
};


void hello_extensions(const key_schedule& handshake, tls_record& buffer, bool use_tls13, bool can_heartbeat);

std::pair<ustring, ustring> tls13_key_calc(key_schedule& handshake);

[[nodiscard]] tls_record server_certificate_record(const key_schedule&, bool use_tls13);
[[nodiscard]] tls_record server_key_exchange_record(const key_schedule& handshake, std::array<uint8_t, 32> pubkey_ephem);
[[nodiscard]] tls_record server_hello_record(const key_schedule& handshake, bool use_tls13, std::optional<std::array<unsigned char, 32UL>> client_session_id, bool can_heartbeat );
[[nodiscard]] tls_record server_certificate_verify_record(key_schedule&);

[[nodiscard]] std::array<uint8_t, 32> extract_x25519_key(std::span<const uint8_t> extension);
void certificates_serial(tls_record& record);
bool is_tls13_supported(std::span<const uint8_t> extension);
bool check_SNI(std::span<const uint8_t> servernames);
std::optional<tls_record> try_extract_record(ustring& input);
std::pair<bool, tls_record> client_heartbeat_record(tls_record record, bool can_heartbeat);
tls_record server_encrypted_extensions_record();
ustring client_key_exchange_receipt(key_schedule& handshake, tls_record record);
tls_record server_hello_done_record();
std::pair<ustring, ustring> tls13_key_calc(key_schedule& handshake);
unsigned short cipher_choice(key_schedule& handshake, const std::span<const uint8_t>& s);
void client_hello_record(key_schedule& handshake, tls_record record, bool& can_heartbeat);

} // namespace


#endif // tls_records_hpp