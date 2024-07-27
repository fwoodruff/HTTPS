//
//  handshake.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//

#ifndef handshake_hpp
#define handshake_hpp


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
    unsigned short cipher {};
    std::array<uint8_t,32> client_public_key {};
public:
    std::unique_ptr<hash_base> handshake_hasher = nullptr;
    ustring m_client_random {};
    ustring m_server_random {};
    
    std::unique_ptr<const hash_base> hash_ctor = nullptr;
    std::array<uint8_t,32> server_private_key_ephem {};
    
    ustring master_secret {};
    ustring server_handshake_hash {};
    std::string alpn;
    bool tls13_available = false;

    bool* p_use_tls13 = nullptr;
    std::unique_ptr<cipher_base>* p_cipher_context;

    [[nodiscard]] tls_record server_certificate_record(bool use_tls13) const;
    [[nodiscard]] tls_record server_key_exchange_record(std::array<uint8_t, 32> pubkey_ephem) const;
    [[nodiscard]] tls_record server_hello_record(bool use_tls13, std::optional<std::array<unsigned char, 32UL>> client_session_id, bool can_heartbeat) const;
    [[nodiscard]] tls_record server_certificate_verify_record() const;
    static tls_record server_encrypted_extensions_record();
    static tls_record server_hello_done_record();
    static std::pair<bool, tls_record> client_heartbeat_record(tls_record record, bool can_heartbeat);

    std::pair<ustring, ustring> tls13_key_calc() const;
    void client_hello_record(tls_record record, bool& can_heartbeat);
    ustring client_key_exchange_receipt(tls_record record);

private:
    unsigned short cipher_choice(const std::span<const uint8_t>& s);
    void hello_extensions(tls_record& buffer, bool use_tls13, bool can_heartbeat) const;
};




} // namespace


#endif // handshake_hpp