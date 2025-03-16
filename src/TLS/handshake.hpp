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
#include "Cryptography/one_way/sha2.hpp"

#include "TLS_enums.hpp"
#include "../TCP/tcp_stream.hpp"
#include "../Runtime/task.hpp"
#include "../TCP/stream_base.hpp"
#include "hello.hpp"

#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>

namespace fbw {

class handshake_ctx {  
    
public:
    key_share client_public_key {};
    std::unique_ptr<hash_base> handshake_hasher = nullptr;
    ustring m_server_random {};
    
    std::unique_ptr<const hash_base> hash_ctor = nullptr;
    std::array<uint8_t,32> server_private_key_ephem {};
    
    hello_record_data client_hello;
    key_schedule tls13_key_schedule;
    ustring tls12_master_secret;

    std::string alpn;

    std::optional<uint16_t> selected_preshared_key_id = std::nullopt;

    uint16_t* p_tls_version = nullptr;
    std::unique_ptr<cipher_base>* p_cipher_context;

    cipher_suites cipher;

    bool middlebox_compatibility();

    int hello_retry_count = 0;

    std::string m_SNI {};

    [[nodiscard]] tls_record server_certificate_record();
    [[nodiscard]] tls_record server_key_exchange_record();
    [[nodiscard]] tls_record server_hello_record();
    [[nodiscard]] tls_record server_certificate_verify_record();
    tls_record server_encrypted_extensions_record();
    tls_record server_hello_done_record();
    

    void client_hello_record(const ustring& handshake_message);
    ustring client_key_exchange_receipt(const ustring& handshake_message);

    void client_handshake_finished12_record(const ustring& handshake_message);
    void client_handshake_finished13_record(const ustring& handshake_message);

    tls_record server_handshake_finished12_record();
    tls_record server_handshake_finished13_record();

    bool is_hello_retry();
private:
    void hello_extensions(tls_record& buffer);
    void hello_retry_extensions(tls_record& record);

    void set_cipher_ctx(cipher_suites cipher_suite);

    std::pair<ustring, std::optional<size_t>> get_psk(const ustring& hello_message) const;
    
};

} // namespace


#endif // handshake_hpp