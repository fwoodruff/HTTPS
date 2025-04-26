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

enum class ServerHelloType {
    unspecified,
    preshared_key,
    preshared_key_dh,
    diffie_hellman,
    hello_retry,
};

constexpr size_t SESSION_HASHSET_SIZE = 256;
extern std::array<std::atomic<uint64_t>, SESSION_HASHSET_SIZE> session_ticket_numbers_once;

class handshake_ctx {  
    
public:
    key_share client_public_key {};
    std::unique_ptr<hash_base> handshake_hasher = nullptr;
    std::vector<uint8_t> m_server_random {};
    
    std::unique_ptr<const hash_base> hash_ctor = nullptr;
    std::array<uint8_t,32> server_private_key_ephem {};
    
    hello_record_data client_hello;
    key_schedule tls13_key_schedule;
    std::vector<uint8_t> tls12_master_secret;

    std::string alpn;

    std::optional<uint16_t> selected_preshared_key_id = std::nullopt;

    ServerHelloType server_hello_type = ServerHelloType::unspecified;

    bool zero_rtt = false;

    uint16_t* p_tls_version = nullptr;
    std::unique_ptr<cipher_base>* p_cipher_context;

    cipher_suites cipher;

    bool middlebox_compatibility();

    std::string m_SNI {};

    [[nodiscard]] tls_record server_certificate_record();
    [[nodiscard]] tls_record server_key_exchange_record();
    [[nodiscard]] tls_record server_hello_record();
    [[nodiscard]] tls_record server_certificate_verify_record();
    tls_record server_encrypted_extensions_record();
    tls_record server_hello_done_record();

    void client_end_of_early_data_record(const std::vector<uint8_t>& handshake_message);

    void client_hello_record(const std::vector<uint8_t>& handshake_message);
    std::vector<uint8_t> client_key_exchange_receipt(const std::vector<uint8_t>& handshake_message);

    void client_handshake_finished12_record(const std::vector<uint8_t>& handshake_message);
    void client_handshake_finished13_record(const std::vector<uint8_t>& handshake_message);

    tls_record server_handshake_finished12_record();
    tls_record server_handshake_finished13_record();

private:
    void hello_extensions(tls_record& buffer);
    void hello_retry_extensions(tls_record& record);

    void set_cipher_ctx(cipher_suites cipher_suite);

    std::tuple<std::vector<uint8_t>, std::optional<size_t>, bool> get_resumption_psk(const std::vector<uint8_t>& hello_message) const;
    
};

} // namespace


#endif // handshake_hpp