//
//  TLS.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 25/11/2021.
//

#ifndef tls_hpp
#define tls_hpp



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

constexpr size_t TLS_EXPANSION_MAX = 2048;
constexpr size_t TLS_HEADER_SIZE = 5;
constexpr size_t WRITE_RECORD_SIZE = 2899;

struct key_schedule {  
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
};

class TLS : public stream {
public:

    TLS(std::unique_ptr<stream> output_stream);
    ~TLS() = default;
    
    [[nodiscard]] task<stream_result> read_append(ustring&, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<stream_result> write(ustring, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<void> close_notify() override;

    [[nodiscard]] task<std::string> perform_handshake();
    [[nodiscard]] task<stream_result> flush() override;
private:
    std::unique_ptr<stream> m_client;
    std::unique_ptr<cipher_base> cipher_context = nullptr;
    HandshakeStage m_expected_record = HandshakeStage::client_hello;
    ustring m_buffer;
   
    bool can_heartbeat = false;
    bool tls13_available = false;
    bool use_tls13 = false;
    std::optional<std::array<uint8_t, 32>> tls13_x25519_key;
    std::optional<std::array<uint8_t, 32>> client_session_id;

    ustring resumption_master_secret13;
    ustring exporter_master_secret13;

    std::array<uint8_t, WRITE_RECORD_SIZE> m_write_buffer {};
    size_t m_write_buffer_idx = 0;

    [[nodiscard]] tls_record decrypt_record(tls_record);
    
    [[nodiscard]] task<std::pair<tls_record, stream_result>> try_read_record(std::optional<milliseconds> timeout);
    [[nodiscard]] task<stream_result> write_record(tls_record record, std::optional<milliseconds> timeout);
    
    [[nodiscard]] task<stream_result> client_handshake_record(key_schedule&, tls_record);
    [[nodiscard]] task<void> client_alert(tls_record, std::optional<milliseconds> timeout); // handshake and application data both perform handshakes.
    [[nodiscard]] task<stream_result> client_heartbeat(tls_record, std::optional<milliseconds> timeout);
    
    void client_change_cipher_spec(tls_record);
    void client_hello(key_schedule& handshake, tls_record);
    void client_key_exchange(key_schedule&, tls_record key_exchange);
    void client_handshake_finished12(key_schedule& handshake, tls_record finish);
    void client_handshake_finished13(key_schedule& handshake, tls_record finish);
    
    [[nodiscard]] task<stream_result> server_hello_request();
    [[nodiscard]] task<stream_result> server_change_cipher_spec();
    [[nodiscard]] task<stream_result> server_hello(key_schedule&);
    [[nodiscard]] task<stream_result> server_certificate(key_schedule&);
    [[nodiscard]] task<stream_result> server_certificate_verify(key_schedule&);

    [[nodiscard]] tls_record server_certificate_record(key_schedule&);
    [[nodiscard]] task<stream_result> server_key_exchange(key_schedule&);
    [[nodiscard]] task<stream_result> server_hello_done(hash_base&);
    [[nodiscard]] task<stream_result> server_handshake_finished12(const key_schedule&);
    [[nodiscard]] task<stream_result> server_handshake_finished13(key_schedule&);

    [[nodiscard]] task<stream_result> server_encrypted_extensions() { co_return stream_result::ok; }

    [[nodiscard]] task<void> server_alert(AlertLevel level, AlertDescription description);
    ustring hello_extensions(key_schedule& handshake);
    unsigned short cipher_choice(key_schedule& handshake, const ustring& s);
    

};

} // namespace


#endif // tls_connection_hpp
