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
#include "Cryptography/one_way/sha2.hpp"

#include "TLS_enums.hpp"
#include "../TCP/tcp_stream.hpp"
#include "../Runtime/task.hpp"
#include "../TCP/stream_base.hpp"
#include "handshake.hpp"

#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>
#include <queue>

namespace fbw {


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
    uint16_t tls_protocol_version = 0;
    std::optional<std::array<uint8_t, 32>> tls13_x25519_key;

    bool server_cipher_spec = false;
    bool client_cipher_spec = false;

    ustring m_handshake_fragment {};

    handshake_ctx handshake;


    std::deque<tls_record> encrypt_send;

    [[nodiscard]] tls_record decrypt_record(tls_record);
    
    [[nodiscard]] task<std::pair<tls_record, stream_result>> try_read_record(std::optional<milliseconds> timeout);
    [[nodiscard]] task<stream_result> write_record(tls_record record, std::optional<milliseconds> timeout);
    
    [[nodiscard]] task<stream_result> client_handshake_record(tls_record);
    [[nodiscard]] task<stream_result> client_handshake_message(const ustring& handshake_message);
    [[nodiscard]] task<void> client_alert(tls_record, std::optional<milliseconds> timeout); // handshake and application data both perform handshakes.
    [[nodiscard]] task<stream_result> client_heartbeat(tls_record, std::optional<milliseconds> timeout);
    [[nodiscard]] task<stream_result> client_post_handshake(const ustring& message,  std::optional<milliseconds> timeout);
    
    void client_hello(const ustring& handshake_message);
    void client_key_exchange(ustring key_exchange);
    void client_handshake_finished12(const ustring& finish); 
    void client_handshake_finished13(const ustring& finish);
    
    [[nodiscard]] task<stream_result> server_hello_request();
    
    [[nodiscard]] task<stream_result> server_hello();
    [[nodiscard]] task<stream_result> server_certificate();
    [[nodiscard]] task<stream_result> server_certificate_verify();

    [[nodiscard]] task<stream_result> server_key_exchange();
    [[nodiscard]] task<stream_result> server_hello_done();
    [[nodiscard]] task<stream_result> server_handshake_finished12();
    [[nodiscard]] task<stream_result> server_handshake_finished13();

    [[nodiscard]] task<stream_result> server_encrypted_extensions();

    [[nodiscard]] task<void> server_alert(AlertLevel level, AlertDescription description);
    

    [[nodiscard]] task<stream_result> server_change_cipher_spec();
    void client_change_cipher_spec(tls_record);


    static std::pair<bool, tls_record> client_heartbeat_record(tls_record record, bool can_heartbeat);

};

} // namespace


#endif // tls_hpp
