//
//  tls_engine.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 25/03/2025.
//

#ifndef tls_engine_hpp
#define tls_engine_hpp

#include "Cryptography/cipher/block_chain.hpp"
#include "../global.hpp"
#include "Cryptography/one_way/sha2.hpp"
#include "TLS_enums.hpp"
#include "../TCP/tcp_stream.hpp"
#include "../TCP/stream_base.hpp"
#include "handshake.hpp"

#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>
#include <queue>

namespace fbw {

struct packet_timed  {
    ustring data;
    std::optional<milliseconds> timeout;
};


class tls_engine {
public:
    tls_engine();

    HandshakeStage process_net_read(std::queue<packet_timed>& network_output, ustring& application_data, const ustring& bio_input, std::optional<milliseconds> app_timeout);
    
    stream_result process_net_write(std::queue<packet_timed>& output, ustring data, std::optional<milliseconds> timeout);

    void process_close_notify(std::queue<packet_timed>& output);
    stream_result close_notify_finish(const ustring& bio_input);

    std::string alpn();
    
    HandshakeStage m_expected_read_record = HandshakeStage::client_hello;
    std::mutex m_write_queue_mut;
private:
    handshake_ctx handshake;

    bool server_cipher_spec = false;
    bool client_cipher_spec = false;
    std::unique_ptr<cipher_base> cipher_context = nullptr; // todo split into read and write
    bool can_heartbeat = false;
    uint16_t tls_protocol_version = 0;
    std::optional<std::array<uint8_t, 32>> tls13_x25519_key;
    ustring m_handshake_fragment {};
    
    uint32_t early_data_received = 0;
    ustring m_buffer;
    bool write_connection_done = false;

    [[nodiscard]] tls_record decrypt_record(tls_record);

    void client_handshake_record_sync(std::queue<packet_timed>& output, tls_record record);
    void client_handshake_message_sync(std::queue<packet_timed>& output, const ustring& handshake_message);
    void client_alert_sync(std::queue<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout);
    void client_heartbeat(std::queue<packet_timed>& output, tls_record client_record, std::optional<milliseconds> timeout);
    void client_hello(const ustring& handshake_message);
    void client_key_exchange(ustring key_exchange);
    void client_handshake_finished12(const ustring& finish); 
    void client_handshake_finished13(const ustring& finish);
    void client_end_of_early_data(ustring handshake_message);
    void client_change_cipher_spec(tls_record);
    
    void server_key_update_respond(std::queue<packet_timed>& output);
    void server_hello_sync(std::queue<packet_timed>& output);
    void server_certificate(std::queue<packet_timed>& output);
    void server_certificate_verify(std::queue<packet_timed>& output);
    void server_key_exchange(std::queue<packet_timed>& output);
    void server_hello_done(std::queue<packet_timed>& output);
    void server_handshake_finished12(std::queue<packet_timed>& output);
    void server_handshake_finished13(std::queue<packet_timed>& output);
    void server_key_update_sync(std::queue<packet_timed>& output);
    void server_encrypted_extensions(std::queue<packet_timed>& output);
    void server_response_to_hello_sync(std::queue<packet_timed>& output);
    void server_change_cipher_spec(std::queue<packet_timed>& output);
    void server_session_ticket_sync(std::queue<packet_timed>& output);
    void server_alert_sync(std::queue<packet_timed>& output, AlertLevel level, AlertDescription description);

    void update_sync(std::queue<packet_timed>& output);
    void write_record_sync(std::queue<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout);

    KeyUpdateRequest client_key_update_received(const ustring& handshake_message);
    static std::pair<bool, tls_record> client_heartbeat_record(tls_record record, bool can_heartbeat);
    std::optional<tls_record> pop_record_from_buffer();
};

}

#endif