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
    void write_sync(std::vector<packet_timed>& output, ustring data, std::optional<milliseconds> timeout);
    std::optional<std::string> perform_hello_sync(std::vector<packet_timed>& output, const ustring& bio_input);


    std::pair<stream_result, bool> read_append_impl_sync(std::vector<packet_timed>& network_output, ustring& application_data, const ustring& bio_input, std::optional<milliseconds> app_timeout, bool early, bool client_finished);
    
    void server_alert_sync(std::vector<packet_timed>& output, AlertLevel level, AlertDescription description);
    std::optional<tls_record> pop_record_from_buffer();

    void flush_sync(std::vector<packet_timed>&);

    void close_notify_sync_write(std::vector<packet_timed>& output);
    stream_result close_notify_sync_finish(std::vector<packet_timed>& output, const ustring& bio_input);

    bool connection_done = false; // todo: make this part of the packet
    HandshakeStage m_expected_record = HandshakeStage::client_hello; // todo: split this server vs client expected
    ustring m_buffer;
private:
    std::deque<tls_record> encrypt_send;
    bool server_cipher_spec = false;
    bool client_cipher_spec = false;
    std::unique_ptr<cipher_base> cipher_context = nullptr;

    
    bool can_heartbeat = false;
    uint16_t tls_protocol_version = 0;
    std::optional<std::array<uint8_t, 32>> tls13_x25519_key;

    ustring early_buffer;
    ustring m_handshake_fragment {};
    handshake_ctx handshake;
    uint32_t early_data_received = 0;


    [[nodiscard]] tls_record decrypt_record(tls_record);
    
    [[nodiscard]] task<std::pair<tls_record, stream_result>> try_read_record(std::optional<milliseconds> timeout);

    bool client_handshake_record_sync(std::vector<packet_timed>& output, tls_record record);
    bool client_handshake_message_sync(std::vector<packet_timed>& output, const ustring& handshake_message);
    
    void client_alert_sync(std::vector<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout);

    void client_heartbeat(std::vector<packet_timed>& output, tls_record client_record, std::optional<milliseconds> timeout);

    void server_session_ticket_sync(std::vector<packet_timed>& output);
    
    void client_hello(const ustring& handshake_message);
    void client_key_exchange(ustring key_exchange);
    void client_handshake_finished12(const ustring& finish); 
    void client_handshake_finished13(const ustring& finish);
    void client_end_of_early_data(ustring handshake_message);

    KeyUpdateRequest client_key_update_received(const ustring& handshake_message);
    void server_key_update_respond(std::vector<packet_timed>& output);
    
    void server_hello_request(std::vector<packet_timed>& output);
    
    void server_hello_sync(std::vector<packet_timed>& output);
    void server_certificate(std::vector<packet_timed>& output);
    void server_certificate_verify(std::vector<packet_timed>& output);

    void server_key_exchange(std::vector<packet_timed>& output);
    void server_hello_done(std::vector<packet_timed>& output);
    void server_handshake_finished12(std::vector<packet_timed>& output);
    void server_handshake_finished13(std::vector<packet_timed>& output);
    void server_key_update_sync(std::vector<packet_timed>& output);

    void server_encrypted_extensions(std::vector<packet_timed>& output);

    void server_response_to_hello_sync(std::vector<packet_timed>& output);
    void flush_update_sync(std::vector<packet_timed>& output);

    
    void server_change_cipher_spec(std::vector<packet_timed>& output);
    void client_change_cipher_spec(tls_record);
    
    static std::pair<bool, tls_record> client_heartbeat_record(tls_record record, bool can_heartbeat);
    
    void write_record_sync(std::vector<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout);

};

}

#endif