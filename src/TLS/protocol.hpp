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
#include "../Runtime/async_mutex.hpp"
#include "tls_engine.hpp"

#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>
#include <queue>

namespace fbw {


class TLS : public stream, public std::enable_shared_from_this<TLS>{
public:

    TLS(std::unique_ptr<stream> output_stream);
    ~TLS() = default;
    
    [[nodiscard]] task<stream_result> read_append(ustring&, std::optional<milliseconds> timeout) override;

    [[nodiscard]] task<stream_result> read_append_early(ustring&, std::optional<milliseconds> timeout);
    [[nodiscard]] task<stream_result> await_handshake_finished();

    [[nodiscard]] task<stream_result> write(ustring, std::optional<milliseconds> timeout) override;
    void write_sync(std::vector<packet_timed>& output, ustring data, std::optional<milliseconds> timeout);

    [[nodiscard]] task<void> close_notify() override;

    [[nodiscard]] task<std::string> perform_hello();
    std::optional<std::string> perform_hello_sync(std::vector<packet_timed>& output, const ustring& bio_input);
    [[nodiscard]] task<stream_result> flush() override;

    void flush_sync(std::vector<packet_timed>&);
    void write_record_sync(std::vector<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout);
private:

    std::unique_ptr<stream> m_client;
    std::unique_ptr<cipher_base> cipher_context = nullptr;
    HandshakeStage m_expected_record = HandshakeStage::client_hello; // todo: split this server vs client expected
    ustring m_buffer;
    bool can_heartbeat = false;
    uint16_t tls_protocol_version = 0;
    std::optional<std::array<uint8_t, 32>> tls13_x25519_key;

    [[nodiscard]] task<stream_result> read_append_impl(ustring&, std::optional<milliseconds> timeout, bool early, bool client_finished);

    //bool read_append_impl_sync(std::vector<packet_timed>& network_output, ustring& application_data, const ustring& bio_input, std::optional<milliseconds> app_timeout, bool early, bool client_finished);
    std::pair<stream_result, bool> read_append_impl_sync(std::vector<packet_timed>& network_output, ustring& application_data, const ustring& bio_input, std::optional<milliseconds> app_timeout, bool early, bool client_finished);
    void bio_read(const ustring& bio_input);

    ustring early_buffer;
    bool server_cipher_spec = false;
    bool client_cipher_spec = false;
    ustring m_handshake_fragment {};
    handshake_ctx handshake;
    uint32_t early_data_received = 0;

    std::queue<tls_record> inbox;

    std::deque<tls_record> encrypt_send;
    
    bool connection_done = false;

    async_mutex m_async_mut;

    task<stream_result> bio_write_all(const std::vector<packet_timed>& packets) const;

    void schedule(task<stream_result> write_task);

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

    void server_alert_sync(std::vector<packet_timed>& output, AlertLevel level, AlertDescription description);

    void server_change_cipher_spec(std::vector<packet_timed>& output);
    void client_change_cipher_spec(tls_record);
    
    friend task<void> make_write_task(task<stream_result> write_task, std::shared_ptr<TLS> this_ptr);

    static std::pair<bool, tls_record> client_heartbeat_record(tls_record record, bool can_heartbeat);

};

tls_record server_key_update_record(KeyUpdateRequest req);

} // namespace


#endif // tls_hpp
