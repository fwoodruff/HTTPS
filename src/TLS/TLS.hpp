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

constexpr size_t TLS_RECORD_SIZE = (1u << 14) - 5;


// todo: modify PRF to use templates and thus write data to stack better
struct handshake_material {  
    std::unique_ptr<hash_base> handshake_hasher = nullptr;
    ustring m_client_random {};
    ustring m_server_random {};
    unsigned short cipher {};
    std::unique_ptr<const hash_base> hash_ctor = nullptr;
    std::array<uint8_t,32> server_private_key_ephem {};
    std::array<uint8_t,32> client_public_key {};
    ustring master_secret {};
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
private:
    std::optional<tls_record> m_buffered_record;
    std::unique_ptr<stream> m_client;
    std::unique_ptr<cipher_base> cipher_context = nullptr;
    HandshakeStage m_expected_record = HandshakeStage::client_hello;
    ustring m_buffer;
    bool can_heartbeat = false;
    bool tls13_available = false;
    bool use_tls13 = false;
    std::optional<std::array<uint8_t, 32>> tls13_x25519_key;
    std::optional<std::array<uint8_t, 32>> client_session_id;

    
    
    [[nodiscard]] task<std::pair<tls_record, stream_result>> try_read_record(std::optional<milliseconds> timeout);
    [[nodiscard]] task<stream_result> write_record(tls_record record, std::optional<milliseconds> timeout);
    
    [[nodiscard]] task<stream_result> client_handshake_record(handshake_material&, tls_record);
    [[nodiscard]] task<void> client_alert(tls_record, std::optional<milliseconds> timeout); // handshake and application data both perform handshakes.
    [[nodiscard]] task<stream_result> client_heartbeat(tls_record, std::optional<milliseconds> timeout);
    
    void client_change_cipher_spec(tls_record);
    void client_hello(handshake_material& handshake, tls_record);
    void client_key_exchange(handshake_material&, tls_record key_exchange);
    void client_handshake_finished(handshake_material& handshake, tls_record finish);
    
    [[nodiscard]] task<stream_result> server_hello_request();
    [[nodiscard]] task<stream_result> server_change_cipher_spec();
    [[nodiscard]] task<stream_result> server_hello(handshake_material&);
    [[nodiscard]] task<stream_result> server_certificate(hash_base&);
    [[nodiscard]] task<stream_result> server_key_exchange(handshake_material&);
    [[nodiscard]] task<stream_result> server_hello_done(hash_base&);
    [[nodiscard]] task<stream_result> server_handshake_finished(const handshake_material&);

    [[nodiscard]] task<void> server_alert(AlertLevel level, AlertDescription description);
    ustring hello_extensions(handshake_material& handshake);
    unsigned short cipher_choice(handshake_material& handshake, const ustring& s);
    

};

} // namespace


#endif // tls_connection_hpp
