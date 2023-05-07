//
//  TLS.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 25/11/2021.
//

#ifndef tls_hpp
#define tls_hpp



#include "block_chain.hpp"
#include "global.hpp"
#include "secure_hash.hpp"

#include "TLS_enums.hpp"
#include "tcp_stream.hpp"
#include "task.hpp"
#include "stream_base.hpp" // rename me

#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>




namespace fbw {


constexpr size_t TLS_RECORD_SIZE = (1u << 14) - 5;


std::optional<tls_record> extract_record(std::span<uint8_t>& input);


class TLS : public stream {
public:

    TLS(std::unique_ptr<stream> output_stream);
    ~TLS() = default;
    
    [[nodiscard]] task<bool> read_append(ustring&, std::optional<milliseconds> timeout = STANDARD_TIMEOUT) override;
    [[nodiscard]] task<void> write(ustring, std::optional<milliseconds> timeout = STANDARD_TIMEOUT) override;
    [[nodiscard]] task<void> close_notify(std::optional<milliseconds> timeout = STANDARD_TIMEOUT) override;
private:
    task<bool> perform_handshake(std::optional<milliseconds> timeout);
    
     
    std::unique_ptr<stream> m_client;
    ustring m_buffer;
    task<std::optional<tls_record>> try_read_record(std::optional<milliseconds> timeout);
    task<void> write_record(tls_record record, std::optional<milliseconds> timeout);
    
    HandshakeStage m_expected_record = HandshakeStage::client_hello;
    
    task<void> client_handshake_record(tls_record, std::optional<milliseconds> timeout);
    void client_alert(tls_record);
    task<void> client_heartbeat(tls_record, std::optional<milliseconds> timeout);
    
    void client_change_cipher_spec(tls_record);
    void client_hello(tls_record);
    void client_key_exchange(tls_record key_exchange);
    void client_handshake_finished(tls_record finish);
    
    task<void> server_change_cipher_spec(std::optional<milliseconds> timeout);
    task<void> server_hello(std::optional<milliseconds> timeout);
    task<void> server_certificate(std::optional<milliseconds> timeout);
    task<void> server_key_exchange(std::optional<milliseconds> timeout);
    task<void> server_hello_done(std::optional<milliseconds> timeout);
    task<void> server_handshake_finished(std::optional<milliseconds> timeout);
    
    void tls_notify_close();
    
    std::unique_ptr<hash_base> handshake_hasher = nullptr;
    std::unique_ptr<cipher_base> cipher_context = nullptr;
    std::array<uint8_t,32> m_client_random {};
    std::array<uint8_t,32> m_server_random {};
    unsigned short cipher {};
    std::unique_ptr<const hash_base> hasher_factory = nullptr;
    std::array<uint8_t,32> server_private_key_ephem {};
    
    unsigned short cipher_choice(const ustring& s);
    
    std::array<uint8_t,32> client_public_key {};
    std::array<uint8_t,48> master_secret {};

    [[nodiscard]] static std::array<uint8_t,48> make_master_secret(const std::unique_ptr<const hash_base>& hasher,
                                                            std::array<uint8_t,32> server_private,
                                              std::array<uint8_t,32> client_public,
                                              std::array<uint8_t,32> server_random,
                                              std::array<uint8_t,32> client_random);
    
    [[nodiscard]] ustring expand_master(const std::array<unsigned char,48>& master,
                          const std::array<unsigned char,32>& server_random,
                          const std::array<unsigned char,32>& client_random, size_t len) const;
    
    
    
    
    
};

} // namespace


#endif /* tls_connection_hpp */
