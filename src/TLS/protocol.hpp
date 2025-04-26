//
//  TLS.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 25/11/2021.
//

#ifndef tls_hpp
#define tls_hpp

#include "../global.hpp"

#include "TLS_enums.hpp"
#include "../TCP/tcp_stream.hpp"
#include "../Runtime/task.hpp"
#include "../TCP/stream_base.hpp"
#include "../Runtime/async_mutex.hpp"
#include "tls_engine.hpp"

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
    
    [[nodiscard]] task<stream_result> read_append(std::deque<uint8_t>&, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<stream_result> read_append_early_data(std::deque<uint8_t>&, std::optional<milliseconds> timeout);
    [[nodiscard]] task<stream_result> await_handshake_finished(); // call this after read_append_early_data for sensitive data
    [[nodiscard]] task<stream_result> write(std::vector<uint8_t>, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<void> close_notify() override;
    [[nodiscard]] task<stream_result> await_hello();

    std::string alpn();

private:
    tls_engine m_engine;
    std::unique_ptr<stream> m_client;
    std::atomic<bool> m_write_region = false;

    async_mutex m_async_read_mut;

    std::queue<packet_timed> output;
    std::deque<uint8_t> early_data_buffer;

    
    task<stream_result> read_append_common(std::deque<uint8_t>& data, std::optional<milliseconds> timeout, bool return_early);
    task<stream_result> net_write_all();
    task<stream_result> await_message(HandshakeStage stage);
};

tls_record server_key_update_record(KeyUpdateRequest req);

class buffer {
public:
    std::deque<uint8_t> write(const std::span<const uint8_t> data);
    std::deque<uint8_t> flush();
private:
    static constexpr size_t BUFFER_SIZE = 4096;
    std::deque<uint8_t> m_buffer;
};

} // namespace



#endif // tls_hpp
