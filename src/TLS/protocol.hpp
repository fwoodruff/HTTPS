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
    
    [[nodiscard]] task<stream_result> read_append(ustring&, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<stream_result> read_append_early_data(ustring&, std::optional<milliseconds> timeout);
    [[nodiscard]] task<stream_result> await_handshake_finished(); // call this after read_append_early_data for sensitive data
    [[nodiscard]] task<stream_result> write(ustring, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<void> close_notify() override;
    [[nodiscard]] task<std::string> perform_hello();
    [[nodiscard]] task<stream_result> flush() override;

private:
    tls_engine m_engine;
    std::unique_ptr<stream> m_client;
    async_mutex m_async_write_mut;
    async_mutex m_async_read_mut;

    [[nodiscard]] task<stream_result> read_append_impl(ustring&, std::optional<milliseconds> timeout, bool early, bool client_finished);
    task<stream_result> bio_write_all(std::queue<packet_timed>& packets);
};

tls_record server_key_update_record(KeyUpdateRequest req);

} // namespace


#endif // tls_hpp
