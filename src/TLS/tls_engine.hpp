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
#include "../Runtime/task.hpp"
#include "../TCP/stream_base.hpp"
#include "handshake.hpp"
#include "../Runtime/async_mutex.hpp"

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
    void flush_sync(std::vector<packet_timed>&);
    void write_record_sync(std::vector<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout);
    void write_sync(std::vector<packet_timed>& ustring, std::optional<milliseconds> timeout);
private:
    std::deque<tls_record> encrypt_send;
    bool server_cipher_spec = false;
    bool client_cipher_spec = false;
    std::unique_ptr<cipher_base> cipher_context = nullptr;
};

}

#endif