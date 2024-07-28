//
//  stream.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#ifndef stream_hpp
#define stream_hpp

#include <stdio.h>
#include <span>
#include <chrono>
#include <optional>
#include <string>

#include "../global.hpp"
#include "stream_base.hpp"
#include "../Runtime/task.hpp"
#include "../TCP/Awaitables/await_accept.hpp"
#include "../TCP/Awaitables/await_stream.hpp"

namespace fbw {

class readable;
class writeable;

class tcp_stream : public stream {
public:
    tcp_stream(int fd, std::string ip, uint16_t port);
    ~tcp_stream();
    tcp_stream(const tcp_stream& other) = delete;
    tcp_stream& operator=(const tcp_stream& other) = delete;
    tcp_stream(tcp_stream&& other);
    tcp_stream& operator=(tcp_stream&& other);
    
    [[nodiscard]] task<stream_result> read_append(ustring&, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<stream_result> write(ustring, bool last, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<void> close_notify() override;
    [[nodiscard]] task<stream_result> flush() override;

    std::string m_ip;
    uint16_t m_port;
private:
    int m_fd;
    [[nodiscard]] readable read(std::span<uint8_t>& bytes, std::optional<milliseconds> timeout);
    [[nodiscard]] writeable write_some(std::span<const uint8_t>& bytes, std::optional<milliseconds> timeout);
    
};

}

#endif // stream_hpp
