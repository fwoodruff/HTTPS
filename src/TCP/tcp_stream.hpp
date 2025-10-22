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
#include <deque>

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
    tcp_stream(int file_descriptor, std::string ipaddr, uint16_t port);
    ~tcp_stream() override;
    tcp_stream(const tcp_stream& other) = delete;
    tcp_stream& operator=(const tcp_stream& other) = delete;
    tcp_stream(tcp_stream&& other) noexcept;
    tcp_stream& operator=(tcp_stream&& other) noexcept;
    
    [[nodiscard]] task<stream_result> read_append(std::deque<uint8_t>& buufer, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<stream_result> write(std::vector<uint8_t> buffer, std::optional<milliseconds> timeout) override;
    [[nodiscard]] task<void> close_notify() override;
    [[nodiscard]] std::string get_ip() override;

    std::string m_ip;
    uint16_t m_port;
private:
    int m_fd;
    [[nodiscard]] readable read(std::span<uint8_t>& bytes, std::optional<milliseconds> timeout) const;
    [[nodiscard]] writeable write_some(std::span<const uint8_t>& bytes, std::optional<milliseconds> timeout) const;
    
};

}

#endif // stream_hpp
