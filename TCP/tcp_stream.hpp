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

#include "global.hpp"
#include "stream_base.hpp"
#include "task.hpp"
#include "await_stream.hpp"
#include "await_accept.hpp"

namespace fbw {

class readable;
class writeable;

class tcp_stream : public stream {
public:
    tcp_stream(int fd);
    ~tcp_stream();
    tcp_stream(const tcp_stream& other) = delete;
    tcp_stream& operator=(const tcp_stream& other) = delete;
    tcp_stream(tcp_stream&& other);
    tcp_stream& operator=(tcp_stream&& other);
    
    [[nodiscard]] task<bool> read_append(ustring&, std::optional<milliseconds> timeout = STANDARD_TIMEOUT) override;
    [[nodiscard]] task<void> write(ustring, std::optional<milliseconds> timeout = STANDARD_TIMEOUT) override;
    [[nodiscard]] task<void> close_notify(std::optional<milliseconds> timeout = STANDARD_TIMEOUT) override;
private:
    int m_fd;
    [[nodiscard]] readable read(std::span<uint8_t>& bytes, std::optional<milliseconds> timeout = STANDARD_TIMEOUT);
    [[nodiscard]] writeable write_some(std::span<const uint8_t>& bytes, std::optional<milliseconds> timeout = STANDARD_TIMEOUT);
    
};

}

#endif /* stream_hpp */
