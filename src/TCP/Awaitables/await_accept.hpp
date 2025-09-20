//
//  acceptable.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#ifndef acceptable_hpp
#define acceptable_hpp

#include <cstdio>
#include <span>
#include <optional>

#include <coroutine>

#include <sys/socket.h>

#include "await_stream.hpp"

namespace fbw {

class tcp_stream;

class acceptable : awaitable_base {
public:
    acceptable(int sfd);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine) noexcept;
    std::optional<tcp_stream> await_resume();
private:
    int m_server_fd;
    struct ::sockaddr_storage m_client_address;
};
}

#endif // acceptable_hpp
