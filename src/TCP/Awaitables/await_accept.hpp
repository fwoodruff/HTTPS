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

#ifdef __linux__
#include <sys/socket.h>
#include "../../Runtime/uring_reactor.hpp"
#endif



namespace fbw {

class tcp_stream;

class acceptable {
public:
    acceptable(int sfd);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    std::optional<tcp_stream> await_resume();
private:
    int m_server_fd;
#ifdef __linux__
    uring_token m_token {};
    struct sockaddr_storage m_addr {};
    socklen_t m_addrlen = sizeof(struct sockaddr_storage);
    bool m_used_uring = false;
#endif
};
}

#endif // acceptable_hpp
