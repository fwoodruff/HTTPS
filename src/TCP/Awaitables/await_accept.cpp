//
//  acceptable.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#include "await_accept.hpp"

#include "../../Runtime/executor.hpp"
#include "../tcp_stream.hpp"

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <optional>
#include <cerrno>

#include <coroutine>


std::pair<std::string, uint16_t> get_ip_port(const struct sockaddr& sa) {
    char ipstr[INET6_ADDRSTRLEN];
    uint16_t port = 0;
    if (sa.sa_family == AF_INET) {
        const struct sockaddr_in& sin = reinterpret_cast<const struct sockaddr_in&>(sa);
        inet_ntop(AF_INET, &sin.sin_addr, ipstr, INET_ADDRSTRLEN);
        port = ntohs(sin.sin_port);
    } else if (sa.sa_family == AF_INET6) {
        const struct sockaddr_in6& sin6 = reinterpret_cast<const struct sockaddr_in6&>(sa);
        inet_ntop(AF_INET6, &sin6.sin6_addr, ipstr, INET6_ADDRSTRLEN);
        port = ntohs(sin6.sin6_port);
    } else {
        ipstr[0] = '\0';
    }
    return {ipstr, port};
}

namespace fbw {

std::optional<tcp_stream> acceptable::await_resume() {
#ifdef __linux__
    if (m_used_uring) {
        int client_fd = m_token.res;
        if (client_fd < 0) {
            return std::nullopt;
        }
        // SOCK_NONBLOCK was requested in accept_flags so no fcntl needed
        auto [ip, port] = get_ip_port(reinterpret_cast<const struct sockaddr&>(m_addr));
        return tcp_stream { client_fd, ip, port };
    }
#endif
    struct sockaddr_storage client_address;
    socklen_t shrink_address_size = sizeof client_address;
    int client_fd = ::accept(m_server_fd, (struct sockaddr *)&client_address, &shrink_address_size);
    if(client_fd == -1) {
        return std::nullopt;
    }
    auto [ip, port] = get_ip_port((struct sockaddr &)client_address);
    if(::fcntl(client_fd, F_SETFL, O_NONBLOCK) == -1) {
        ::close(client_fd);
        return std::nullopt;
    }
    return {{client_fd, ip, port}};
}

acceptable::acceptable(int sfd) : m_server_fd(sfd) {}

bool acceptable::await_ready() const noexcept {
    return false;
}

bool acceptable::await_suspend(std::coroutine_handle<> coroutine) {
#ifdef __linux__
    if (executor_singleton().m_reactor.uring_ok()) {
        m_token.handle = coroutine;
        if (executor_singleton().m_reactor.submit_accept(m_server_fd, &m_addr, &m_addrlen, &m_token)) {
            m_used_uring = true;
            return true;  // suspend; will resume via CQE
        }
        // Ring full — fall back to poll reactor so we still get woken when the fd is ready.
    }
#endif
    executor_singleton().m_reactor.add_task(m_server_fd, coroutine, IO_direction::Read);
    return true;
}

} // namespace
