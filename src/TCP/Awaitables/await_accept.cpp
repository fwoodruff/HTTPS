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
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h> 
#include <arpa/inet.h>
#include <optional>

#include <coroutine>
#include <liburing.h>
#include "../../Runtime/reactor.hpp"

std::pair<std::string, uint16_t> get_ip_port(const struct sockaddr& sa) {
    char ipstr[INET6_ADDRSTRLEN];
    uint16_t port = 0;
    if (sa.sa_family == AF_INET) {
        struct sockaddr_in& sin = (struct sockaddr_in&)sa;
        inet_ntop(AF_INET, &sin.sin_addr, ipstr, INET_ADDRSTRLEN);
        port = ntohs(sin.sin_port);
    } else if (sa.sa_family == AF_INET6) {
        struct sockaddr_in6& sin6 = (struct sockaddr_in6& )sa;
        inet_ntop(AF_INET6, &sin6.sin6_addr, ipstr, INET6_ADDRSTRLEN);
        port = ntohs(sin6.sin6_port);
    }
    return {ipstr, port};
}

namespace fbw {

std::optional<tcp_stream> acceptable::await_resume() {
    if (m_res < 0) {
        return std::nullopt;
    }
    int client_fd = m_res;
    auto [ip, port] = get_ip_port((struct sockaddr &)m_client_address);
    std::string stip = ip;
    //int res = ::fcntl(client_fd, F_SETFL, O_NONBLOCK);
    //assert(res == 0);
    return {{client_fd, ip, port}};
}

acceptable::acceptable(int sfd) : m_server_fd(sfd) {}

bool acceptable::await_ready() const noexcept {
    return false;
}

bool acceptable::await_suspend(std::coroutine_handle<> coroutine) noexcept {
    io_uring_sqe* sqe = io_uring_get_sqe(&m_ring);
    if (!sqe) {
        m_res = -ECONNRESET;
        return false;
    }

    socklen_t shrink_address_size = sizeof m_client_address;
    io_uring_prep_accept(sqe, m_server_fd, (struct sockaddr *)&m_client_address,  &shrink_address_size, 0);
    sqe->user_data = std::bit_cast<uint64_t>(this);
    return true;
}

} // namespace
