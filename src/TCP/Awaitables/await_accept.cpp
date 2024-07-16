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

#ifdef __cpp_impl_coroutine
#include <coroutine>
#else
#include <experimental/coroutine>
namespace std {
    namespace experimental {}
    using namespace experimental;
}
#endif


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
    struct sockaddr_storage client_address;
    socklen_t shrink_address_size = sizeof client_address;
    int client_fd = ::accept(m_server_fd, (struct sockaddr *)&client_address, &shrink_address_size);
    if(client_fd == -1) {
        return std::nullopt;
    }
    auto [ip, port] = get_ip_port((struct sockaddr &)client_address);
    std::string stip = ip;
    int res = ::fcntl(client_fd, F_SETFL, O_NONBLOCK);
    assert(res == 0);
    return {{client_fd, ip, port}};
}

acceptable::acceptable(int sfd) : m_server_fd(sfd) {}

bool acceptable::await_ready() const noexcept {
    return false;
}

void acceptable::await_suspend(std::coroutine_handle<> coroutine) noexcept {
    auto& exec = executor_singleton();
    exec.m_reactor.add_task(m_server_fd, coroutine, IO_direction::Read);
}

} // namespace
