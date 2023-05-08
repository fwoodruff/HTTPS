//
//  acceptable.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#include "await_accept.hpp"

#include "executor.hpp"
#include "tcp_stream.hpp"

#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#ifdef __cpp_impl_coroutine
#include <coroutine>
#else
#include <experimental/coroutine>
namespace std {
    namespace experimental {}
    using namespace experimental;
}
#endif


namespace fbw {

std::optional<tcp_stream> acceptable::await_resume() {
    struct sockaddr_storage client_address;
    socklen_t shrink_address_size = sizeof client_address;
    int client_fd = ::accept(m_server_fd, (struct sockaddr *)&client_address, &shrink_address_size);
    if(client_fd == -1) {
        return std::nullopt;
    }
    ::fcntl(client_fd, F_SETFL, O_NONBLOCK);
    return client_fd;
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
