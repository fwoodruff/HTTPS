//
//  await_connect.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 14/03/2026.
//

#include "await_connect.hpp"
#include "../tcp_stream.hpp"
#include "../../Runtime/executor.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <utility>
#include <cerrno>

namespace fbw {

// Opens a non-blocking socket and calls connect(). Returns the fd, or -1 on hard error.
// Sets out_immediate=true if the connection succeeded without EINPROGRESS.
static int begin_connect(const std::string& host, uint16_t port, bool& out_immediate) {
    bool is_ipv6 = host.find(':') != std::string::npos;
    int fd = ::socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (::fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        ::close(fd); return -1;
    }
    int r;
    if (is_ipv6) {
        struct sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (::inet_pton(AF_INET6, host.c_str(), &addr.sin6_addr) <= 0) {
            ::close(fd); return -1;
        }
        r = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    } else {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) <= 0) {
            ::close(fd); return -1;
        }
        r = ::connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    }
    if (r < 0 && errno != EINPROGRESS) {
        ::close(fd); return -1;
    }
    out_immediate = (r == 0);
    return fd;
}

connectable::connectable(std::string host, uint16_t port) noexcept
    : m_host(std::move(host)), m_port(port) {}

connectable::~connectable() {
    if (m_fd != -1) ::close(m_fd);
}

connectable::connectable(connectable&& other) noexcept
    : m_host(std::move(other.m_host))
    , m_port(other.m_port)
    , m_fd(std::exchange(other.m_fd, -1)) {}

bool connectable::await_ready() const noexcept {
    return false;
}

bool connectable::await_suspend(std::coroutine_handle<> cont) {
    bool immediate = false;
    m_fd = begin_connect(m_host, m_port, immediate);
    if (m_fd == -1 || immediate) {
        return false; // resume immediately: either failed or already connected
    }
    executor_singleton().m_reactor.add_task(m_fd, cont, IO_direction::Write);
    return true;
}

std::optional<tcp_stream> connectable::await_resume() {
    if (m_fd == -1) return std::nullopt;
    int err = 0;
    socklen_t len = sizeof(err);
    if (::getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        return std::nullopt;
    }
    return tcp_stream{std::exchange(m_fd, -1), m_host, m_port};
}

} // namespace fbw
