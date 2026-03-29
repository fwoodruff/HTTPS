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
#include <atomic>
#include <unistd.h>
#include <utility>
#include <cerrno>
#include <cstring>

namespace fbw {

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
    bool is_ipv6 = m_host.find(':') != std::string::npos;
    m_fd = ::socket(is_ipv6 ? AF_INET6 : AF_INET, SOCK_STREAM, 0);
    if (m_fd < 0) return false;
    if (::fcntl(m_fd, F_SETFL, O_NONBLOCK) < 0) {
        ::close(m_fd); m_fd = -1; return false;
    }

#ifdef __linux__
    if (is_ipv6) {
        std::memset(&m_addr, 0, sizeof(m_addr));
        m_addr.v6.sin6_family = AF_INET6;
        m_addr.v6.sin6_port   = htons(m_port);
        if (::inet_pton(AF_INET6, m_host.c_str(), &m_addr.v6.sin6_addr) <= 0) {
            ::close(m_fd); m_fd = -1; return false;
        }
        m_addrlen = sizeof(m_addr.v6);
    } else {
        std::memset(&m_addr, 0, sizeof(m_addr));
        m_addr.v4.sin_family = AF_INET;
        m_addr.v4.sin_port   = htons(m_port);
        if (::inet_pton(AF_INET, m_host.c_str(), &m_addr.v4.sin_addr) <= 0) {
            ::close(m_fd); m_fd = -1; return false;
        }
        m_addrlen = sizeof(m_addr.v4);
    }
    if (executor_singleton().m_reactor.uring_ok()) {
        std::atomic_ref<std::coroutine_handle<>>{m_token.handle}.store(cont, std::memory_order_release);
        executor_singleton().m_reactor.submit_connect(
            m_fd, reinterpret_cast<struct sockaddr*>(&m_addr), m_addrlen, &m_token);
        return true;
    }
    // Poll fallback: addr already filled in m_addr union above
    {
        int r;
        if (is_ipv6) {
            r = ::connect(m_fd, reinterpret_cast<struct sockaddr*>(&m_addr.v6), sizeof(m_addr.v6));
        } else {
            r = ::connect(m_fd, reinterpret_cast<struct sockaddr*>(&m_addr.v4), sizeof(m_addr.v4));
        }
        if (r == 0) return false;
        if (errno != EINPROGRESS) { ::close(m_fd); m_fd = -1; return false; }
        executor_singleton().m_reactor.add_task(m_fd, cont, IO_direction::Write);
        return true;
    }
#else
    int r;
    if (is_ipv6) {
        struct sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port   = htons(m_port);
        if (::inet_pton(AF_INET6, m_host.c_str(), &addr.sin6_addr) <= 0) {
            ::close(m_fd); m_fd = -1; return false;
        }
        r = ::connect(m_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    } else {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(m_port);
        if (::inet_pton(AF_INET, m_host.c_str(), &addr.sin_addr) <= 0) {
            ::close(m_fd); m_fd = -1; return false;
        }
        r = ::connect(m_fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
    }
    if (r == 0) return false;  // connected immediately
    if (errno != EINPROGRESS) { ::close(m_fd); m_fd = -1; return false; }
    executor_singleton().m_reactor.add_task(m_fd, cont, IO_direction::Write);
    return true;
#endif
}

std::optional<tcp_stream> connectable::await_resume() {
    if (m_fd == -1) return std::nullopt;
#ifdef __linux__
    if (executor_singleton().m_reactor.uring_ok()) {
        if (m_token.res < 0) {
            ::close(m_fd); m_fd = -1; return std::nullopt;
        }
        return tcp_stream { std::exchange(m_fd, -1), m_host, m_port };
    }
#endif
    int err = 0;
    socklen_t len = sizeof(err);
    if (::getsockopt(m_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        return std::nullopt;
    }
    return tcp_stream { std::exchange(m_fd, -1), m_host, m_port };
}

} // namespace fbw
