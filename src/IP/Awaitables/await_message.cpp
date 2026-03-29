//
//  writeable.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 18/11/2025.
//

#include "await_message.hpp"
#include <string>
#include <atomic>
#include "../listener.hpp"
#include "../../Runtime/reactor.hpp"
#include "../../Runtime/executor.hpp"

namespace fbw {

int get_datagram_socket(const std::string &service) {
    auto sockfd = get_socket(service, SOCK_DGRAM);
    return sockfd;
}

udp_socket udp_socket::bind(std::string service) {
    auto sockfd = get_datagram_socket(service);
    return udp_socket(sockfd);
}

udp_receiver udp_socket::receive_from(std::optional<milliseconds> millis) {
    return udp_receiver(m_fd, millis);
}

udp_socket::udp_socket(int sfd) : m_fd(sfd) {}

udp_receiver::udp_receiver(int sfd, std::optional<milliseconds> millis): m_fd(sfd), m_millis(millis) {}

bool udp_receiver::await_ready() const noexcept { // recvfrom(..., MSG_PEEK) ?
    return false;
}

bool udp_receiver::await_suspend(std::coroutine_handle<> awaiting_coroutine) {
#ifdef __linux__
    if (executor_singleton().m_reactor.uring_ok()) {
        m_iov.iov_base       = m_buf.data();
        m_iov.iov_len        = m_buf.size();
        m_msg.msg_name       = &m_addr;
        m_msg.msg_namelen    = sizeof(m_addr);
        m_msg.msg_iov        = &m_iov;
        m_msg.msg_iovlen     = 1;
        m_msg.msg_control    = nullptr;
        m_msg.msg_controllen = 0;
        m_msg.msg_flags      = 0;
        std::atomic_ref<std::coroutine_handle<>>{m_token.handle}.store(awaiting_coroutine, std::memory_order_release);
        executor_singleton().m_reactor.submit_recvmsg(m_fd, &m_msg, &m_token, m_millis);
        return true;
    }
#endif
    auto& exec = executor_singleton();
    exec.m_reactor.add_task(m_fd, awaiting_coroutine, IO_direction::Read, m_millis);
    return true;
}

datagram udp_receiver::await_resume() {
#ifdef __linux__
    if (executor_singleton().m_reactor.uring_ok()) {
        int32_t res = m_token.res;
        if (res <= 0) return {};
        datagram gram;
        gram.data = std::vector<uint8_t>(m_buf.begin(), m_buf.begin() + res);
        gram.addr = m_addr;
        gram.address_size = static_cast<ssize_t>(m_msg.msg_namelen);
        return gram;
    }
#endif
    struct sockaddr_storage their_addr;
    socklen_t addr_len;
    addr_len = sizeof(their_addr);

    std::vector<uint8_t> buffer(udp_buffer_size);
    auto numbytes = ::recvfrom(m_fd, (void*) &buffer[0], buffer.size() , 0, (struct sockaddr *)&their_addr, &addr_len);
    if(numbytes < 0){
        return {};
    }
    buffer.resize(numbytes);
    datagram gram;
    gram.data = buffer;
    gram.addr = their_addr;
    gram.address_size = addr_len;
    return gram;
}

udp_socket::udp_socket(udp_socket&& other) : m_fd(std::exchange(other.m_fd, -1)) {}

udp_socket& udp_socket::operator=(udp_socket&& other) {
    m_fd = std::exchange(other.m_fd, -1);
    return *this;
}

udp_socket::~udp_socket() {
    if(m_fd != -1) {
        ::close(m_fd);
    }
}

udp_sender udp_socket::send_to(datagram dgram, std::optional<milliseconds> millis) {
    return udp_sender { m_fd, dgram, millis };
}

udp_sender::udp_sender(int fd, datagram dgram, std::optional<milliseconds> millis) : m_fd(fd), m_dgram(dgram) {}

bool udp_sender::await_ready() const noexcept {
    return false;
}

bool udp_sender::await_suspend(std::coroutine_handle<> awaiting_coroutine) {
#ifdef __linux__
    if (executor_singleton().m_reactor.uring_ok()) {
        m_iov.iov_base       = m_dgram.data.data();
        m_iov.iov_len        = m_dgram.data.size();
        m_msg.msg_name       = &m_dgram.addr;
        m_msg.msg_namelen    = static_cast<socklen_t>(m_dgram.address_size);
        m_msg.msg_iov        = &m_iov;
        m_msg.msg_iovlen     = 1;
        m_msg.msg_control    = nullptr;
        m_msg.msg_controllen = 0;
        m_msg.msg_flags      = 0;
        std::atomic_ref<std::coroutine_handle<>>{m_token.handle}.store(awaiting_coroutine, std::memory_order_release);
        executor_singleton().m_reactor.submit_sendmsg(m_fd, &m_msg, &m_token, m_millis);
        return true;
    }
#endif
    auto& exec = executor_singleton();
    exec.m_reactor.add_task(m_fd, awaiting_coroutine, IO_direction::Write, m_millis);
    return true;
}

bool udp_sender::await_resume() {
#ifdef __linux__
    if (executor_singleton().m_reactor.uring_ok()) {
        return m_token.res >= 0;
    }
#endif
    auto code = ::sendto(m_fd, &m_dgram.data[0], m_dgram.data.size(), 0, (const sockaddr *) &m_dgram.addr, m_dgram.address_size);
    if(code == -1) {
        return false;
    }
    return true;
}


}
