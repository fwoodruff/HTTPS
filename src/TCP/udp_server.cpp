//
//  udp_server.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 21/11/2025.
//

#include "udp_server.hpp"
#include "../Runtime/task.hpp"
#include "Awaitables/await_message.hpp"
#include "../Runtime/executor.hpp"

#include <span>
#include <unordered_map>
#include <vector>
#include <utility>

namespace fbw {

using namespace std::chrono;


udp_connection_receiver::udp_connection_receiver(udp_connection& udp_conn) : m_conn(udp_conn) {}

bool udp_connection_receiver::await_ready() const noexcept {
    return !m_conn.inbox.empty();
}
void udp_connection_receiver::await_suspend(std::coroutine_handle<> awaiting) {
    m_conn.waiter = awaiting;
}
datagram udp_connection_receiver::await_resume() {
    std::scoped_lock lk { m_conn.m_mut };
    auto result = m_conn.inbox.front();
    m_conn.inbox.pop_front();
    return result;
}

udp_connection::udp_connection(udp_socket sock) : m_sock(std::move(sock)) {}

udp_connection_receiver udp_connection::receive() {
    return udp_connection_receiver{*this};
}

udp_sender udp_connection::send(datagram packet) {
    return m_sock.send_to(packet, std::nullopt);
}

void udp_connection::resume_if_waiting() {
    if (waiter && !waiter.done()) {
        auto h = waiter;
        waiter = nullptr;
        h.resume();
    }
}

task<void> handle_connection(std::shared_ptr<udp_connection> conn) {
    auto datag = co_await conn->receive();
    co_await conn->send(datag);
}

static std::string addr_to_key(const struct sockaddr_storage &ss) { // placeholder
    if (ss.ss_family == AF_INET) {
        const auto *in = reinterpret_cast<const struct sockaddr_in*>(&ss);
        std::string key;
        key.reserve(2 + 4 + 1);
        uint16_t port = in->sin_port;
        key.append(reinterpret_cast<const char*>(&in->sin_family), sizeof(in->sin_family));
        key.append(reinterpret_cast<const char*>(&port), sizeof(port));
        key.append(reinterpret_cast<const char*>(&in->sin_addr), sizeof(in->sin_addr));
        return key;
    } else if (ss.ss_family == AF_INET6) {
        const auto *in6 = reinterpret_cast<const struct sockaddr_in6*>(&ss);
        std::string key;
        key.reserve(2 + 16 + 4);
        uint16_t port = in6->sin6_port;
        key.append(reinterpret_cast<const char*>(&in6->sin6_family), sizeof(in6->sin6_family));
        key.append(reinterpret_cast<const char*>(&port), sizeof(port));
        key.append(reinterpret_cast<const char*>(&in6->sin6_addr), sizeof(in6->sin6_addr));
        key.append(reinterpret_cast<const char*>(&in6->sin6_scope_id), sizeof(in6->sin6_scope_id));
        return key;
    } else {
        return std::string(reinterpret_cast<const char*>(&ss), sizeof(ss));
    }
}

task<void> serve_udp(std::string port) {
    udp_socket socket = udp_socket::bind(port);
    std::unordered_map<std::string, std::shared_ptr<udp_connection>> addr_map;
    for(;;) {
        auto dgram = co_await socket.receive_from(std::nullopt);
        auto dgram_address_key = addr_to_key(dgram.addr);
        auto it = addr_map.find(dgram_address_key); // TODO, replace this with a lookup against the packet's id
        std::shared_ptr<udp_connection> connection;
        if(it == addr_map.end()) {
            connection = std::make_shared<udp_connection>(std::move(socket));
            addr_map.insert({dgram_address_key, connection});
            async_spawn(handle_connection(connection));
        } else {
            connection = it->second;
        }
        {
            std::scoped_lock lk { connection->m_mut };
            connection->inbox.emplace_back(dgram);
        }
        connection->resume_if_waiting();
    }
}

}

