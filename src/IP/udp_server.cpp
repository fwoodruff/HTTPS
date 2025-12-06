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
#include <functional>

namespace fbw {

using namespace std::chrono;

udp_connection_receiver::udp_connection_receiver(udp_connection& udp_conn) : m_conn(udp_conn) {}

bool udp_connection_receiver::await_ready() const noexcept {
    return false;
}

bool udp_connection_receiver::await_suspend(std::coroutine_handle<> awaiting) {
    std::scoped_lock lk {m_conn.m_mut};
    if(!m_conn.inbox.empty()) {
        return false;
    }
    m_conn.waiter = awaiting;
    return true;
}

std::optional<datagram> udp_connection_receiver::await_resume() {
    std::scoped_lock lk { m_conn.m_mut };
    if(m_conn.inbox.empty()) {
        return std::nullopt;
    }
    auto result = m_conn.inbox.front();
    m_conn.inbox.pop_front();
    return {result};
}

udp_connection::udp_connection(udp_socket sock) : m_sock(std::move(sock)) {}

task<void> wait_and_fire_for(std::shared_ptr<udp_connection> conn, milliseconds millis, uint64_t this_gen) {
    co_await wait_for(millis);
    std::coroutine_handle<> handle {};
    {
        std::scoped_lock lk {conn->m_mut};
        if(this_gen == conn->wait_generation) {
            handle = std::exchange(conn->waiter, nullptr);
        }
    }
    if(handle) {
        handle.resume();
    }
}

task<void> wait_and_fire_until(std::shared_ptr<udp_connection> conn, time_point<steady_clock> until, uint64_t this_gen) {
    co_await wait_until(until);
    std::coroutine_handle<> handle {};
    {
        std::scoped_lock lk {conn->m_mut};
        if(this_gen == conn->wait_generation) {
            handle = std::exchange(conn->waiter, nullptr);
        }
    }
    if(handle) {
        handle.resume();
    }
}

task<std::optional<datagram>> udp_connection::receive_for(milliseconds millis) {
    uint64_t this_gen;
    {
        std::scoped_lock lk {m_mut};
        wait_generation++;
        this_gen = wait_generation;
    }
    async_spawn(wait_and_fire_for(shared_from_this(), millis, this_gen));
    co_return co_await receive_untimed();
}

task<std::optional<datagram>> udp_connection::receive_until(time_point<steady_clock> until) {
    uint64_t this_gen;
    {
        std::scoped_lock lk {m_mut};
        wait_generation++;
        this_gen = wait_generation;
    }
    async_spawn(wait_and_fire_until(shared_from_this(), until, this_gen));
    co_return co_await receive_untimed();
}

udp_connection_receiver udp_connection::receive_untimed() {
    return udp_connection_receiver{*this};
}

udp_sender udp_connection::send(datagram packet) {
    return m_sock.send_to(packet, std::nullopt);
}

void udp_connection::resume_if_waiting() {
    std::coroutine_handle<> handle;
    {
        std::scoped_lock lk {m_mut};
        handle = std::exchange(waiter, nullptr);
    }
    if(handle) {
        handle.resume();
    }
}

task<void> echo_handler(std::shared_ptr<udp_connection> conn) {
    std::optional<datagram> datag = co_await conn->receive_for(500ms);
    if(!datag.has_value()) {
        co_return;
    }
    datagram d = *datag;
    co_await conn->send(d);
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

task<void> serve_udp(std::string port, std::function<task<void>(std::shared_ptr<fbw::udp_connection>)> connection_handler) {
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
            async_spawn(connection_handler(connection));
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

