//
//  udp_server.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 21/11/2025.
//

#ifndef udp_server_hpp
#define udp_server_hpp

#include "../Runtime/task.hpp"
#include "Awaitables/await_message.hpp"

#include <string>
#include <mutex>
#include <deque>
#include <memory>

namespace fbw {

task<void> serve_udp(std::string port); // TODO include callback

struct udp_connection_receiver;

struct udp_connection {
public:
    udp_connection(udp_socket sock);
    udp_connection_receiver receive();
    udp_sender send(datagram packet);
    void resume_if_waiting();
    std::deque<datagram> inbox;
    std::mutex m_mut;
    std::coroutine_handle<> waiter;
    std::span<uint8_t> received_packet;
    udp_socket m_sock;
};

struct udp_connection_receiver {
public:
    udp_connection_receiver(udp_connection& udp_conn);
    bool await_ready() const noexcept;
    void await_suspend(std::coroutine_handle<> awaiting);
    datagram await_resume();
private:
    udp_connection& m_conn;
};


}

#endif