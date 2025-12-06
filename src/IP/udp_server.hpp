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
#include <functional>

namespace fbw {

struct udp_connection_receiver;

struct udp_connection : std::enable_shared_from_this<udp_connection> {
public:
    udp_connection(udp_socket sock);
    task<std::optional<datagram>> receive_for(milliseconds millis);
    task<std::optional<datagram>> receive_until(time_point<steady_clock> time_point);
    udp_sender send(datagram packet);
    void resume_if_waiting();
    std::deque<datagram> inbox;
    std::mutex m_mut;
    std::coroutine_handle<> waiter;
    std::span<uint8_t> received_packet;
    udp_socket m_sock;
    uint64_t wait_generation = 1;
private:
    udp_connection_receiver receive_untimed();
};

struct udp_connection_receiver {
public:
    udp_connection_receiver(udp_connection& udp_conn);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting);
    std::optional<datagram> await_resume();
private:
    udp_connection& m_conn;
};

task<void> echo_handler(std::shared_ptr<udp_connection> conn);
task<void> serve_udp(std::string port, std::function<task<void>(std::shared_ptr<fbw::udp_connection>)> connection_handler);


}

#endif