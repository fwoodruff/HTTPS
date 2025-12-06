//
//  await_message.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 18/11/2025.
//

#ifndef await_message_hpp
#define await_message_hpp

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <span>
#include <coroutine>
#include <optional>
#include <chrono>

using namespace std::chrono;

namespace fbw {

constexpr size_t udp_buffer_size = 4040;

struct datagram {
    std::vector<uint8_t> data;
    struct sockaddr_storage addr;
    ssize_t address_size;
};

class udp_receiver {
public:
    udp_receiver(int sfd, std::optional<milliseconds> millis);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    datagram await_resume();
private:
    int m_fd;
    std::optional<milliseconds> m_millis;
};

class udp_sender {
public:
    udp_sender(int fd, datagram dgram, std::optional<milliseconds> millis);
    bool await_ready() const noexcept;
    bool await_suspend(std::coroutine_handle<> awaiting_coroutine);
    bool await_resume();
private:
    int m_fd;
    datagram m_dgram;
    std::optional<milliseconds> m_millis;
};

class udp_socket {
public:
    udp_socket(int sfd);
    static udp_socket bind(std::string service);
    udp_receiver receive_from(std::optional<milliseconds> millis);
    udp_sender send_to(datagram dgram, std::optional<milliseconds> millis);

    udp_socket(const udp_socket& other) = delete;
    udp_socket(udp_socket&& other);
    udp_socket& operator=(const udp_socket& other) = delete;
    udp_socket& operator=(udp_socket&& other);
    ~udp_socket();
private:
    int m_fd;
};

}

#endif