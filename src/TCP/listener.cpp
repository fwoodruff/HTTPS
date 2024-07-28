//
//  listener.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#include "listener.hpp"
#include "Awaitables/await_accept.hpp"

#include <fcntl.h>
#include <cstdio>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <cstring>
#include <unistd.h>
#include <cstdlib>
#include <cerrno>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <sstream>
#include <chrono>
#include <iostream>
#include <utility>
#include <cassert>

namespace fbw {


tcplistener::tcplistener(int fd) : m_fd(fd) {}

tcplistener::~tcplistener() {
    if(m_fd != -1) {
        int err = ::close(m_fd);
        assert(err == 0);
    }
}

/*
int get_listener_socket(std::string service) {
    int sockfd = -1;
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *servinfo;
    if (int rv = ::getaddrinfo(nullptr, service.c_str(), &hints, &servinfo) != 0) {
        std::stringstream sse;
        sse << "getaddrinfo: " << gai_strerror(rv) << "\n";
        throw std::runtime_error(sse.str());
    }
    // loop through all the results and bind to the first we can
    struct addrinfo *p;
    int sockopt = 0;
    for(p = servinfo; p != nullptr; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        int yes = 1;
        if (sockopt = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)); sockopt == -1) {
            continue;
        }
        if (::bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    if(sockopt == -1) {
        throw std::runtime_error("setsockopt failed");
    }
    if (p == nullptr)  {
        throw std::runtime_error("server: failed to bind\n");
    }
    if (listen(sockfd, 10) == -1) {
        throw std::runtime_error("listen");
    }

    ::fcntl(sockfd, F_SETFL, O_NONBLOCK);
    return sockfd;
}
*/

int get_listener_socket(const std::string &service) {
    int sockfd = -1;
    int port = std::stoi(service); // Convert service (port) to integer

    struct sockaddr_in6 server_addr {}; // IPv6 address structure

    if (port < 0 || port > 65535) {
        throw std::runtime_error("Invalid port number");
    }

    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd == -1) {
        throw std::runtime_error("socket: failed to create socket");
    }

    // Allow both IPv4 and IPv6 connections
    int no = 0;
    if (setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (void *)&no, sizeof(no)) == -1) {
        close(sockfd);
        throw std::runtime_error("setsockopt: failed to set IPV6_V6ONLY");
    }
    
    int yes = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        close(sockfd);
        throw std::runtime_error("setsockopt: failed");
    }

    // Configure the sockaddr_in6 structure for IPv6
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_addr = in6addr_any; // Bind to all available interfaces
    server_addr.sin6_port = htons(port);

    // Bind socket to port
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        close(sockfd);
        throw std::runtime_error("bind: failed to bind socket");
    }

    // Listen on the socket
    if (listen(sockfd, 10) == -1) {
        close(sockfd);
        throw std::runtime_error("listen: failed");
    }

    // Set socket to non-blocking mode
    if (fcntl(sockfd, F_SETFL, O_NONBLOCK) == -1) {
        close(sockfd);
        throw std::runtime_error("fcntl: failed to set non-blocking");
    }

    return sockfd;
}


tcplistener tcplistener::bind(std::string service) {
    int sockfd = get_listener_socket(service);
    return tcplistener(sockfd);
}

acceptable tcplistener::accept() {
    return acceptable(m_fd);
}

tcplistener::tcplistener(tcplistener&& other) : m_fd(std::exchange(other.m_fd, -1)) {
}

tcplistener& tcplistener::operator=(tcplistener&& other) {
    this->m_fd = std::exchange(other.m_fd, -1);
    return *this;
}


}
