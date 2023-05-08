//
//  listener.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#include "listener.hpp"
#include "await_accept.hpp"

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
    for(p = servinfo; p != nullptr; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            continue;
        }
        int yes = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            throw std::runtime_error("setsockopt");
        }
        if (::bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            continue;
        }
        break;
    }
    freeaddrinfo(servinfo);
    if (p == nullptr)  {
        throw std::runtime_error("server: failed to bind\n");
    }
    if (listen(sockfd, 10) == -1) {
        throw std::runtime_error("listen");
    }
    ::fcntl(sockfd, F_SETFL, O_NONBLOCK);
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
