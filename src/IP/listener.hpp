//
//  listener.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 16/04/2023.
//

#ifndef listener_hpp
#define listener_hpp

#include <stdio.h>
#include <string>

namespace fbw {

class acceptable;

class tcplistener {
public:
    tcplistener(int fd);
    ~tcplistener();
    tcplistener(const tcplistener& other) = delete;
    tcplistener& operator=(const tcplistener& other) = delete;
    tcplistener(tcplistener&& other);
    tcplistener& operator=(tcplistener&& other);
    
    static tcplistener bind(std::string service);
    acceptable accept();
private:
    int m_fd;
};

int get_socket(const std::string &service, int sock_kind);

}

#endif // listener_hpp
