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
    tcplistener(int file_descriptor);
    ~tcplistener();
    tcplistener(const tcplistener& other) = delete;
    tcplistener& operator=(const tcplistener& other) = delete;
    tcplistener(tcplistener&& other) noexcept;
    tcplistener& operator=(tcplistener&& other) noexcept;
    
    static tcplistener bind(std::string service);
    acceptable accept();
private:
    int m_fd;
};

}

#endif // listener_hpp
