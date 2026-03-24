//
//  server.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 09/03/2026.
//

#pragma once

#include "Runtime/executor.hpp"
#include "TCP/listener.hpp"

#include <string>

task<void> async_main(fbw::tcplistener https_listener, std::string https_port,
                      fbw::tcplistener http_listener, std::string http_port);
