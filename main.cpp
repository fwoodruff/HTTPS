//
//  main.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//

#include "server.hpp"
#include "global.hpp"
#include "Runtime/executor.hpp"
#include "IP/listener.hpp"
#include "TLS/session_ticket.hpp"
#include "TLS/Cryptography/one_way/keccak.hpp"

#include <cstdio>

int main(int argc, const char* argv[]) {
    try {
        auto config_path = fbw::get_config_path(argc, argv);
        fbw::init_options(config_path);
        auto http_port = fbw::project_options.redirect_port;
        auto http_listener = fbw::tcplistener::bind(http_port);
        auto https_port = fbw::project_options.server_port;
        auto https_listener = fbw::tcplistener::bind(https_port);
        fbw::randomgen.randgen(fbw::session_ticket_master_secret);
        fbw::randomgen.randgen(fbw::session_ticket_master_secret);
        run(async_main(std::move(https_listener), https_port, std::move(http_listener), http_port));
    } catch(const std::exception& e) {
        fprintf(stderr, "main: %s\n\n", e.what());
    }
    return 0;
}
