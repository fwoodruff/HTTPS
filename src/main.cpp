
#include "TLS/TLS.hpp"
#include "Runtime/executor.hpp"
#include "TCP/listener.hpp"
#include "HTTP/HTTP.hpp"
#include "global.hpp"

#include <memory>
#include <fstream>
#include <string>
#include <sstream>

// after a connection is accepted, this is the per-client entry point
task<void> http_client(std::unique_ptr<fbw::stream> client_stream, bool redirect) {
    try {
        fbw::HTTP http_handler { std::move(client_stream), fbw::option_singleton().webpage_folder, redirect };
        co_await http_handler.client();
    } catch(const std::exception& e) {
        std::cerr << e.what();
    }
}

// accepts connections and spins up per-client asynchronous tasks
// if the server socket would block on accept, we suspend the coroutine and park the connection over at the reactor
// when the task wakes we push it to the server
task<void> https_server() {
    try {
        auto port = fbw::option_singleton().server_port;
        auto listener = fbw::tcplistener::bind(port);
        std::stringstream ss;
        ss << "HTTPS running on port " << port << std::endl;
        std::clog << ss.str() << std::flush;
        for(;;) {
            if(auto client = co_await listener.accept()) {
                std::unique_ptr<fbw::stream> tcp_stream = std::make_unique<fbw::tcp_stream>(std::move( * client ));
                std::unique_ptr<fbw::stream> tls_stream = std::make_unique<fbw::TLS>(std::move(tcp_stream));
                async_spawn(http_client(std::move(tls_stream), false));
            }
        }
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

task<void> redirect_server() {
    try {
        auto port = fbw::option_singleton().redirect_port ;
        auto listener = fbw::tcplistener::bind(port);
        std::stringstream ss;
        ss << "Redirect running on port " << port << std::endl;
        std::clog << ss.str() << std::flush;
        for(;;) {
            if(auto client = co_await listener.accept()) {
                std::unique_ptr<fbw::stream> client_tcp_stream = std::make_unique<fbw::tcp_stream>(std::move(*client));
                async_spawn(http_client(std::move(client_tcp_stream), true));
            }
        }
    } catch(const std::exception& e ) {
        std::cerr << e.what() << std::endl;
    }
}

task<void> async_main(int argc, const char * argv[]) {
    async_spawn(https_server());
    async_spawn(redirect_server());
    co_return;
}

int main(int argc, const char * argv[]) {
    run(async_main(argc, argv));
    return 0;
}
