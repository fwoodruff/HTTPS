
#include "TLS.hpp"
#include "executor.hpp"
#include "listener.hpp"
#include "HTTP.hpp"
#include "global.hpp"

#include <memory>
#include <fstream>
#include <string>

task<void> http_client(std::unique_ptr<fbw::stream> client_stream, bool redirect) {
    try {
        auto webpages = fbw::absolute_directory(fbw::get_option("webpage_folder"));
        fbw::HTTP http_handler { std::move(client_stream), webpages, redirect };
        co_await http_handler.client();
    } catch(const std::out_of_range& e) {
        std::cerr << "no configured webpages folder" << std::endl;
        std::cerr << e.what();
    } catch(...) {
        assert(false);
    }
}

task<void> https_server() {
    try {
        auto port = fbw::get_option("server_port") ;
        auto listener = fbw::tcplistener::bind(port);
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
        auto port = fbw::get_option("redirect_port") ;
        auto listener = fbw::tcplistener::bind(port);
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
