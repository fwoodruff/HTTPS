
#include "TLS.hpp"
#include "executor.hpp"
#include "listener.hpp"
#include "HTTP.hpp"

#include <memory>

// https://github.com/tttapa/docker-arm-cross-toolchain or learn some other cross-compilation tool

task<void> http_client(std::unique_ptr<fbw::stream> client_stream, bool redirect) {
    try {
        fbw::HTTP http_handler { std::move(client_stream), fbw::rootdir, redirect };
        co_await http_handler.client();
    } catch(...) {
        assert(false);
    }
}

task<void> https_server() {
    auto listener = fbw::tcplistener::bind("4344");
    for(;;) {
        if(auto client = co_await listener.accept()) {
            std::unique_ptr<fbw::stream> tcp_stream = std::make_unique<fbw::tcp_stream>(std::move( * client ));
            std::unique_ptr<fbw::stream> tls_stream = std::make_unique<fbw::TLS>(std::move(tcp_stream));
            async_spawn(http_client(std::move(tls_stream), false));
        }
    }
}

task<void> redirect_server() {
    auto listener = fbw::tcplistener::bind("8081");
    for(;;) {
        if(auto client = co_await listener.accept()) {
            std::unique_ptr<fbw::stream> client_tcp_stream = std::make_unique<fbw::tcp_stream>(std::move(*client));
            async_spawn(http_client(std::move(client_tcp_stream), true));
        }
    }
}

task<void> async_main(int argc, const char * argv[]) {
    async_spawn(https_server());
    //async_spawn(redirect_server());

    co_return;
}

int main(int argc, const char * argv[]) {
    
    
    
    run(async_main(argc, argv));
    return 0;
}
