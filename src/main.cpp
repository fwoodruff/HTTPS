
#include "TLS/TLS.hpp"
#include "Runtime/executor.hpp"
#include "TCP/listener.hpp"
#include "HTTP/HTTP.hpp"
#include "HTTP/string_utils.hpp"
#include "global.hpp"

#include <memory>
#include <fstream>
#include <string>


task<void> client_receiver(std::shared_ptr<fbw::HTTP> context) {
    co_await context->client_receiver();
}

task<void> client_responder(std::shared_ptr<fbw::HTTP> context) {
    co_await context->client_responder();
}

// accepts connections and spins up per-client asynchronous tasks
// if the server socket would block on accept, we suspend the coroutine and park the connection over at the reactor
// when the task wakes we push it to the server
task<void> https_server() {
    try {
        auto port = fbw::get_option("SERVER_PORT") ;
        auto listener = fbw::tcplistener::bind(port);
        auto webpages = fbw::absolute_directory(fbw::get_option("WEBPAGE_FOLDER"));
        std::clog << "HTTPS running on port " << port << std::endl;
        for(;;) {
            if(auto client = co_await listener.accept()) {
                std::unique_ptr<fbw::stream> tcp_stream = std::make_unique<fbw::tcp_stream>(std::move( * client ));
                std::unique_ptr<fbw::stream> tls_stream = std::make_unique<fbw::TLS>(std::move(tcp_stream));
                auto context = std::make_shared<fbw::HTTP>(std::move(tls_stream), webpages, false);
                async_spawn(client_receiver(context));
                async_spawn(client_responder(context));
            }
        }
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

task<void> redirect_server() {
    try {
        auto port = fbw::get_option("REDIRECT_PORT") ;
        auto listener = fbw::tcplistener::bind(port);
        auto webpages = fbw::absolute_directory(fbw::get_option("WEBPAGE_FOLDER"));
        std::clog << "Redirect running on port " << port << std::endl;
        for(;;) {
            if(auto client = co_await listener.accept()) {
                std::unique_ptr<fbw::stream> client_tcp_stream = std::make_unique<fbw::tcp_stream>(std::move(*client));
                auto context = std::make_shared<fbw::HTTP>(std::move(client_tcp_stream), webpages, true);
                async_spawn(client_receiver(context));
                async_spawn(client_responder(context));
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
