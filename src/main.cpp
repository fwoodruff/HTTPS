
#include "TLS/TLS.hpp"
#include "Runtime/executor.hpp"
#include "TCP/listener.hpp"
#include "HTTP/HTTP.hpp"
#include "global.hpp"
#include "HTTP/mimemap.hpp"
#include "TLS/PEMextract.hpp"

#include <memory>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <unordered_map>

using ip_map = std::unordered_map<std::string, int>;

std::mutex connections_mut;
constexpr int max_ip_connections = 100;

// todo:
// secp256k1 and x25519, get the point at infinity behaviour right
// implement TLS 1.3
// Make encryption concurrent (depends on TLS 1.3 interface)
// Implement a map between HTTP 'host' header and webroot (with default)
// Implement an HTTP webroot (with 301 not 404) - this is so we can use HTTP ACME challenges
// Implement a map between SNI host and TLS certificate (with default)
// SHA-384 and AES-256
// memory allocators on a per IP basis
// add a health check to the docker image
// Add ranges for large HTTP requests

// after a connection is accepted, this is the per-client entry point
task<void> http_client(std::unique_ptr<fbw::stream> client_stream, bool redirect, ip_map& ip_connections, std::string ip) {
    try {
        fbw::HTTP http_handler { std::move(client_stream), fbw::option_singleton().webpage_folder, redirect };
        co_await http_handler.client();
    } catch(const std::exception& e) {
        std::cerr << e.what();
    }
    std::scoped_lock lk {connections_mut};

    ip_connections[ip]--;
    if(ip_connections[ip] == 0) {
        ip_connections.erase(ip);
    }
}

// accepts connections and spins up per-client asynchronous tasks
// if the server socket would block on accept, we suspend the coroutine and park the connection over at the reactor
// when the task wakes we push it to the server
task<void> https_server(std::shared_ptr<ip_map> ip_connections) {
    try {
        auto port = fbw::option_singleton().server_port;
        auto listener = fbw::tcplistener::bind(port);
        std::stringstream ss;
        ss << "HTTPS running on port " << port << std::endl;
        std::clog << ss.str() << std::flush;
        for(;;) {
            if(auto client = co_await listener.accept()) {
                auto ip = client->m_ip;
                {
                    std::scoped_lock lk {connections_mut};
                    if((*ip_connections)[ip] >= max_ip_connections) {
                        continue;
                    }
                    (*ip_connections)[ip]++;
                }
                // todo: perform the handshake first, and then assign the application layer based on asn1
                std::unique_ptr<fbw::stream> tcp_stream = std::make_unique<fbw::tcp_stream>(std::move( * client ));
                std::unique_ptr<fbw::stream> tls_stream = std::make_unique<fbw::TLS>(std::move(tcp_stream));
                async_spawn(http_client(std::move(tls_stream), false, *ip_connections, ip));
            }
        }
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

task<void> redirect_server(std::shared_ptr<ip_map> ip_connections) {
    try {
        // todo: have a folder for HTTP connections so we can implement HTTP-01 acme challenges
        auto port = fbw::option_singleton().redirect_port ;
        auto listener = fbw::tcplistener::bind(port);
        std::stringstream ss;
        ss << "Redirect running on port " << port << std::endl;
        std::clog << ss.str() << std::flush;
        for(;;) {
            if(auto client = co_await listener.accept()) {
                auto ip = client->m_ip;
                {
                    std::scoped_lock lk {connections_mut};
                    if((*ip_connections)[ip] >= max_ip_connections) {
                        continue;
                    }
                    (*ip_connections)[ip]++;
                }
                std::unique_ptr<fbw::stream> client_tcp_stream = std::make_unique<fbw::tcp_stream>(std::move(*client));
                async_spawn(http_client(std::move(client_tcp_stream), true, *ip_connections, ip));
            }
        }
    } catch(const std::exception& e ) {
        std::cerr << e.what() << std::endl;
    }
}

task<void> async_main(int argc, const char * argv[]) {
    try {
        fbw::MIMEmap = fbw::MIMES(fbw::option_singleton().mime_folder);
        static_cast<void>(fbw::privkey_from_file(fbw::option_singleton().key_file));
        static_cast<void>(fbw::der_cert_from_file(fbw::option_singleton().certificate_file));
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;

        std::cerr << "Mime folder: " << std::filesystem::absolute(fbw::option_singleton().mime_folder) << std::endl;
        std::cerr << "Key file: " << std::filesystem::absolute(fbw::option_singleton().key_file) << std::endl;
        std::cerr << "Certificate file: " << std::filesystem::absolute(fbw::option_singleton().certificate_file) << std::endl;
        co_return;
    }
    auto ip_connections = std::make_shared<ip_map>(); // todo: integrate
    async_spawn(https_server(ip_connections));
    async_spawn(redirect_server(ip_connections));
    co_return;
}

int main(int argc, const char * argv[]) {
    run(async_main(argc, argv));
    return 0;
}
