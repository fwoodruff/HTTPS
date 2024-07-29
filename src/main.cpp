
#include "TLS/protocol.hpp"
#include "Runtime/executor.hpp"
#include "TCP/listener.hpp"
#include "HTTP/HTTP.hpp"
#include "HTTP/HTTP2.hpp"
#include "global.hpp"
#include "HTTP/mimemap.hpp"
#include "TLS/PEMextract.hpp"
#include "HTTP/string_utils.hpp"
#include "limiter.hpp"
#include "TLS/Cryptography/one_way/secure_hash.hpp"
#include "TLS/Cryptography/one_way/hash_base.hpp"

#include <memory>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <unordered_map>

// todo:
// secp256k1 and x25519, get the point at infinity behaviour right
// implement TLS 1.3
// Make encryption concurrent (depends on TLS 1.3 interface) - could have a 'coroutine thread pool' in async_main
// Implement a map between HTTP 'host' header and webroot (with default)
// Implement an HTTP webroot (with 301 not 404) - this is so we can use HTTP ACME challenges
// Implement a map between SNI host and TLS certificate (with default)
// fix the SHA-384 implementations
// AES-256
// add a health check to the docker image
// implement HTTP/1.1 compression encodings
// review unnecessary buffer copies, more subspan, less substr
// HTTP codes should be a map code -> { title, blurb }
// errors in server config should output to stderr
// HTTP/2
// use master key rather than expanded key material for TLS 1.2 handshakes
// mostly lock-free runtime
// check all 'expected record' logic (asserts, etc.)
// unhandled exception when running exec outside of root folder
// 'split' and 'split_string' functions are redundant
// more functions should take const& and return a value

// after a connection is accepted, this is the per-client entry point
task<void> http_client(std::unique_ptr<fbw::stream> client_stream, bool redirect, connection_token ip_connections, std::string alpn) {
    try {
        if(alpn == "http/1.1") {
            fbw::HTTP http_handler { std::move(client_stream), fbw::option_singleton().webpage_folder, redirect };
            co_await http_handler.client();
        } if(alpn == "h2") {
            fbw::HTTP2 http_handler { std::move(client_stream), fbw::option_singleton().webpage_folder };
            co_await http_handler.client();
        }
    } catch(const std::exception& e) {
        std::cerr << e.what();
    }
}

task<void> tls_client(std::unique_ptr<fbw::TLS> client_stream, connection_token ip_connections) {
    std::string alpn = co_await client_stream->perform_handshake();
    if(alpn.empty()) {
        co_return;
    }
    co_await http_client(std::move(client_stream), false, std::move(ip_connections), alpn);
}

// accepts connections and spins up per-client asynchronous tasks
// if the server socket would block on accept, we suspend the coroutine and park the connection over at the reactor
// when the task wakes we push it to the server
task<void> https_server(std::shared_ptr<limiter> ip_connections) {
    try {
        auto port = fbw::option_singleton().server_port;
        auto listener = fbw::tcplistener::bind(port);
        std::stringstream ss;
        ss << "HTTPS running on port " << port << std::endl;
        std::clog << ss.str() << std::flush;
        for(;;) {
            if(auto client = co_await listener.accept()) {
                auto conn = ip_connections->add_connection(client->m_ip);
                if(conn == std::nullopt) {
                    continue;
                }

                auto tcp_stream = std::make_unique<fbw::tcp_stream>(std::move( * client ));
                auto tls_stream = std::make_unique<fbw::TLS>(std::move(tcp_stream));
                
                async_spawn(tls_client(std::move(tls_stream), std::move(*conn)));
            }
        }
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
}

task<void> redirect_server(std::shared_ptr<limiter> ip_connections) {
    try {
        // todo: have a folder for HTTP connections so we can implement HTTP-01 acme challenges
        auto port = fbw::option_singleton().redirect_port ;
        auto listener = fbw::tcplistener::bind(port);
        std::stringstream ss;
        ss << "Redirect running on port " << port << std::endl;
        std::clog << ss.str() << std::flush;
        for(;;) {
            if(auto client = co_await listener.accept()) {
                auto conn = ip_connections->add_connection(client->m_ip);
                if(conn == std::nullopt) {
                    continue;
                }
                auto client_tcp_stream = std::make_unique<fbw::tcp_stream>(std::move(*client));
                async_spawn(http_client(std::move(client_tcp_stream), true, std::move(*conn), "http/1.1"));
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
        fbw::parse_tlds(fbw::option_singleton().tld_file);
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;

        std::cerr << "Mime folder: " << std::filesystem::absolute(fbw::option_singleton().mime_folder) << std::endl;
        std::cerr << "Key file: " << std::filesystem::absolute(fbw::option_singleton().key_file) << std::endl;
        std::cerr << "Certificate file: " << std::filesystem::absolute(fbw::option_singleton().certificate_file) << std::endl;
        co_return;
    }
    auto ip_connections = std::make_shared<limiter>();
    async_spawn(https_server(ip_connections));
    async_spawn(redirect_server(ip_connections));
    co_return;
}

int main(int argc, const char * argv[]) {
    run(async_main(argc, argv));
    return 0;
}
