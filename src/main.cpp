
#include "TLS/protocol.hpp"
#include "Runtime/executor.hpp"
#include "TCP/listener.hpp"
#include "HTTP/HTTP1_1/HTTP.hpp"
#include "HTTP/HTTP2/h2proto.hpp"
#include "HTTP/HTTP1_1/HTTP.hpp"
#include "HTTP/HTTP2/h2proto.hpp"
#include "global.hpp"
#include "HTTP/HTTP1_1/mimemap.hpp"
#include "HTTP/HTTP1_1/mimemap.hpp"
#include "TLS/PEMextract.hpp"
#include "HTTP/HTTP1_1/string_utils.hpp"
#include "HTTP/HTTP1_1/string_utils.hpp"
#include "limiter.hpp"
#include "TLS/session_ticket.hpp"
#include "TLS/Cryptography/one_way/keccak.hpp"
#include "TLS/session_ticket.hpp"
#include "TLS/Cryptography/one_way/keccak.hpp"

#include <memory>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <unordered_map>
#include <print>

// Wishlist:

// Features:
//      HTTP/2
//      HTTP webroot for ACME
//      HRR cookies

// Correctness:
//      Check that poly1305 is constant-time
//      Points at infinity?
//      ustring is not UB but can be
//      Check ALPN in session tickets

// Syntax:
//      Add 'explict' to constructors
//      Remove C-style casts
//      More functions should take const& and span
//      Review interface for signatures and key exchange
//      Reference RFC 8446 in comments

// Separation of concerns:
//      0-RTT context should be per-server not global - implement fingerprinting query helpersx
//      read/write operations should emit 'jobs' not data, separate context for actual encryption
//      buffering logic should be independent from encryption
//      HTTP codes should be a map code -> { title, blurb }

// Optimisations:
//      Revisit big numbers
//      Allocation-free TLS context
//      Views rather than clones for client hello extensions
//      ChaCha should zip pairs of 'state' objects for SIMD
//      std::generator when emitting records

// Future:
//      QUIC
//      TLS Client

// after a connection is accepted, this is the per-client entry point
task<void> http_client(std::unique_ptr<fbw::stream> client_stream, bool redirect, connection_token ip_connections, std::string alpn) {
    try {
        if(alpn == "http/1.1") {
            fbw::HTTP http_handler { std::move(client_stream), fbw::project_options.webpage_folder, redirect };
            co_await http_handler.client();
        } if(alpn == "h2") {
            auto http_handler = std::make_shared<fbw::HTTP2>( std::move(client_stream), fbw::project_options.webpage_folder );
            co_await http_handler->client();
        }
    } catch(const std::exception& e) {
        std::println(std::cerr, "{}", e.what());
    }
}

task<void> tls_client(std::unique_ptr<fbw::TLS> client_stream, connection_token ip_connections) {
    assert(client_stream != nullptr);
    auto res = co_await client_stream->await_hello();
    if(res != fbw::stream_result::ok) {
        co_return;
    }
    std::string alpn = client_stream->alpn();
    if(alpn.empty()) {
        co_return;
    }
    co_await http_client(std::move(client_stream), false, std::move(ip_connections), alpn);
}

// accepts connections and spins up per-client asynchronous tasks
// if the server socket would block on accept, we suspend the coroutine and park the connection over at the reactor
// when the task wakes we push it to the server
task<void> https_server(std::shared_ptr<limiter> ip_connections, fbw::tcplistener listener) {
    try {
        for(;;) {
            if(auto client = co_await listener.accept()) {
                assert(ip_connections != nullptr);
                assert(ip_connections != nullptr);
                auto conn = ip_connections->add_connection(client->m_ip);
                if(conn == std::nullopt) [[unlikely]] {
                    continue;
                }

                auto tcp_stream = std::make_unique<fbw::tcp_stream>(std::move( * client ));
                auto tls_stream = std::make_unique<fbw::TLS>(std::move(tcp_stream));
                
                async_spawn(tls_client(std::move(tls_stream), std::move(*conn)));
            }
        }
    } catch(const std::exception& e) {
        std::println(std::cerr, "{}", e.what());
    }
}

task<void> redirect_server(std::shared_ptr<limiter> ip_connections, fbw::tcplistener listener) {
    try {
        for(;;) {
            if(auto client = co_await listener.accept()) {
                assert(ip_connections != nullptr);
                assert(client != std::nullopt);
                assert(ip_connections != nullptr);
                assert(client != std::nullopt);
                auto conn = ip_connections->add_connection(client->m_ip);
                if(conn == std::nullopt) [[unlikely]] {
                    continue;
                }
                auto client_tcp_stream = std::make_unique<fbw::tcp_stream>(std::move(*client));
                async_spawn(http_client(std::move(client_tcp_stream), true, std::move(*conn), "http/1.1"));
            }
        }
    } catch(const std::exception& e ) {
        std::println(std::cerr, "{}", e.what());
    }
}

task<void> async_main(fbw::tcplistener https_listener, std::string https_port, fbw::tcplistener http_listener, std::string http_port) {
    try {
        fbw::MIMEmap = fbw::MIMES(fbw::project_options.mime_folder);
        static_cast<void>(fbw::der_cert_for_domain(fbw::project_options.default_subfolder));
        static_cast<void>(fbw::privkey_for_domain(fbw::project_options.default_subfolder));
        fbw::parse_tlds(fbw::project_options.tld_file);

        std::println("Redirect running on port {}", http_port);
        std::println("HTTPS running on port {}", https_port);

        auto ip_connections = std::make_shared<limiter>();
        async_spawn(https_server(ip_connections, std::move(https_listener)));
        async_spawn(redirect_server(ip_connections, std::move(http_listener)));

    } catch(const std::exception& e) {
        std::println(std::cerr, "{}", e.what());
        std::println(std::cerr, "Mime folder: {}", std::filesystem::absolute(fbw::project_options.mime_folder).string());
        std::println(std::cerr, "Key file: {}", std::filesystem::absolute(fbw::project_options.key_file).string());
        std::println(std::cerr, "Certificate file: {}", std::filesystem::absolute(fbw::project_options.certificate_file).string());
    }
    co_return;
}




int main(int argc, const char * argv[]) {
    try {
        fbw::init_options();
        auto http_port = fbw::project_options.redirect_port ;
        auto http_listener = fbw::tcplistener::bind(http_port);
        auto https_port = fbw::project_options.server_port;
        auto https_listener = fbw::tcplistener::bind(https_port);
        fbw::randomgen.randgen(fbw::session_ticket_master_secret);
        fbw::randomgen.randgen(fbw::session_ticket_master_secret);
        run(async_main(std::move(https_listener), https_port, std::move(http_listener), http_port));
    } catch(const std::exception& e) {
        std::cerr << "main: " << e.what() << std::endl;
    }
    return 0;
}
