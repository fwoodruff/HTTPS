
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

// todo:
// Make encryption concurrent (depends on TLS 1.3 interface) - could have a 'coroutine thread pool' in async_main
// Implement an HTTP webroot (with 301 not 404) for HTTP-01 ACME challenges
// review unnecessary buffer copies, more subspan, less substr
// ustring is UB!! Use vector<std::byte>
// HTTP codes should be a map code -> { title, blurb }
// HTTP/2
// more functions should take const& and return a value
// GET request to /readiness should return 206 below brownout threshold, 429 above
// memory pool of common objects (records) - view calls to malloc
// improve interface for signature and key exchange
// docker in CI with curlimages/curl to docker network
// nail down constant time-ness - look at RFC 7746 for x25519
// scope of parsed hello should be such that it gets removed sooner
// offload state to TLS HRR cookie
// project point at infinity into Montgomery space, add with other points (including Pt@Inf), project back - check value still good
// go through full H2 section and remove hacks like C-style casts - deserialisation code must have bugs 
// Implement TLS 1.3 session ticket resumption, and emit ticket contents for fingerprinting clients
// Add explicit to constructors liberally
// Use a global fixed size hash-set cache to determine if a session token is being reused (0-RTT if not) - based on ticket nonce, with eviction
// refactor TLS::write_buffer usage - also this might handle empty records strangely
// to test key update mechanism again after changes
// todo: add RFC references as comments
// once HTTP/2 and HTTP/1.1 share the same interface, combine perform_hello_sync and read_append_impl_sync

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

// todo: refactor this so that the http client just reads and writes to the stream, where handshakes are an implementation detail
// add a method for the http client to 'peak and review' early data if any.
// then consider replacing the existing stateful mechanism for preventing ticket replay attacks with a stateless one
task<void> tls_client(std::unique_ptr<fbw::TLS> client_stream, connection_token ip_connections) {
    assert(client_stream != nullptr);
    std::string alpn = co_await client_stream->perform_hello();
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
