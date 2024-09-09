
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

#include <memory>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <unordered_map>

// todo:
// Make encryption concurrent (depends on TLS 1.3 interface) - could have a 'coroutine thread pool' in async_main
// Implement an HTTP webroot (with 301 not 404) for HTTP-01 ACME challenges
// review unnecessary buffer copies, more subspan, less substr
// HTTP codes should be a map code -> { title, blurb }
// HTTP/2
// more functions should take const& and return a value
// GET request to /readiness should return 206 below brownout threshold, 429 above
// memory pool of common objects (records) - view calls to malloc
// improve interface for signature and key exchange
// docker in CI with curlimages/curl to docker network
// nail down constant time-ness - look at RFC 7746 for x25519
// offload state to TLS HRR cookie

// after a connection is accepted, this is the per-client entry point
task<void> http_client(std::unique_ptr<fbw::stream> client_stream, bool redirect, connection_token ip_connections, std::string alpn) {
    try {
        if(alpn == "http/1.1") {
            fbw::HTTP http_handler { std::move(client_stream), fbw::project_options.webpage_folder, redirect };
            co_await http_handler.client();
        } if(alpn == "h2") {
            fbw::HTTP2 http_handler { std::move(client_stream), fbw::project_options.webpage_folder };
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
task<void> https_server(std::shared_ptr<limiter> ip_connections, fbw::tcplistener listener) {
    try {
        for(;;) {
            if(auto client = co_await listener.accept()) {
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
        std::cerr << e.what() << std::endl;
    }
}

task<void> redirect_server(std::shared_ptr<limiter> ip_connections, fbw::tcplistener listener) {
    try {        
        for(;;) {
            if(auto client = co_await listener.accept()) {
                auto conn = ip_connections->add_connection(client->m_ip);
                if(conn == std::nullopt) [[unlikely]] {
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

task<void> async_main(fbw::tcplistener https_listener, std::string https_port, fbw::tcplistener http_listener, std::string http_port) {
    try {
        fbw::MIMEmap = fbw::MIMES(fbw::project_options.mime_folder);
        static_cast<void>(fbw::der_cert_for_domain(fbw::project_options.default_subfolder));
        static_cast<void>(fbw::privkey_for_domain(fbw::project_options.default_subfolder));
        fbw::parse_tlds(fbw::project_options.tld_file);

        std::stringstream ss;
        std::clog << ss.str() << std::flush;
        ss << "Redirect running on port " << http_port << std::endl;
        std::clog << ss.str();
        std::stringstream ss_s;
        ss_s << "HTTPS running on port " << https_port << std::endl;
        std::clog << ss_s.str() << std::flush;

        auto ip_connections = std::make_shared<limiter>();
        async_spawn(https_server(ip_connections, std::move(https_listener)));
        async_spawn(redirect_server(ip_connections, std::move(http_listener)));

    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
        std::cerr << "Mime folder: " << std::filesystem::absolute(fbw::project_options.mime_folder) << std::endl;
        std::cerr << "Key file: " << std::filesystem::absolute(fbw::project_options.key_file) << std::endl;
        std::cerr << "Certificate file: " << std::filesystem::absolute(fbw::project_options.certificate_file) << std::endl;
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
        run(async_main(std::move(https_listener), https_port, std::move(http_listener), http_port));
    } catch(const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    return 0;
}
