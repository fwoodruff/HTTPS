
#include "TLS/protocol.hpp"
#include "Runtime/executor.hpp"
#include "TCP/listener.hpp"
#include "HTTP/common/HTTP.hpp"
#include "HTTP/HTTP2/h2proto.hpp"
#include "global.hpp"
#include "HTTP/common/mimemap.hpp"
#include "TLS/PEMextract.hpp"
#include "HTTP/common/string_utils.hpp"
#include "limiter.hpp"
#include "TLS/session_ticket.hpp"
#include "TLS/Cryptography/one_way/keccak.hpp"
#include "HTTP/HTTP1/h1stream.hpp"
#include "Application/http_handler.hpp"

#include "TLS/Cryptography/assymetric/mlkem.hpp"

#include <memory>
#include <fstream>
#include <string>
#include <filesystem>
#include <unordered_map>
#include <print>

#include <liburing.h>

// Wishlist:

// Features:
//      HRR cookies
//      HTTP/2 graceful server shutdown
//      memory-bounded TLS layer w.r.t. async suspension points
//      Accept-Languages header folders
//      Config path should be relative to exec not caller working dir
//      apt install
//      websockets need an awaitable sleep function
//      consume bytes on h2 context for protocol switching
//      at max connections await an async semaphore rather than the tcp listener
//      per-thread semaphore for executor
//      io_uring option for reactor
//      non-allocating executor

// Correctness:
//      Check that poly1305 is constant-time
//      go through RFC 9113 ensuring correct handling of everything
//      TLS SNI should match HTTP/2 :authority and HTTP/1.1 Host
//      HTTP/1.1 should add keep-alive/close header

// Syntax:
//      Add 'explict' to constructors
//      Remove C-style casts
//      More functions should take const& and span
//      Review interface for signatures and key exchange
//      Reference RFC 8446 in comments

// Separation of concerns:
//      0-RTT context should be per-server not global - implement fingerprinting query helpers
//      read/write operations should emit 'jobs' not data, separate context for actual encryption
//      buffering logic should be independent from encryption
//      HTTP codes should be a map code -> { title, blurb }
//      combine sync layers for TLS + HTTP/2
//      write and use a 'safe add' function
//      request_headers struct rather than a vector.
//      for state machine transitions, have functions close_local() and close_remote() which perform some cleanup

// Optimisations:
//      Revisit big numbers
//      Allocation-free TLS context
//      Views rather than clones for client hello extensions
//      ChaCha should zip pairs of 'state' objects for SIMD
//      std::generator when emitting records
//      tls record serialisation could be simpler

// Future:
//      QUIC
//      TLS Client
//      Russian TLS ciphers and curves - Magma and Kuznyechik

// ideas:
// the h2_context should stream in bytes not frames, so that it can emit the right errors for malformed frames
// and send the server settings straight after the client preface (which isn't a frame)


struct io_uring m_ring;

// after a connection is accepted, this is the per-client entry point
task<void> http_client(std::unique_ptr<fbw::stream> client_stream, connection_token ip_connections, std::string alpn, fbw::callback handler) {
    try {
        if(alpn == "http/1.1") {
            auto http_handler = std::make_shared<fbw::HTTP1>( std::move(client_stream), handler);
            co_await http_handler->client();
        } if(alpn == "h2") {
            auto http_handler = std::make_shared<fbw::HTTP2>( std::move(client_stream), handler);
            co_await http_handler->client();
        }
    } catch(const std::exception& e) {
        std::println(stderr, "client exception: {}\n", e.what());
    }
}

task<void> tls_client(std::unique_ptr<fbw::TLS> client_stream, connection_token ip_connections) {
    assert(client_stream != nullptr);
    try {
        auto res = co_await client_stream->await_hello();
        if(res != fbw::stream_result::ok) {
            co_return;
        }
        std::string alpn = client_stream->alpn();
        if(alpn.empty()) {
            co_return;
        }
        co_await http_client(std::move(client_stream), std::move(ip_connections), alpn, fbw::application_handler);
    } catch(const std::exception& e) {
        std::println(stderr, "TLS client exception: {}\n", e.what());
    }
}

// accepts connections and spins up per-client asynchronous tasks
// if the server socket would block on accept, we suspend the coroutine and park the connection over at the reactor
// when the task wakes we push it to the server
task<void> https_server(std::shared_ptr<limiter> ip_connections, fbw::tcplistener listener) {
    for(;;) {
        try {
            auto client = co_await listener.accept();
            assert(ip_connections != nullptr);
            if(!client) {
                bool retriable = co_await ip_connections->wait_until_retriable();
                if(!retriable) {
                    break;
                }
                continue;
            }
            std::ofstream ip_ban = std::ofstream(fbw::project_options.ip_ban_file, std::ios_base::app);
            if (!ip_ban.is_open()) {
                throw std::runtime_error("failed to open ip ban file");
            }

            auto timestamp = fbw::build_iso_8601_current_timestamp();
            auto ip = client->get_ip();
            std::println(ip_ban, "[{}] CONNECT ip={}", timestamp, ip);
            ip_ban.flush();
            auto conn = co_await ip_connections->add_connection(client->m_ip);
            if(conn == std::nullopt) [[unlikely]] {
                continue;
            }
            auto tcp_stream = std::make_unique<fbw::tcp_stream>(std::move( * client ));
            auto tls_stream = std::make_unique<fbw::TLS>(std::move(tcp_stream));
            
            async_spawn(tls_client(std::move(tls_stream), std::move(*conn)));
        } catch(const std::exception& e) {
            std::println(stderr, "{}\n", e.what());
        }
    }
}

task<void> redirect_server(std::shared_ptr<limiter> ip_connections, fbw::tcplistener listener) {
    for(;;) {
        try {
            auto client = co_await listener.accept();
            assert(ip_connections != nullptr);
            if(!client) {
                bool retriable = co_await ip_connections->wait_until_retriable();
                if(!retriable) {
                    break;
                }
                continue;
            }

            std::ofstream ip_ban = std::ofstream(fbw::project_options.ip_ban_file, std::ios_base::app);
            if (!ip_ban.is_open()) {
                throw std::runtime_error("failed to open ip ban file");
            }
            auto timestamp = fbw::build_iso_8601_current_timestamp();
            auto ip = client->get_ip();
            std::println(ip_ban, "[{}] CONNECT ip={}", timestamp, ip);
            ip_ban.flush();

            auto conn = co_await ip_connections->add_connection(client->m_ip);
            if(conn == std::nullopt) [[unlikely]] {
                continue;
            }
            auto client_tcp_stream = std::make_unique<fbw::tcp_stream>(std::move(*client));
            async_spawn(http_client(std::move(client_tcp_stream), std::move(*conn), "http/1.1", fbw::redirect_handler));
            
        } catch(const std::exception& e ) {
            std::println(stderr, "{}\n", e.what());
        }
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
        std::fflush(stdout);

        auto ip_connections = std::make_shared<limiter>();
        async_spawn(https_server(ip_connections, std::move(https_listener)));
        async_spawn(redirect_server(ip_connections, std::move(http_listener)));

    } catch(const std::exception& e) {
        auto default_key_file = fbw::project_options.key_folder / fbw::project_options.default_subfolder / fbw::project_options.key_file;
        auto default_certificate_file = fbw::project_options.key_folder / fbw::project_options.default_subfolder / fbw::project_options.certificate_file;
        std::println(stderr, "{}", e.what());
        std::println(stderr, "{}", e.what());
        std::println(stderr, "Mime folder: {}", std::filesystem::absolute(fbw::project_options.mime_folder).lexically_normal().string());
        std::println(stderr, "Key file: {}", std::filesystem::absolute(default_key_file).lexically_normal().string());
        std::println(stderr, "Certificate file: {}", std::filesystem::absolute(default_certificate_file).lexically_normal().string());
    }
    co_return;
}




int main(int argc, const char * argv[]) {
    try {
        std::string config_path = fbw::get_config_path(argc, argv);
        fbw::init_options(config_path);
        auto http_port = fbw::project_options.redirect_port ;
        auto http_listener = fbw::tcplistener::bind(http_port);
        auto https_port = fbw::project_options.server_port;
        auto https_listener = fbw::tcplistener::bind(https_port);
        fbw::randomgen.randgen(fbw::session_ticket_master_secret);
        fbw::randomgen.randgen(fbw::session_ticket_master_secret);

        int io_uring_queue_init(128, &m_ring, 0);

        run(async_main(std::move(https_listener), https_port, std::move(http_listener), http_port));
    } catch(const std::exception& e) {
        std::println(stderr, "main: {}\n", e.what());
    }
    return 0;
}
