//
//  limiter.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//

#include <optional>
#include <string>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <queue>
#include <coroutine>

class limiter;

class connection_token {
    std::weak_ptr<limiter> lim;
    std::string ip;
public:
    connection_token(const std::shared_ptr<limiter>& lim, std::string ip_addr);
    connection_token(connection_token&& other) noexcept;
    connection_token& operator=(connection_token&& other) noexcept;
    connection_token& operator=(const connection_token&) = delete;
    connection_token(const connection_token&) = delete;
    ~connection_token();
};

class limiter : public std::enable_shared_from_this<limiter> {
    constexpr static int max_connections = 11000; // max concurrent connections
    constexpr static int max_ip_connections = 25; // connections per IP under low load
    constexpr static int brownout_connections = 2000;
    constexpr static int brownout_ip_connections = 3; // connections per IP under high load
    std::mutex connections_mut;
    int total_connections = 0;
    std::unordered_map<std::string, int> ip_map;
    friend class connection_token;
public:
    struct acquirable;
private:
    struct waiter {
        std::coroutine_handle<> handle;
        acquirable* bp;
    };
    std::queue<std::coroutine_handle<>> retriable;
    std::queue<waiter> blocked;
public:
    ~limiter();
    struct acquirable {
        std::shared_ptr<limiter> lim;
        std::string ip;
        std::optional<connection_token> token;
        bool await_ready();
        bool await_suspend(std::coroutine_handle<> handle);
        std::optional<connection_token> await_resume();
    };
    struct fallible {
        std::shared_ptr<limiter> lim;
        bool await_ready();
        void await_suspend(std::coroutine_handle<> handle) const;
        bool await_resume() const;
    };
    acquirable add_connection(std::string ipaddr);
    fallible wait_until_retriable();
};

