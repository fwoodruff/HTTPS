


#include <optional>
#include <string>
#include <unordered_map>
#include <mutex>

class limiter;

class connection_token {
    limiter* lim;
    std::string ip;
public:
    connection_token(limiter* lim, std::string ip);
    connection_token(connection_token&& other);
    connection_token& operator=(connection_token&& other);
    connection_token& operator=(const connection_token&) = delete;
    connection_token(const connection_token&) = delete;
    ~connection_token();
};

class limiter {
    constexpr static int max_connections = 11000; // max concurrent connections
    constexpr static int max_ip_connections = 25; // connections per IP under low load
    constexpr static int brownout_connections = 2000;
    constexpr static int brownout_ip_connections = 3; // connections per IP under high load
    std::mutex connections_mut;
    int total_connections = 0;
    std::unordered_map<std::string, int> ip_map;
    friend class connection_token;
public:
    std::optional<connection_token> add_connection(std::string ip);
};

