

#include "limiter.hpp"
#include <utility>

connection_token::connection_token(limiter* lim, std::string ip) : lim(lim), ip(ip) {}
connection_token::connection_token(connection_token&& other) : lim(std::exchange(other.lim, nullptr)), ip(std::move(other.ip)) {};
connection_token& connection_token::operator=(connection_token&& other) {
    std::swap(other.lim, lim);
    return *this;
}

std::optional<connection_token> limiter::add_connection(std::string ip) {
    std::scoped_lock lk {connections_mut};
    if(total_connections > max_connections) {
        return std::nullopt;
    }
    if(total_connections > brownout_connections and ip_map[ip] >= brownout_ip_connections) {
        return std::nullopt;
    }
    if(ip_map[ip] >= max_ip_connections) {
        return std::nullopt;
    }
    total_connections++;
    ip_map[ip]++;
    return connection_token{this, ip};
}

connection_token::~connection_token() {
    if(lim != nullptr) {
        std::scoped_lock lk {lim->connections_mut};
        lim->ip_map[ip]--;
        lim->total_connections--;
        if(lim->ip_map[ip] == 0) {
            lim->ip_map.erase(ip);
        }
    }
}