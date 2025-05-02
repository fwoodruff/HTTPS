//
//  limiter.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//


#include "limiter.hpp"
#include <utility>

connection_token::connection_token(std::shared_ptr<limiter> lim, std::string ip) : lim(lim), ip(ip) {}
connection_token::connection_token(connection_token&& other) : lim(other.lim), ip(std::move(other.ip)) {
    other.lim.reset();
};
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
    return connection_token{ shared_from_this(), ip};
}

connection_token::~connection_token() {
    auto ptr = lim.lock();
    if(ptr != nullptr) {
        std::scoped_lock lk {ptr->connections_mut};
        ptr->ip_map[ip]--;
        ptr->total_connections--;
        if(ptr->ip_map[ip] == 0) {
            ptr->ip_map.erase(ip);
        }
    }
}