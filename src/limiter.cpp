//
//  limiter.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//


#include "limiter.hpp"
#include <utility>
#include <cassert>
#include <coroutine>

connection_token::connection_token(std::shared_ptr<limiter> lim, std::string ip) : lim(lim), ip(ip) {}
connection_token::connection_token(connection_token&& other) : lim(other.lim), ip(std::move(other.ip)) {
    other.lim.reset();
};
connection_token& connection_token::operator=(connection_token&& other) {
    if(this != &other) {
        lim = std::exchange(other.lim, std::weak_ptr<limiter>{});
        ip = std::move(other.ip);
    }
    return *this;
}

limiter::acquirable limiter::add_connection(std::string ip) {
    return acquirable{ shared_from_this(), std::move(ip), std::nullopt };
}

limiter::fallible limiter::wait_until_retriable() {
    return fallible{ shared_from_this()};
}

bool limiter::acquirable::await_ready() {
    return false;
}

bool limiter::acquirable::await_suspend(std::coroutine_handle<> h) {
    std::scoped_lock lk {lim->connections_mut};
    waiter w { h, this };
    if(lim->total_connections >= max_connections) {
        lim->blocked.push(w);
        return true;
    }
    if(lim->total_connections >= brownout_connections and lim->ip_map[ip] >= brownout_ip_connections) {
        token = std::nullopt;
        return false;
    }

    if(lim->ip_map[ip] >= max_ip_connections) {
        token = std::nullopt;
        return false;
    }
    lim->total_connections++;
    lim->ip_map[ip]++;
    token = connection_token{ lim, ip};
    return false;
}

std::optional<connection_token> limiter::acquirable::await_resume() {
    return std::move(token);
}

bool limiter::fallible::await_ready() {
    return false;
}

void limiter::fallible::await_suspend(std::coroutine_handle<> h) {
    std::scoped_lock lk {lim->connections_mut};
    lim->retriable.push(h);
}

bool limiter::fallible::await_resume() {
    std::scoped_lock lk {lim->connections_mut};
    if(lim->total_connections == 0) {
        return false;
    }
    return true;
}

limiter::~limiter() {
    assert(blocked.empty());
    assert(retriable.empty());
}

connection_token::~connection_token() {
    auto ptr = lim.lock();
    if(ptr == nullptr) {
        return;
    }
    limiter::waiter w {};
    std::queue<std::coroutine_handle<>> local_retriable;
    {
        std::scoped_lock lk {ptr->connections_mut};
        std::swap(ptr->retriable, local_retriable);
        if (!ptr->blocked.empty()) {
            w = ptr->blocked.front();
            ptr->blocked.pop();
            if(ptr->total_connections >= limiter::brownout_connections and ptr->ip_map[w.bp->ip] >= limiter::brownout_ip_connections) {
                w.bp->token = std::nullopt;
            } else if(ptr->ip_map[w.bp->ip] >= limiter::max_ip_connections) {
                w.bp->token = std::nullopt;
            } else {
                ptr->ip_map[w.bp->ip]++;
                w.bp->token = connection_token{ ptr, w.bp->ip };
            }
        } else {
            ptr->total_connections--;
        }
        ptr->ip_map[ip]--;
        if(ptr->ip_map[ip] == 0) {
            ptr->ip_map.erase(ip);
        }
    }
    if (w.handle) {
        w.handle.resume();
    }
    while(!local_retriable.empty()) {
        auto handle = local_retriable.front();
        local_retriable.pop();
        handle.resume();
    }
}