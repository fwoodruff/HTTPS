//
//  reactor.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 23/04/2023.
//

#include "reactor.hpp"
#include <poll.h>
#include <unistd.h>
#include <thread>
#include <cassert>
#include "fcntl.h"
#include "executor.hpp"

reactor::reactor() {
    int rw[2];
    int err = ::pipe(rw);
    assert(err == 0);
    m_pipe_read = rw[0];
    m_pipe_write = rw[1];
    if(::fcntl(m_pipe_read, F_SETFL, O_NONBLOCK) == -1) {
        throw std::system_error(errno, std::generic_category(), "fcntl O_NONBLOCK on pipe");
    }
}

void reactor::add_task(int fd, std::coroutine_handle<> handle, IO_direction read_write,
                      std::optional<milliseconds> timeout) {
    
    auto rw = ((read_write == IO_direction::Read)? 0 : 1);
    {
        std::scoped_lock lk { m_mut };
        io_handle a_handle {};
        if (auto it = park_map.find(fd); it != park_map.end()) {
            a_handle = it->second;
            assert(a_handle.handle[!rw] != nullptr);
        }
        a_handle.handle[rw] = handle;
        a_handle.fd = fd;
        if(timeout) {
            a_handle.wake_up[rw] = steady_clock::now() + *timeout;
        } else {
            a_handle.wake_up[rw] = std::nullopt;
        }
        park_map[fd] = a_handle;
        // epoll context add fd->handle
    }
    notify();
}

void reactor::sleep_for(std::coroutine_handle<> handle, milliseconds dur) {
    if (!handle) {
        return;
    }
    const auto when = steady_clock::now() + dur;
    {
        std::scoped_lock lk{m_mut};
        m_timers.emplace(when, handle);
    }
    notify();
}

void reactor::sleep_until(std::coroutine_handle<> handle, time_point<steady_clock> when) {
    if (!handle) {
        return;
    }
    {
        std::scoped_lock lk{m_mut};
        m_timers.emplace(when, handle);
    }
    notify();
}

void reactor::notify() {
    char buff = '\0';
    while(true) {
        ssize_t succ = ::write(m_pipe_write, &buff, 1); // notify ::poll
        if(succ < 0) {
            if(errno == EINTR) {
                continue;
            } else if (errno == EPIPE) {
                ;
            } else {
                assert(false);
            }
        }
        break;
    }
}

size_t reactor::task_count() {
    std::scoped_lock lk { m_mut };
    return park_map.size() + m_timers.size();
}

std::pair<std::optional<time_point<steady_clock>>, std::vector<std::coroutine_handle<>>>
reactor::wakeup_timeouts( const time_point<steady_clock> &now) {
    std::scoped_lock lk { m_mut };
    std::optional<time_point<steady_clock>> first_wake = std::nullopt;
    std::vector<std::coroutine_handle<>> out;
    for(auto it = park_map.begin(); it != park_map.end(); ) {
        auto wakeup = it->second.wake_up;
        for(int i = 0; i < 2; i++) {
            if(wakeup[i] != std::nullopt) {
                if (!first_wake or *(wakeup[i]) < *first_wake) {
                    first_wake = wakeup[i];
                }
            }
            if(wakeup[i] and *wakeup[i] < now) {
                out.push_back(it->second.handle[i]);
                it->second.handle[i] = nullptr;
                it->second.wake_up[i] = std::nullopt;
            }
        }
        if(it->second.handle[0] == nullptr and it->second.handle[1] == nullptr) {
            it = park_map.erase(it);
        } else {
            it++;
        }
    }
    return { first_wake, out };
}

std::pair<std::optional<time_point<steady_clock>>, std::vector<std::coroutine_handle<>>>
reactor::wakeup_timers(const time_point<steady_clock>& now) {

    std::vector<std::coroutine_handle<>> out;
    std::optional<time_point<steady_clock>> next_deadline = std::nullopt;

    std::scoped_lock lk {m_mut};
    while (!m_timers.empty() and m_timers.top().when <= now) {
        out.push_back(m_timers.top().handle);
        m_timers.pop();
    }
    if (!m_timers.empty()) {
        next_deadline = m_timers.top().when;
    }
    return { next_deadline, out };
}

template<typename T>
std::optional<T> min_optional(std::optional<T> a, std::optional<T> b) {
    if (a && b) {
        return std::min(*a, *b);
    }
    return a ? a : b;
}

std::vector<std::coroutine_handle<>> reactor::wait(bool noblock) {
    auto now = steady_clock::now();
    auto [first_wake_fd, out] = wakeup_timeouts(now);
    auto [first_wake_timer, out_timers] = wakeup_timers(now);
    if (!out_timers.empty()) {
        out.insert(out.end(), out_timers.begin(), out_timers.end());
    }
    if(!out.empty()) {
        return out;
    }
    
    std::optional<milliseconds> timeout_duration = std::nullopt;
    
    auto first_wake = min_optional(first_wake_fd, first_wake_timer);
    if(first_wake) {
        timeout_duration = duration_cast<milliseconds>(*first_wake - now + 1ms);
    }
    if(noblock) {
        timeout_duration = 0ms;
    }
    
    std::vector<pollfd> to_poll;
    {
        std::scoped_lock lk { m_mut };
        for(const auto& [fd, hand] : park_map) {
            pollfd poll_fd {};
            poll_fd.fd = fd;
            assert(hand.fd == fd);
            poll_fd.events = (hand.handle[0] != nullptr ? POLLIN  : 0) | (hand.handle[1] != nullptr ? POLLOUT : 0) ;
            assert(poll_fd.events != 0);
            poll_fd.revents = 0;
            to_poll.push_back(poll_fd);
        }
    }
    pollfd pipepoll;
    pipepoll.fd = m_pipe_read; // const after constructor syscall
    pipepoll.events = POLLIN;
    pipepoll.revents = 0;
    to_poll.push_back(pipepoll);

    int num_descriptors = ::poll(to_poll.data(), (int) to_poll.size(), timeout_duration? (int) timeout_duration->count() : -1);
    if(num_descriptors == -1) {
        if(errno == EINTR) {
            return out;
        } else {
            assert(false);
        }
    }
    if(to_poll.back().revents & POLLIN) {
        char buff;
        while(true) {
            ssize_t succ = ::read(m_pipe_read, &buff, 1); // unclog pipe
            if(succ < 0) {
                if(errno == EINTR) {
                    continue;
                } else if (errno == EPIPE) {
                    ;
                } else {
                    assert(false);
                }
            }
            break;
        }
    }
    to_poll.pop_back(); // exclude the pipe
    
    {
        std::scoped_lock lk { m_mut };
        for(auto& fdd : to_poll) {
            auto& handle = park_map[fdd.fd].handle;
            auto& wakeup = park_map[fdd.fd].wake_up;
            auto IOevent = std::array{POLLIN, POLLOUT};
            for(int i = 0; i < 2; i++) {
                assert(!(fdd.revents & POLLNVAL));
                if(fdd.revents & (IOevent[i] | POLLHUP | POLLERR)) {
                    if (handle[i] != nullptr) {
                        out.push_back(handle[i]);
                    }
                    handle[i] = nullptr;
                    wakeup[i] = std::nullopt;
                }
            }
            if (handle[0] == nullptr and handle[1] == nullptr) {
                auto res = park_map.erase(fdd.fd);
                assert(res == 1);
            }
        }
    }

    const auto after = steady_clock::now();
    auto [_, wakeups_after] = wakeup_timers(after);
    if (!wakeups_after.empty()) {
        out.insert(out.end(), wakeups_after.begin(), wakeups_after.end());
    }

    return out;
}

wait_for::wait_for(milliseconds duration) : m_duration(duration) {}

bool wait_for::await_ready() const noexcept {
    return false;
}
void  wait_for::await_suspend(std::coroutine_handle<> awaiting_coroutine) {
    auto& global_executor = executor_singleton();
    global_executor.m_reactor.sleep_for(awaiting_coroutine, m_duration);
}
void wait_for::await_resume() {

}
