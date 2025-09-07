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

#include <liburing.h>

reactor::reactor() {
    int rw[2];
    int err = ::pipe(rw);
    assert(err == 0);
    m_pipe_read = rw[0];
    m_pipe_write = rw[1];
    ::fcntl(m_pipe_read, F_SETFL, O_NONBLOCK);
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

void reactor::notify() {
    char buff = '\0';
    do {
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
    } while(false);
}

size_t reactor::task_count() {
    std::scoped_lock lk { m_mut };
    return park_map.size();
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

std::vector<std::coroutine_handle<>> reactor::wait(bool noblock) {
    std::vector<std::coroutine_handle<>> handles;
    
    io_uring_cqe* cqe = nullptr;
    while (io_uring_peek_cqe(&m_ring, &cqe) == 0 && cqe) {
        uint64_t ud = cqe->user_data;
        int res = cqe->res;
        io_uring_cqe_seen(&m_ring, cqe);
        awaitable* aw = reinterpret_cast<awaitable*>(ud);
        aw->m_res = res;
        std::coroutine_handle<> coro = aw->this_coro;
        handles.push_back(coro);
    }
    if(!handles.empty() || noblock) {
        return handles;
    }
    int ret = io_uring_wait_cqe(&m_ring, &cqe);
    if (ret == 0 && cqe) {
        uint64_t ud = cqe->user_data;
        int res = cqe->res;
        io_uring_cqe_seen(&m_ring, cqe);
        awaitable* aw = reinterpret_cast<awaitable*>(ud);
        aw->m_res = res;
        std::coroutine_handle<> coro = aw->this_coro;
        handles.push_back(coro);
    }
    return handles;
}
