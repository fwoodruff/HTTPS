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

std::vector<std::coroutine_handle<>> reactor::wait(bool noblock) {
    std::vector<std::coroutine_handle<>> handles;
    io_uring_submit(&m_ring);
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
