//
//  executor.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 15/04/2023.
//

#include "executor.hpp"
#include <mutex>
#include <iostream>
#include <chrono>
#include <poll.h>
#include <algorithm>
#include <cassert>
#include <utility>

static size_t NUM_THREADS = std::thread::hardware_concurrency();
using namespace std::chrono;
using namespace std::chrono_literals;



void executor::thread_function() {
    for(;;) {
        std::coroutine_handle<> task;
        bool this_thread_does_poll_wait = false;
        {
            std::unique_lock lk { m_mut };
            m_cond.wait(lk, [&]{
                return !m_ready.empty()
                or num_tasks == 0
                or (can_poll_wait and m_reactor.task_count() != 0); });
            if(num_tasks == 0) {
                assert(m_ready.empty());
                break;
            } else if(!m_ready.empty()) {
                task = m_ready.front();
                m_ready.pop();
            } else {
                assert(can_poll_wait);
                this_thread_does_poll_wait = std::exchange(can_poll_wait, false);
            }
        }
        if(this_thread_does_poll_wait) {
            auto wakeable_coroutines = m_reactor.wait();
            {
                std::unique_lock lk { m_mut };
                for(auto&& coro : wakeable_coroutines) {
                    m_ready.push(coro);
                }
                can_poll_wait = true;
            }
            m_cond.notify_one();
        } else {
            task.resume();
        }
    }
    m_cond.notify_one();
}

void executor::run() {
    for(unsigned i = 0; i < NUM_THREADS; i++) {
        m_threadpool.emplace_back(&executor::thread_function, this);
    }
    for(auto& thd : m_threadpool) {
        thd.join();
    }
}


root_task make_root_task(task<void> task) {
    co_await task;
    executor& global_executor = executor_singleton();
    {
        std::scoped_lock lk { global_executor.m_mut };
        global_executor.num_tasks--;
    }
    global_executor.m_cond.notify_one();
}

// enqueues an asynchronous task for the executor to run when resources are available
void executor::spawn(task<void> taskob) {
    {
        auto root = make_root_task(std::move(taskob));
        std::unique_lock lk { m_mut };
        m_ready.push(root.m_coroutine);
        ++num_tasks;
    }
    m_cond.notify_one();
}

// starts the runtime
void run(task<void> main_task) {
    auto& exec = executor_singleton();
    exec.spawn(std::move(main_task));
    exec.run();
}


void async_spawn(task<void> subtask) {
    auto& exec = executor_singleton();
    exec.spawn(std::move(subtask));
}

// thread pool with a reactor
executor& executor_singleton() {
    static executor global_executor;
    return global_executor;
}


