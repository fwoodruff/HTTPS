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

static size_t NUM_THREADS = 0;//std::thread::hardware_concurrency() - 1;
using namespace std::chrono;
using namespace std::chrono_literals;

void executor::thread_function() {
    for(;;) {
        auto task = m_ready.try_pop();
        if(task) {
            if(*task == nullptr) {
                return;
            }
            task->resume();
            continue;
        }
        try_poll();
        auto task_b = m_ready.pop();
        if(!task_b) {
            m_ready.push(nullptr);
            return;
        }
        task_b.resume();
    }
}

void executor::try_poll() {
    if(m_ready.size_hint() < NUM_THREADS) {
        auto this_can_lock = can_poll_wait.try_lock();
        if(this_can_lock) {
            std::vector<std::coroutine_handle<>> wakeable_coroutines_a{};
            {
                std::unique_lock lk { can_poll_wait, std::adopt_lock };
                auto wakeable_coroutines_a = m_reactor.wait(true);
            }
            m_ready.push_bulk(wakeable_coroutines_a);
        }
    }
}

void executor::main_thread_function() {
    for(;;) {
        try_poll();
        auto task = m_ready.try_pop();
        if(task) {
            if(*task == nullptr) {
                return;
            }
            task->resume();
            continue;
        }

        std::vector<std::coroutine_handle<>> wakeable_coroutines{};
        {
            std::scoped_lock lk { can_poll_wait };
            wakeable_coroutines = m_reactor.wait(false);
        }
        m_ready.push_bulk(wakeable_coroutines);
    }
}

void executor::run() {
    for(unsigned i = 0; i < NUM_THREADS; i++) {
        m_threadpool.emplace_back(&executor::thread_function, this);
    }
    main_thread_function();
    for(auto& thd : m_threadpool) {
        thd.join();
    }
}

root_task make_root_task(task<void> task) {
    co_await task;
    executor& global_executor = executor_singleton();
    auto numtasks = global_executor.num_tasks.fetch_sub(1, std::memory_order_relaxed);
    if(numtasks == 1) {
        global_executor.m_ready.push(nullptr);
    }
}

// enqueues an asynchronous task for the executor to run when resources are available
void executor::spawn(task<void> taskob) {
    auto root = make_root_task(std::move(taskob));
    num_tasks.fetch_add(1, std::memory_order_relaxed);
    m_ready.push(root.m_coroutine);
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


