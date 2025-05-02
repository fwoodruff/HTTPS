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

static const size_t NUM_THREADS = std::thread::hardware_concurrency();
using namespace std::chrono;
using namespace std::chrono_literals;

void executor::notify_runtime() {
    m_ready.push(nullptr);
    m_reactor.notify();
}

void executor::thread_function() {
    for(;;) {
        auto task = m_ready.try_pop();
        if(task) {
            if(*task == nullptr) {
                notify_runtime();
                return;
            }
            task->resume();
            continue;
        }
        try_poll();
        auto task_b = m_ready.pop();
        if(!task_b) {
            notify_runtime();
            return;
        }
        task_b.resume();
    }
}

void executor::try_poll() {
    auto this_can_lock = can_poll_wait.try_lock();
    if(this_can_lock) {
        std::vector<std::coroutine_handle<>> wakeable_coroutines{};
        {
            std::unique_lock lk { can_poll_wait, std::adopt_lock };
            wakeable_coroutines = m_reactor.wait(true);
        }
        m_ready.push_bulk(std::move(wakeable_coroutines));
    }
}

int executor::resume_batch(size_t batch_size) {
    for (size_t i = 0; i < batch_size; ++i) {
        auto task = m_ready.try_pop();
        if (!task) {
            return i;
        }
        if (*task == nullptr) {
            notify_runtime();
            return -1;
        }
        task->resume();
    }
    return batch_size;
}

void executor::main_thread_function() {
    for(;;) {
        try_poll();
        int num_tasks = resume_batch(((m_ready.size_hint() + 1)/ NUM_THREADS) + 1);
        if(num_tasks < 0) { // signals to shut down the thread
            break;
        }
        if(num_tasks > 0) {
            continue;
        }
        std::vector<std::coroutine_handle<>> wakeable_coroutines{};
        {
            std::scoped_lock lk { can_poll_wait };
            wakeable_coroutines = m_reactor.wait(false);
        }
        m_ready.push_bulk(std::move(wakeable_coroutines));
    }
}

void executor::run() {
    // On the good-connection high-load path: the reactor is rarely used and we push and pull to the task queue.
    // On the bad-connection high-load path: only the main thread polls the reactor, with other threads putting tasks to sleep on the reactor.
    // When machine cores are not dedicated to this program, all threads make haphazard attempts to interact with both the task queue and the reactor.
    // When idle, the main thread blocks on the reactor, and other threads block on the task queue.
    assert(NUM_THREADS > 0);
    for(unsigned i = 0; i < NUM_THREADS - 1; i++) {
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
        std::atomic_thread_fence(std::memory_order::acquire);
        assert(global_executor.num_tasks.load() == 0);
        global_executor.m_ready.push(nullptr);
    }
}

// enqueues an asynchronous task for the executor to run when resources are available
void executor::spawn(task<void> taskob) {
    auto root = make_root_task(std::move(taskob));
    num_tasks.fetch_add(1, std::memory_order_relaxed);
    m_ready.push(root.m_coroutine);
}

void executor::commence(task<void> taskob) {
    auto root = make_root_task(std::move(taskob));
    num_tasks.fetch_add(1, std::memory_order_relaxed);
    root.m_coroutine.resume();
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

void sync_spawn(task<void> subtask) {
    auto& exec = executor_singleton();
    exec.commence(std::move(subtask));
}

// thread pool with a reactor
executor& executor_singleton() {
    static executor global_executor;
    return global_executor;
}


