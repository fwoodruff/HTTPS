//
//  executor.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 15/04/2023.
//

#include "executor.hpp"
#include <algorithm>
#include <mutex>
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

void executor::mark_done() {
    std::scoped_lock const lk {thread_mut};
    num_active_threads.fetch_sub(1, std::memory_order_relaxed);
    m_zombies.push_back(std::this_thread::get_id());
}

void executor::reap_done() {
    std::vector<std::thread::id> zombies;
    {
        std::scoped_lock const lk {thread_mut};
        zombies.swap(m_zombies);
    }
    if (zombies.empty()) {
        return;
    }
    std::vector<std::thread> to_join;
    {
        std::scoped_lock const lk {thread_mut};
        auto is_zombie = [&](const std::thread& t) {
            return std::ranges::find(zombies, t.get_id()) != zombies.end();
        };
        for (size_t i = 0; i < m_threadpool.size(); ) {
            if (is_zombie(m_threadpool[i])) {
                to_join.emplace_back(std::move(m_threadpool[i]));
                m_threadpool[i] = std::move(m_threadpool.back());
                m_threadpool.pop_back();
            } else {
                i++;
            }
        }
    }
    for (auto &t : to_join) {
        if (t.joinable()) {
            t.join();
        }
    }
}

void executor::thread_function() {
    for(;;) {
        auto task = m_ready.try_pop();
        if(task) {
            if(*task == nullptr) {
                notify_runtime();
                mark_done();
                return;
            }
            upcast(*task).promise().affinity = std::this_thread::get_id();
            task->resume();
            continue;
        }
        if(num_tasks.load() <= num_active_threads.load(std::memory_order_relaxed)) {
            mark_done();
            return;
        }
        try_poll();
        auto task_b = m_ready.pop();
        if(!task_b) {
            notify_runtime();
            mark_done();
            return;
        }
        upcast(task_b).promise().affinity = std::this_thread::get_id();
        task_b.resume();
    }
}

void executor::try_poll() {
    auto this_can_lock = can_poll_wait.try_lock();
    if(this_can_lock) {
        std::vector<std::coroutine_handle<>> wakeable_coroutines{};
        {
            std::unique_lock const lk { can_poll_wait, std::adopt_lock };
            wakeable_coroutines = m_reactor.wait(true);
        }
        m_ready.push_bulk(std::move(wakeable_coroutines));
    }
}

void executor::block_until_ready() {
    std::vector<std::coroutine_handle<>> wakeables;
    {
        std::scoped_lock const lk{ can_poll_wait };
        wakeables = m_reactor.wait(false);
    }
    m_ready.push_bulk(std::move(wakeables));
}

void executor::main_thread_function() {
    for(;;) {
        try_poll();
        auto task = m_ready.try_pop();
        if (!task) {
            block_until_ready();
            continue;
        }
        if (*task == nullptr) {
            notify_runtime();
            reap_done();
            return;
        }
        auto active = num_active_threads.load(std::memory_order::relaxed);
        if(num_tasks.load() > active + 3 && active < long(NUM_THREADS)) {
            std::scoped_lock const lk {thread_mut};
            num_active_threads.fetch_add(1, std::memory_order_relaxed);
            m_threadpool.emplace_back(&executor::thread_function, this);
        }
        reap_done();
        upcast(*task).promise().affinity = std::this_thread::get_id();
        task->resume();
    }
}

void executor::run() {
    // On the good-connection high-load path: the reactor is rarely used and we push and pull to the task queue.
    // On the bad-connection high-load path: only the main thread polls the reactor, with other threads putting tasks to sleep on the reactor.
    // When machine cores are not dedicated to this program, all threads make haphazard attempts to interact with both the task queue and the reactor.
    // When idle, the main thread blocks on the reactor, and other threads block on the task queue.
    assert(NUM_THREADS > 0);
    main_thread_function();
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
    root.m_coroutine.promise().affinity = std::this_thread::get_id();
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


