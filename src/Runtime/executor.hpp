//
//  executor.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 15/04/2023.
//

#ifndef executor_hpp
#define executor_hpp

#include "reactor.hpp"
#include "task.hpp"

#include <stdio.h>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include <condition_variable>
#include <unordered_map>
#include <queue>
#include <optional>
#include <span>
#include "blocking_queue.hpp"

using namespace std::chrono;
using namespace std::chrono_literals;


class executor {
public:
    friend void async_spawn(task<void> subtask);
    friend void run(task<void> main_task);
    friend root_task make_root_task(task<void> task);
    friend executor& executor_singleton();
    
    reactor m_reactor;
private:
    executor() = default;
    blocking_queue<std::coroutine_handle<>> m_ready;
    std::vector<std::thread> m_threadpool;
    std::atomic<int> num_tasks;
    std::mutex can_poll_wait;
    
    void run();
    void spawn(task<void> subtask);
    void thread_function();
    void main_thread_function();
    void try_poll();
    void notify_runtime();
    friend struct yield_coroutine;
};

executor& executor_singleton();
void async_spawn(task<void> subtask);
void run(task<void> main_task);

struct yield_coroutine {
    bool await_ready() const noexcept {
        return false;
    }
    void await_suspend(std::coroutine_handle<> handle) noexcept {
        auto& global_executor = executor_singleton();
        global_executor.m_ready.push(handle);
    }
    void await_resume() noexcept { }
};

#endif // executor_hpp
