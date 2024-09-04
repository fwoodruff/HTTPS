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

using namespace std::chrono;
using namespace std::chrono_literals;

template<typename T>
class concurrent_queue {
public:
    void push(T value) {
        if(value == nullptr) {
            std::terminate();
        }
        std::unique_lock lk { m_mut };
        m_queue.push(std::move(value));
        m_cv.notify_one();
    }
    std::optional<T> try_pop() {
        std::unique_lock lk { m_mut };
        if(m_queue.empty()) {
            return std::nullopt;
        }
        auto ret = m_queue.front();
        m_queue.pop();
        return ret;
    }
    T pop() {
        std::unique_lock lk { m_mut };
        m_cv.wait(lk, [&]{
            return !m_queue.empty();
        });
        auto ret = m_queue.front();
        m_queue.pop();
        return ret;
    }
    bool empty() {
        std::unique_lock lk { m_mut };
        return m_queue.empty();
    }
private:
    std::condition_variable m_cv;
    std::mutex m_mut;
    std::queue<T> m_queue;
};



class executor {
public:
    friend void async_spawn(task<void> subtask);
    friend void run(task<void> main_task);
    friend root_task make_root_task(task<void> task);
    friend executor& executor_singleton();
    
    reactor m_reactor;
private:
    executor() = default;
    
    std::mutex m_mut;
    std::condition_variable m_cond;
    concurrent_queue<std::coroutine_handle<>> m_ready;
    std::vector<std::thread> m_threadpool;
    int num_tasks;
    bool can_poll_wait = true;
    
    void run();
    void spawn(task<void> subtask);
    void thread_function();
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
        std::scoped_lock lk { global_executor.m_mut };
        global_executor.m_ready.push(handle);
    }
    void await_resume() noexcept { }
};

#endif // executor_hpp
