
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
#include <semaphore>

#ifndef concurrent_queue_hpp
#define concurrent_queue_hpp


// todo: work stealing or lock-freedom rather than global locking
template<typename T>
class blocking_queue {
public:
    void push(T value) {
        std::unique_lock lk { m_mut_back };
        m_queue.push(std::move(value));
        hint_size.fetch_add(1, std::memory_order_relaxed);
        m_sem.release();
    }
    void push_bulk(std::vector<T> values) {
        if(values.empty()) {
            return;
        }
        std::unique_lock lk { m_mut_back };
        for(auto&& value : values) {
            m_queue.push(std::move(value));
        }
        hint_size.fetch_add(values.size(), std::memory_order_relaxed);
        m_sem.release(values.size());
    }
    std::optional<T> try_pop() {
        bool acqu = m_sem.try_acquire();
        if(!acqu) {
            return std::nullopt;
        }
        return pop_impl();
    }
    T pop() {
        m_sem.acquire();
        return *pop_impl();
    }
    size_t size_hint() {
        return hint_size.load(std::memory_order_relaxed);
    }
private:
    std::optional<T> pop_impl() {
        std::unique_lock lk { m_mut_front };
        auto ret = std::move(m_queue.front());
        m_queue.pop();
        hint_size.fetch_sub(1, std::memory_order_relaxed);
        return ret;
    }

    std::atomic<int> hint_size = 0;
    std::counting_semaphore<> m_sem{0};
    std::mutex m_mut_front;
    std::mutex m_mut_back;
    std::queue<T> m_queue;
};

#endif // concurrent_queue_hpp