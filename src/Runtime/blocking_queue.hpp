
#ifndef blocking_queue_hpp
#define blocking_queue_hpp

#include <stdio.h>
#include <queue>
#include <vector>
#include <optional>
#include <semaphore>
#include "concurrent_queue.hpp"

template<typename T>
class blocking_queue {
public:
    void push(T value) {
        m_queue.push(value);
        hint_size.fetch_add(1, std::memory_order_relaxed);
        m_sem.release();
    }
    void push_bulk(std::vector<T> values) {
        if(values.empty()) {
            return;
        }
        auto size = values.size();
        m_queue.push_bulk(std::move(values));
        hint_size.fetch_add(size, std::memory_order_relaxed);
        m_sem.release(size);
    }
    std::optional<T> try_pop() {
        bool acqu = m_sem.try_acquire();
        if(!acqu) {
            return std::nullopt;
        }
        auto res = m_queue.try_pop();
        hint_size.fetch_sub(1, std::memory_order_relaxed);
        return res;
    }
    T pop() {
        m_sem.acquire();
        auto res = *m_queue.try_pop();
        hint_size.fetch_sub(1, std::memory_order_relaxed);
        return res;
    }
    size_t size_hint() {
        return hint_size.load(std::memory_order_relaxed);
    }
private:
    std::atomic<int> hint_size = 0;
    std::counting_semaphore<> m_sem{0};
    concurrent_queue<T> m_queue;
};

#endif // blocking_queue_hpp