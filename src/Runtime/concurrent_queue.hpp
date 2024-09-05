
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

#ifndef concurrent_queue_hpp
#define concurrent_queue_hpp

template<typename T>
class concurrent_queue {
public:
    void push(T value) {
        std::unique_lock lk { m_mut };
        m_queue.push(std::move(value));
        size.fetch_add(1, std::memory_order_relaxed);
        m_cv.notify_one();
    }
    void push_bulk(std::vector<T> values) {
        if(values.empty()) {
            return;
        }
        std::unique_lock lk { m_mut };
        for(auto&& value : values) {
            m_queue.push(std::move(value));
        }
        size.fetch_add(values.size(), std::memory_order_relaxed);
        m_cv.notify_one();
    }
    std::optional<T> try_pop() {
        std::unique_lock lk { m_mut };
        if(m_queue.empty()) {
            return std::nullopt;
        }
        auto ret = m_queue.front();
        m_queue.pop();
        size.fetch_sub(1, std::memory_order_relaxed);
        return ret;
    }
    T pop() {
        std::unique_lock lk { m_mut };
        m_cv.wait(lk, [&]{
            return !m_queue.empty();
        });
        auto ret = m_queue.front();
        m_queue.pop();
        size.fetch_sub(1, std::memory_order_relaxed);
        return ret;
    }
    size_t size_hint() {
        return size.load(std::memory_order_relaxed);
    }
private:
    std::atomic<int> size = 0;
    std::condition_variable m_cv;
    std::mutex m_mut;
    std::queue<T> m_queue;
};

#endif // concurrent_queue_hpp