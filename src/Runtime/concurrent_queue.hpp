
#include <stdio.h>
#include <mutex>
#include <queue>
#include <vector>
#include <queue>
#include <optional>
#include <semaphore>

#ifndef concurrent_queue_hpp
#define concurrent_queue_hpp

template<typename T>
class concurrent_queue {
public:
    void push(T value) {
        std::unique_lock lk { m_mut_back };
        m_queue.push(std::move(value));
    }
    void push_bulk(std::vector<T> values) {
        if(values.empty()) {
            return;
        }
        std::unique_lock lk { m_mut_back };
        for(auto&& value : values) {
            m_queue.push(std::move(value));
        }
    }
    std::optional<T> try_pop() {
        std::unique_lock lk { m_mut_front };
        auto ret = std::move(m_queue.front());
        m_queue.pop();
        return ret;
    }
private:
    std::mutex m_mut_front;
    std::mutex m_mut_back;
    std::queue<T> m_queue;
};

#endif // concurrent_queue_hpp