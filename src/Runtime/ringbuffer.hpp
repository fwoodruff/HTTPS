#include "../coroutine_incl.hpp"
#include "executor.hpp"
#include "../HTTP/string_utils.hpp"
namespace fbw {

template<typename T> 
class ringbuffer {
    constexpr static size_t buffer_size = 6;
    std::array<T, buffer_size> buffer { };

    bool success = true;
    int m_write_index = 0;
    int m_read_index = 0;
    async_condition_variable wait_enqueue;
    async_condition_variable wait_dequeue;
    std::mutex m;

    bool is_full() const {
        return (m_write_index + 1) % buffer_size == m_read_index;
    }

    bool is_empty() const {
        return m_write_index == m_read_index;
    }
public:

    task<bool> enqueue(T value) {
        {
            std::unique_lock lk { m };
            while (is_full()) {
                lk.unlock();
                co_await wait_enqueue;
                lk.lock();
            }
            if(!success) {
                co_return false;
            }
            buffer[m_write_index] = std::move(value);
            m_write_index = (m_write_index + 1) % buffer_size;
            
        }
        wait_dequeue.notify_one();
        co_return true;
    }

    task<T> dequeue() {
        std::unique_lock lk { m }; 
        while(is_empty()) {
            lk.unlock();
            co_await wait_dequeue;
            lk.lock();
        }

        T value = std::move(buffer[m_read_index]);
        m_read_index = (m_read_index + 1) % buffer_size;
        lk.unlock();
        wait_enqueue.notify_one();
        co_return value;
    }

    void fast_fail() {
        {
            std::unique_lock lk { m };
            success = false;
        }
        wait_enqueue.notify_all();
    }
};

} // fbw