//
//  async_mutex.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/03/2025.
//

#ifndef async_mutex_hpp
#define async_mutex_hpp

#include <mutex>
#include <coroutine>
#include <queue>

namespace fbw {

class async_mutex {
public:
    class lockable {
        public:
        lockable(async_mutex* ctx);
        bool await_ready() const noexcept;
        bool await_suspend(std::coroutine_handle<> awaiting_coroutine) noexcept;
        void await_resume();
    private:
        async_mutex* m_ctx;
    };
    lockable lock();
    void maybe_unlock(); // multiple calls to maybe_unlock() acceptable
private:
    bool locked = false;
    std::mutex m_mut;
    std::queue<std::coroutine_handle<>> m_queue;
};

class guard {
public:
    guard(const guard&) = delete;
    guard& operator=(const guard&) = delete;
    guard(async_mutex*);
    ~guard();
private:
    async_mutex* m_ctx = nullptr;
};

}

#endif // async_mutex_hpp