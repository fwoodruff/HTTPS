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
    class lockable;
    class scope_guard {
    public:
        scope_guard(const scope_guard&) = delete;
        scope_guard& operator=(const scope_guard&) = delete;
        scope_guard(scope_guard&&);
        scope_guard& operator=(scope_guard&&);
        ~scope_guard();
    private:
        friend class lockable;
        scope_guard(async_mutex*);
        async_mutex* m_ctx = nullptr;
    };

    class lockable {
    public:
        lockable(async_mutex* ctx);
        ~lockable();
        bool await_ready() const noexcept;
        bool await_suspend(std::coroutine_handle<> awaiting_coroutine) noexcept;
        scope_guard await_resume();
    private:
        bool is_enqueued = false;
        async_mutex* m_ctx;
    };
    [[nodiscard("should co_await")]] lockable lock();
private:
    void unlock();
    bool locked = false;
    std::mutex m_mut;
    std::queue<std::coroutine_handle<>> m_queue;
};

}

#endif // async_mutex_hpp