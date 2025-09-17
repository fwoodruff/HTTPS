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
    class scope_guard {
    public:
        scope_guard(const scope_guard&) = delete;
        scope_guard& operator=(const scope_guard&) = delete;
        scope_guard(scope_guard&&) noexcept;
        scope_guard& operator=(scope_guard&&) noexcept;
        ~scope_guard();

        scope_guard(async_mutex* m_ctx);

        bool await_ready() const noexcept;
        bool await_suspend(std::coroutine_handle<> awaiting_coroutine) noexcept;
        scope_guard await_resume();
    private:
        friend class lockable;
        async_mutex* m_ctx = nullptr;
        bool is_enqueued = false;
    };
    [[nodiscard("should co_await")]] scope_guard lock();
private:
    void unlock();
    bool locked = false;
    std::mutex m_mut;
    std::queue<std::coroutine_handle<>> m_queue;
};

}

#endif // async_mutex_hpp