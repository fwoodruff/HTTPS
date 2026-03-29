//
//  task.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 15/04/2023.
//

#ifndef task_hpp
#define task_hpp

#include <stdio.h>


#include <type_traits>
#include <concepts>
#include <atomic>
#include <optional>
#include <cassert>
#include <exception>
#include <utility>
#include <coroutine>
#include <thread>

struct promise_metadata {
    virtual ~promise_metadata() = default;
    std::thread::id affinity {};
};

inline std::coroutine_handle<promise_metadata> upcast(std::coroutine_handle<> h) noexcept {
    auto meta = std::coroutine_handle<promise_metadata>::from_address(h.address());
    promise_metadata& base = meta.promise();
    assert(dynamic_cast<promise_metadata*>(&base));
    return meta;
}

// pared down from Lewis Baker's cppcoro
template<class T> class task;

class task_promise_base : public promise_metadata {
public:
    struct final_awaitable {
        bool await_ready() const noexcept { return false; }
        template<typename PROMISE>
        std::coroutine_handle<> await_suspend(std::coroutine_handle<PROMISE> coro) noexcept {
            auto& p = coro.promise();
            if (p.m_started) {
                // Eager-start protocol — mirrors the uring_token release/acquire pattern:
                //   Release-store 'done' so the awaiter's acquire-load of 'done' sees it.
                //   Acquire-load 'cont' to close the window where the awaiter stored the
                //   handle between our done-store and this cont-load.
                p.m_eager_done.store(true, std::memory_order_release);
                void* ptr = p.m_eager_cont.load(std::memory_order_acquire);
                if (ptr) return std::coroutine_handle<>::from_address(ptr);
                return std::noop_coroutine(); // await_suspend will detect done=true
            }
            return p.m_continuation;
        }
        void await_resume() noexcept { }
    };
    std::suspend_always initial_suspend() noexcept { return {}; }
    final_awaitable final_suspend() noexcept { return {}; }
    template<typename PROMISE>
    void set_continuation(std::coroutine_handle<PROMISE> continuation) noexcept {
        if constexpr (std::derived_from<PROMISE, promise_metadata>) {
            affinity = continuation.promise().affinity;
        }
        m_continuation = continuation;
    }
    void unhandled_exception() {
        m_exception = std::current_exception();
    }

    // Eager-start support.
    // m_started is set by task::start() before resuming the coroutine.
    // final_suspend and task::awaitable::await_suspend use the release/acquire
    // atomic protocol on m_eager_done / m_eager_cont to avoid a race between
    // the task completing on one thread and the awaiter registering its handle
    // on another.
    bool m_started = false;
    std::atomic<bool>  m_eager_done { false };
    std::atomic<void*> m_eager_cont { nullptr }; // nullptr = no awaiter yet

protected:
    std::exception_ptr m_exception = nullptr;
private:
    std::coroutine_handle<> m_continuation;
};

template<typename T>
class task_promise final : public task_promise_base {
public:
    task_promise() noexcept {};
    ~task_promise() noexcept {
        if (init) {
            m_value.~T();
        }
    };

    template<typename U = T>
    void return_value(U&& value) noexcept {
        // copy elision does not occur in co_return statements
        ::new (static_cast<void*>(std::addressof(m_value))) T(std::forward<U>(value));
        init = true;
    }
    T& result() {
        if (m_exception) {
            std::rethrow_exception(m_exception);
        }
        return m_value;
    }
    task<T> get_return_object() noexcept;
private:
    union {
        T m_value;
    };
    bool init = false;
};

template<>
class task_promise<void> final : public task_promise_base {
public:
    void return_void() noexcept { }
    void result() {
        if (m_exception) {
            std::rethrow_exception(m_exception);
        }
    }
    task<void> get_return_object() noexcept;
};

template<typename T>
class task_promise<T&> final : public task_promise_base {
public:
    void return_value(T& value) noexcept { m_value = &value; }
    T& result() {
        if (m_exception) {
            std::rethrow_exception(m_exception);
        }
        return *m_value;
    }
    task<T&> get_return_object() noexcept;
private:
    T* m_value = nullptr;
};

template<typename T>
class task {
public:
    using promise_type = task_promise<T>;
    struct awaitable {
        std::coroutine_handle<promise_type> m_coroutine;

        bool await_ready() const noexcept {
            if (!m_coroutine || m_coroutine.done()) return true;
            if (m_coroutine.promise().m_started) {
                // For an eager-started task: check the atomic done flag (acquire
                // so we see the stored result before calling await_resume).
                return m_coroutine.promise().m_eager_done.load(std::memory_order_acquire);
            }
            return false;
        }
        template<class Promise>
        std::coroutine_handle<> await_suspend( std::coroutine_handle<Promise> awaiting_coroutine ) noexcept {
            auto& p = m_coroutine.promise();
            if (p.m_started) {
                // Eager-start protocol — mirrors the uring_token release/acquire pattern:
                //   Release-store 'cont' so final_suspend's acquire-load of 'cont' sees it.
                //   Acquire-load 'done' to close the window where final_suspend stored done
                //   between our cont-store and this done-load.
                p.m_eager_cont.store(awaiting_coroutine.address(), std::memory_order_release);
                if (p.m_eager_done.load(std::memory_order_acquire)) {
                    // Task completed between await_ready() and here; final_suspend saw
                    // cont==null and returned noop.  Resume the awaiter immediately.
                    return awaiting_coroutine;
                }
                // Not done yet; final_suspend will load our cont and resume us.
                return std::noop_coroutine();
            }
            p.set_continuation( awaiting_coroutine );
            return m_coroutine;
        }
        decltype(auto) await_resume() {
            return m_coroutine.promise().result();
        }
    };
    awaitable operator co_await() {
        return { m_coroutine };
    }

    task() noexcept : m_coroutine(nullptr)  {}
    task(const task&) = delete;
    task& operator=(const task&) = delete;
    ~task() {
        if (m_coroutine) {
            m_coroutine.destroy();
        }
    }
    task(task&& other) noexcept : m_coroutine(other.m_coroutine) {
        other.m_coroutine = nullptr;
    }
    task& operator=(task&& other) noexcept {
        if (&other != this) {
            if (m_coroutine) {
                m_coroutine.destroy();
            }
            m_coroutine = std::exchange(other.m_coroutine, nullptr);
        }
        return *this;
    }
    explicit task(std::coroutine_handle<promise_type> coroutine) : m_coroutine(coroutine) {}

    explicit operator bool() const noexcept { return m_coroutine != nullptr; }

    // Start the task without suspending the caller.
    //
    // Drives the task's coroutine until it first suspends (typically at an
    // io_uring SQE submission).  Returns immediately; the caller can do other
    // work and co_await the task later.  The result is retrieved via the normal
    // co_await path, which uses the eager-start atomic protocol to avoid a race
    // between the task completing on another thread and the awaiter registering.
    //
    // Requires: the task has not already been started or awaited.
    void start() {
        assert(m_coroutine && !m_coroutine.promise().m_started && !m_coroutine.done());
        m_coroutine.promise().m_started = true;
        m_coroutine.resume();
    }

private:
    std::coroutine_handle<promise_type> m_coroutine;
};

template<typename T>
task<T> task_promise<T>::get_return_object() noexcept {
    return task<T>{ std::coroutine_handle<task_promise>::from_promise(*this) };
}

inline task<void> task_promise<void>::get_return_object() noexcept {
    return task<void>{ std::coroutine_handle<task_promise>::from_promise(*this) };
}

template<typename T>
task<T&> task_promise<T&>::get_return_object() noexcept {
    return task<T&>{ std::coroutine_handle<task_promise>::from_promise(*this) };
}

// final_suspend performs cleanup.
// https://stackoverflow.com/questions/66406763/c-coroutine-leaking-memory-and-frame
// we need final_suspend to return suspend never because .destroy() does not perform proper cleanup
// within <experimental/coroutines>
class root_task {
public:
    struct promise_type : public promise_metadata {
        root_task get_return_object() noexcept {
            return root_task { std::coroutine_handle<promise_type>::from_promise(*this) };
        }
        void return_void() noexcept { }
        std::suspend_always initial_suspend() noexcept {
            return {};
        }
        std::suspend_never final_suspend() noexcept {
            return {};
        }
        void unhandled_exception() {
            assert(false);
        }
    };
    std::coroutine_handle<promise_type> m_coroutine;
};


#endif // task_hpp
