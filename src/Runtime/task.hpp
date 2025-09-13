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

#include <coroutine>



// pared down from Lewis Baker's cppcoro
template<class T> class task;

class task_promise_base {
public:
    struct final_awaitable {
        bool await_ready() const noexcept { return false; }
        template<typename PROMISE>
        std::coroutine_handle<> await_suspend(std::coroutine_handle<PROMISE> coro) noexcept {
            return coro.promise().m_continuation;
        }
        void await_resume() noexcept { }
    };
    std::suspend_always initial_suspend() noexcept { return {}; }
    final_awaitable final_suspend() noexcept { return {}; }
    void set_continuation(std::coroutine_handle<> continuation) { m_continuation = continuation; }
    void unhandled_exception() {
        m_exception = std::current_exception();
    }
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
        bool await_ready() const noexcept { return !m_coroutine || m_coroutine.done(); }
        std::coroutine_handle<> await_suspend( std::coroutine_handle<> awaiting_coroutine ) noexcept {
            m_coroutine.promise().set_continuation( awaiting_coroutine );
            return m_coroutine;
        }
        decltype(auto) await_resume() {
            return m_coroutine.promise().result();
        }
        std::coroutine_handle<promise_type> m_coroutine;
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
            m_coroutine = other.m_coroutine;
            other.m_coroutine = nullptr;
        }
        return *this;
    }
    explicit task(std::coroutine_handle<promise_type> coroutine) : m_coroutine(coroutine) {}
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
    struct promise_type {
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
