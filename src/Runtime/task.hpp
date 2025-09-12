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

#include <iostream>

struct arena {
    std::size_t offset = 0;
    std::size_t capacity;
    std::byte buffer[];

    arena(std::size_t cap) : capacity(cap) {}

    void* allocate(std::size_t n, std::size_t alignment) {
        std::size_t aligned = (offset + alignment - 1) & ~(alignment - 1);
        if (aligned + n > capacity) throw std::bad_alloc{};
        void* p = buffer + aligned;
        offset = aligned + n;
        return p;
    }
};

template<class T>
struct arena_allocator {
    using value_type = T;
    std::shared_ptr<arena> backing;

    arena_allocator(std::shared_ptr<arena> a) noexcept : backing(a) {}
    template<class U>
    arena_allocator(const arena_allocator<U>& other) noexcept : backing(other.backing) {}

    T* allocate(std::size_t n) {
        std::cout << "arena alloc" << std::endl;
        return static_cast<T*>(backing->allocate(n * sizeof(T), alignof(T)));
    }
    void deallocate(T*, std::size_t) noexcept {
        std::cout << "arena dealloc" << std::endl;
        // no-op (bump allocator)
    }
};

inline std::shared_ptr<arena> make_arena(std::size_t cap) {
    std::size_t total = sizeof(arena) + cap * sizeof(std::byte);
    void* raw = ::operator new(total, std::nothrow);
    if (!raw) {
        return nullptr; // failed allocation
    }
    arena* a = new (raw) arena(cap);
    return std::shared_ptr<arena>(a, [](arena* p) {
        p->~arena();
        ::operator delete(p);
    });
}

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

    template<typename... ARGS>
    void* operator new(std::size_t size, std::allocator_arg_t, arena_allocator<std::byte>& ba, ARGS& ... args) {
        void* raw = ba.allocate(size + sizeof(arena_allocator<std::byte>) + sizeof(char));
        *reinterpret_cast<arena_allocator<std::byte>*>(static_cast<std::byte*>(raw) + size) = ba;
        *(static_cast<char*>(raw) + size + 1) = 1;
        return raw;
    }

    template<typename... ARGS>
    void* operator new(std::size_t size, ARGS& ... args) {
        void* raw = ::operator new(size + sizeof(arena_allocator<std::byte>));
        *(static_cast<char*>(raw) + size + 1) = 0;
        return raw;
    }

    void operator delete(void* p, std::size_t size) noexcept {
        auto ba_ind = (static_cast<char*>(p) + size + 1);
        auto ba_ptr = reinterpret_cast<arena_allocator<std::byte>*>(static_cast<std::byte*>(p) + size);
        if(*ba_ind == 0) {
            ::operator delete(p);
            return;
        }
        ba_ptr->deallocate(static_cast<std::byte*>(p), size);
        return;

    }
    
    task_promise() noexcept {}
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
