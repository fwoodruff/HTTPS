//
//  async_mutex.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/03/2025.
//

#include "async_mutex.hpp"
#include "../Runtime/task.hpp"

#include <utility>

namespace fbw {

async_mutex::lockable async_mutex::lock() {
    return lockable {this};
}

void async_mutex::unlock() {
    std::coroutine_handle<> atask = nullptr;
    {
        std::scoped_lock lk {m_mut};
        if(!locked) {
            return;
        }
        if(m_queue.empty()) {
            locked = false;
            return;
        }
        
        atask = m_queue.front();
        m_queue.pop();
    }
    atask.resume();
}

async_mutex::lockable::lockable(async_mutex* ctx) : m_ctx(ctx) {}

async_mutex::lockable::~lockable() {
    assert(!is_enqueued);
}

bool async_mutex::lockable::await_ready() const noexcept {
    return false;
}

bool async_mutex::lockable::await_suspend(std::coroutine_handle<> coroutine) {
    std::scoped_lock lk { m_ctx->m_mut };
    if(std::exchange(m_ctx->locked, true)) {
        m_ctx->m_queue.push(coroutine);
        is_enqueued = true;
        return true;
    }
    return false;
}

async_mutex::scope_guard async_mutex::lockable::await_resume() {
    is_enqueued = false;
    return scope_guard(m_ctx);
}

async_mutex::scope_guard::scope_guard(async_mutex* ctx) : m_ctx(ctx) {}
async_mutex::scope_guard::~scope_guard() {
    if(m_ctx) {
        m_ctx->unlock();
    }
}

async_mutex::scope_guard::scope_guard(scope_guard&& other) {
    m_ctx = std::exchange(other.m_ctx, nullptr);
}

async_mutex::scope_guard& async_mutex::scope_guard::operator=(scope_guard&& other) {
    if (this != &other) {
        m_ctx = std::exchange(other.m_ctx, nullptr);
    }
    return *this;
}

} // fbw
