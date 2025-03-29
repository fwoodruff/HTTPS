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

// safe to unlock same async_mutex twice 
void async_mutex::maybe_unlock() {
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

bool async_mutex::lockable::await_ready() const noexcept {
    return false;
}

bool async_mutex::lockable::await_suspend(std::coroutine_handle<> coroutine) noexcept {
    std::scoped_lock lk { m_ctx->m_mut };
    if(std::exchange(m_ctx->locked, true)) {
        m_ctx->m_queue.push(coroutine);
        return true;
    }
    return false;
}

void async_mutex::lockable::await_resume() {}

guard::guard(async_mutex* ctx) : m_ctx(ctx) {}
guard::~guard() {
    assert( m_ctx != nullptr);
    m_ctx->maybe_unlock();
}

} // fbw
