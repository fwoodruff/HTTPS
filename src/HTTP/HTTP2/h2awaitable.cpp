//
//  h2awaitable.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 21/09/2024.
//

#include "h2awaitable.hpp"
#include "h2frame.hpp"
#include "h2proto.hpp"
#include "h2stream.hpp"
#include <span>

using namespace std::chrono_literals;
using namespace std::chrono;

namespace fbw {

// Write data

h2writeable::h2writeable(std::weak_ptr<HTTP2> h2_contx, uint32_t stream_id)
    : m_h2_contx(h2_contx), m_stream_id(stream_id) {}

bool h2writeable::await_ready() const noexcept {
    return false;
}

bool h2writeable::await_suspend(std::coroutine_handle<> continuation) {
    auto h2_contx = m_h2_contx.lock();
    if(!h2_contx) {
        return false;
    }
    std::scoped_lock lk { h2_contx->m_coro_mut };
    h2_contx->m_coros.insert({m_stream_id, {continuation, false}});
    return true;
}

stream_result h2writeable::await_resume() {
    auto h2_contx = m_h2_contx.lock();
    if(!h2_contx) {
        return stream_result::closed; // connection closed
    }
    auto& cx = h2_contx->h2_ctx;
    return cx.is_closed(m_stream_id);
}

// Read data
// todo: alias the pointer to the context
h2readable::h2readable(std::weak_ptr<HTTP2> connection, int32_t stream_id, const std::span<uint8_t> data) :
    m_h2_contx(connection), m_stream_id(stream_id), m_data(data) {
        assert(!data.empty());
}

bool h2readable::await_suspend(std::coroutine_handle<> continuation) {
    auto h2_contx = m_h2_contx.lock();
    if(!h2_contx) {
        return false;
    }
    auto& cx = h2_contx->h2_ctx;
    m_bytes_read = cx.read_data(m_data, m_stream_id);
    if(m_bytes_read == std::nullopt) {
        std::scoped_lock lk { h2_contx->m_coro_mut };
        h2_contx->m_coros.insert({m_stream_id, {continuation, true}});
        return true;
    }
    return false;
}

std::pair<size_t, bool> h2readable::await_resume() {
    auto h2_contx = m_h2_contx.lock();
    if(!h2_contx) {
        return {0, true};
    }
    if(m_bytes_read == std::nullopt) {
        auto& cx = h2_contx->h2_ctx;
        m_bytes_read = cx.read_data(m_data, m_stream_id);
    }
    assert(m_bytes_read != std::nullopt);
    return *m_bytes_read;
}

bool h2readable::await_ready() const noexcept {
    return false;
}

// to do: reading trailers

} // namespace
