//
//  h2proto.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//

#include "../../Runtime/task.hpp"

#include "h2proto.hpp"
#include <queue>
#include "../../Runtime/executor.hpp"
#include "../../Application/http_handler.hpp"
#include "h2frame.hpp"
#include "h2awaitable.hpp"
#include "../../global.hpp"
#include "h2stream.hpp"

namespace fbw {

const std::string connection_init = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

task<void> HTTP2::client() {
    if(!co_await connection_startup()) {
        co_return;
    }
    for(;;) {
        do {
            auto res = co_await send_outbox();
            if(res != stream_result::ok) {
                co_await close_connection();
                co_return;
            }
        } while(extract_and_handle());
        auto res = co_await m_stream->read_append(m_read_buffer, project_options.keep_alive);
        if(res != stream_result::ok) {
            co_await close_connection();
            co_return;
        }
    }
}

bool HTTP2::extract_and_handle() {
    auto [frame, did_extract] = extract_frame(m_read_buffer);
    if(!did_extract) {
        return false;
    }
    if(frame == nullptr) {
        // unrecognised frame type
        return true;
    }
    handle_frame(*frame);
    return true;
}

void HTTP2::handle_frame(h2frame& frame) {
    // todo: return all streams to wake and get rid of 'can_resume'
    auto stream_to_wake = h2_ctx.receive_peer_frame(frame);
    if(stream_to_wake == std::nullopt) {
        return;
    }

    if(stream_to_wake > last_coro_id) { // todo: receive_peer_frame should signal this
        last_coro_id = *stream_to_wake;
        sync_spawn(handle_stream(weak_from_this(), *stream_to_wake));
        return;
    }
    std::vector<std::coroutine_handle<>> waking;
    {
        std::scoped_lock lk { m_coro_mut };
        if (stream_to_wake == 0) {
            for (auto it = m_coros.begin(); it != m_coros.end(); ) {
                auto [stream_id, handle] = std::move(*it);
                if (h2_ctx.can_resume(stream_id, handle.is_reader)) {
                    it = m_coros.erase(it);
                    waking.push_back(handle.handle);
                } else {
                    ++it;
                }
            }
        } else {
            auto it = m_coros.find(*stream_to_wake);
            if(it != m_coros.end()) {
                auto& handle = it->second;
                if(h2_ctx.can_resume(*stream_to_wake, handle.is_reader)) {
                    m_coros.erase(it);
                    waking.push_back(handle.handle);
                }
            }
        }
    }
    for(auto handle : waking) {
        handle.resume();
    }
    return;
}

task<void> HTTP2::close_connection() {
    h2_ctx.close_connection();
    co_await send_outbox();
    // co_await m_stream->close_notify(); // consider placement of this
}

// todo: need an async lock around claiming the mutex and then writing the buffer
// todo: extracting the outbox belongs in the sync logic

task<stream_result> HTTP2::send_outbox() {
    guard g(&m_async_mut);
    co_await m_async_mut.lock();
    auto [data_contiguous, closing] = h2_ctx.extract_outbox();
    if(!data_contiguous.empty()) {
        auto res = co_await m_stream->write(data_contiguous, project_options.session_timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
    }
    if(closing) {
        co_await m_stream->close_notify();
        co_return stream_result::closed;
    }
    co_return stream_result::ok;
}

task<bool> HTTP2::connection_startup() {
    assert(m_stream);
    do {
        auto res = co_await m_stream->read_append(m_read_buffer, project_options.keep_alive);
        if(res == stream_result::closed) {
            co_return false;
        }
        if(m_read_buffer.size() < connection_init.size()) {
            continue;
        }
    } while(false);
    for(size_t i = 0; i < connection_init.size(); i++) {
        if(connection_init[i] != m_read_buffer[i]) {
            co_return false;
        }
    }
    m_read_buffer = m_read_buffer.substr(connection_init.size());
    co_return true;
}

std::pair<std::unique_ptr<h2frame>, bool> extract_frame(ustring& buffer)  {
    if(buffer.size() >= 3) {
        auto size = try_bigend_read(buffer, 0, 3);
        if(size + H2_FRAME_HEADER_SIZE <= buffer.size()) {
            auto frame_bytes = buffer.substr(0, size + H2_FRAME_HEADER_SIZE);
            std::unique_ptr<h2frame> frame = h2frame::deserialise(frame_bytes);
            buffer = buffer.substr(size + H2_FRAME_HEADER_SIZE);
            return {std::move(frame), true};
        }
    }
    return {nullptr, false};
}

task<void> handle_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id) {
    auto hcx = std::make_shared<h2_stream> (connection, stream_id);
    assert(hcx != nullptr);
    co_await application_handler(hcx);
    //co_await hcx->write_data(std::span<uint8_t> {}, true); // todo: check if already sent
    auto conn = connection.lock();
    if(!conn) {
        co_return;
    }
    std::scoped_lock lk { conn->m_coro_mut };
    conn->m_coros.erase(stream_id);
    co_return;
}

HTTP2::HTTP2(std::unique_ptr<stream> stream, std::string folder) : m_stream(std::move(stream)), m_folder(folder){}

HTTP2::~HTTP2() {
    assert (m_coros.empty());
}


} // namespace 

