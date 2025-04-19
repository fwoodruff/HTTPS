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
            auto resa = co_await send_outbox();
            if(resa != stream_result::ok) {
                co_return;
            }
        } while(extract_and_handle());
        auto res = co_await m_stream->read_append(m_read_buffer, project_options.session_timeout);
        if(res != stream_result::ok) {
            std::unordered_map<uint32_t, rw_handle> m_coros_local;
            h2_ctx.close_connection();
            {
                std::scoped_lock lk(m_coro_mut);
                m_coros_local = std::exchange(m_coros, {});
            }
            co_await send_outbox();
            for(auto c : m_coros_local) {
                c.second.handle.resume();
            }
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
    std::cout << "received: " << frame.pretty() << std::endl;
    auto streams_to_wake = h2_ctx.receive_peer_frame(frame);
    std::vector<std::coroutine_handle<>> waking;
    for(auto strm : streams_to_wake) {
        if(strm.m_action == wake_action::new_stream) {
            sync_spawn(handle_stream(weak_from_this(), strm.stream_id));
        } else {
            std::scoped_lock lk { m_coro_mut };
            auto it = m_coros.find(strm.stream_id);
            if(it != m_coros.end()) {
                if((it->second.is_reader == (strm.m_action == wake_action::wake_read)) or strm.m_action == wake_action::wake_any) {
                    waking.push_back(it->second.handle);
                    m_coros.erase(it);
                }
            }
        }
    }
    for(auto handle : waking) {
        handle.resume();
    }
    return;
}

task<stream_result> HTTP2::send_outbox() {
    guard g(&m_async_mut);
    co_await m_async_mut.lock();
    auto [data_contiguous, closing] = h2_ctx.extract_outbox();
    while(!data_contiguous.empty()) {
        auto packet = std::move(data_contiguous.front());
        data_contiguous.pop_front();
        auto res = co_await m_stream->write(std::move(packet), project_options.session_timeout);
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
    while (m_read_buffer.size() < connection_init.size()) {
        auto res = co_await m_stream->read_append(m_read_buffer,
                                                 project_options.keep_alive);
        if (res == stream_result::closed) {
            co_return false;
        }
    }
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
    auto conn = connection.lock();
    if(!conn) {
        co_return;
    }
    auto hcx = std::make_shared<h2_stream> (connection, stream_id);
    assert(hcx != nullptr);
    try {
        co_await conn->m_handler(hcx);
    } catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
    }
    if(!hcx->is_done()) {
        co_await hcx->write_data(std::span<uint8_t> {}, true);
    }
    
    std::scoped_lock lk { conn->m_coro_mut };
    conn->m_coros.erase(stream_id);
    co_return;
}

HTTP2::HTTP2(std::unique_ptr<stream> stream, std::function<task<bool>(std::shared_ptr<http_ctx>)> handler) :
    m_stream(std::move(stream)), m_handler(handler) {}

HTTP2::~HTTP2() {
    assert (m_coros.empty());
}


} // namespace 

