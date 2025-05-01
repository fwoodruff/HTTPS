//
//  h2proto.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//

#ifndef http2_hpp
#define http2_hpp

#include "h2_ctx.hpp"
#include "../../TCP/tcp_stream.hpp"
#include "../../global.hpp"
#include "../../Runtime/task.hpp"
#include "../../Runtime/async_mutex.hpp"
#include "../../Runtime/concurrent_queue.hpp"
#include "hpack.hpp"
#include "h2awaitable.hpp"
#include "h2frame.hpp"
#include <queue>
#include <unordered_map>
#include <memory>
#include <string>
#include <functional>

namespace fbw {

// we ensure single threaded-ness by demanding that every time the coroutine resumes from a different thread, we yield, placing it on this thread's executor
// every task must end in such a yield if it may have entered a different thread

struct rw_handle {
    std::coroutine_handle<> handle;
    bool is_reader; // or writer
};

class HTTP2 : public std::enable_shared_from_this<HTTP2> {

public:
    [[nodiscard]] task<void> client();
    HTTP2(std::unique_ptr<stream> stream, std::function< task<bool>(http_ctx& )> handler);
    ~HTTP2();
    HTTP2(const HTTP2&) = delete;
    HTTP2& operator=(const HTTP2&) = delete;
    
    h2_context h2_ctx;
    std::unordered_map<uint32_t, rw_handle> m_coros; // window updates
    std::deque<std::coroutine_handle<>> m_writers; // back-pressure
    std::mutex m_coro_mut;

    std::unique_ptr<stream> m_stream;
    friend class h2_stream;
    std::function<task<bool>(http_ctx&)> m_handler;
    bool is_blocking_read = false; // todo: friend awaitable?
private:
    [[nodiscard]] task<bool> connection_startup();
    [[nodiscard]] task<stream_result> send_outbox(bool flush = true);
    bool extract_and_handle();
    void handle_frame(h2frame& frame);
    bool resume_back_pressure();
    async_mutex m_async_mut;
    uint32_t last_coro_id = 0;
    std::deque<uint8_t> m_read_buffer;
};

std::pair<std::unique_ptr<h2frame>, bool> extract_frame(std::deque<uint8_t>& buffer);

task<void> handle_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id);

} // namespace fbw

#endif // http2_hpp