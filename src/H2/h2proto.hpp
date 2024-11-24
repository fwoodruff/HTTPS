//
//  h2proto.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//

#ifndef http2_hpp
#define http2_hpp

#include "../TCP/tcp_stream.hpp"
#include "../global.hpp"
#include "../Runtime/task.hpp"
#include "../Runtime/concurrent_queue.hpp"
#include "hpack.hpp"
#include "h2awaitable.hpp"
#include "h2frame.hpp"
#include <queue>
#include <unordered_map>
#include <memory>
#include <string>

namespace fbw {

// we ensure single threaded-ness by demanding that every time the coroutine resumes from a different thread, we yield, placing it on this thread's executor
// every task must end in such a yield if it may have entered a different thread


enum stream_frame_state {
    headers_expected,
    continuation_expected,
    data_pp_trailers_expected,
    trailer_continuation_expected,
    done,
};

constexpr size_t MIN_FRAME_SIZE = 16384;
constexpr size_t MAX_FRAME_SIZE = 16777215;
constexpr size_t MAX_WINDOW_SIZE = 0x7fffffff;
constexpr size_t INITIAL_MAX_CONCURRENT_STREAMS = 0x7fffffff;
constexpr int32_t INITIAL_WINDOW_SIZE = 65535;
constexpr size_t HEADER_LIST_SIZE = 0x7fffffff;

class h2_stream {
public:
    int64_t stream_current_window_remaining = INITIAL_WINDOW_SIZE;

    stream_state state = stream_state::idle;
    stream_frame_state client_sent_headers = headers_expected;
    stream_frame_state server_sent_headers = headers_expected;
    std::string method;
    std::string path;
    std::string scheme;
    std::string authority;
    std::vector<entry_t> m_received_headers;
    std::vector<entry_t> m_received_trailers;
    void receive_headers(std::vector<entry_t> headers); // populate headers
    void receive_trailers(std::vector<entry_t> headers); // populate headers after data
    std::queue<h2_data> inbox;

    std::coroutine_handle<> m_reader { nullptr };
    std::coroutine_handle<> m_writer { nullptr };

    ~h2_stream();
};

struct setting_values {
    bool push_promise_enabled = true;
    uint32_t max_concurrent_streams = 0x7fffffff;
    int32_t initial_window_size = 65535;
    uint32_t max_frame_size = 16384;
    uint32_t max_header_size = 0x7fffffff;
};

class HTTP2 : public std::enable_shared_from_this<HTTP2> {

public:
    [[nodiscard]] task<void> client();
    HTTP2(std::unique_ptr<stream> stream, std::string folder);
    ~HTTP2();

    [[nodiscard]] task<stream_result> handle_frame(const h2frame& frame);
    [[nodiscard]] task<stream_result> handle_peer_settings(h2_settings settings);
    void handle_headers_frame(const h2_headers& frame);
    void handle_continuation_frame(const h2_continuation& frame);
    void handle_rst_stream(const h2_rst_stream& frame);
    void handle_data_frame(const h2_data& frame);
    [[nodiscard]] task<stream_result> handle_window_frame(const h2_window_update& frame);

    hpack m_hpack;
    std::unordered_map<size_t, std::shared_ptr<h2_stream>> m_h2streams; // contains all streams but not all coroutines
    // a thread may choose to post itself onto a 'executor' to bring its execution onto non-competing threads - implement later
    setting_values server_settings; // applies to server, sent by client
    setting_values client_settings;
    
    std::unique_ptr<stream> m_stream;
    std::queue<std::coroutine_handle<>> waiters_global;
    std::string m_folder;
    int64_t connection_current_window_remaining;
    uint32_t last_stream_id; // most recent id
    bool received_settings;
    bool awaiting_settings_ack;
    bool notify_close_sent;
    
    [[nodiscard]] task<void> send_goaway(h2_code code, std::string message);
    [[nodiscard]] task<stream_result> raise_stream_error(h2_code code, uint32_t stream_id);
};

std::pair<std::unique_ptr<h2frame>, bool> extract_frame(ustring& buffer);

} // namespace fbw

#endif // http2_hpp