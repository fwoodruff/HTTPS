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

// if after .resume() a coroutine hasn't landed back, await its return on the main event loop rather than blocking on read
// then keep writes on the main thread.

enum stream_frame_state {
    headers_expected,
    continuation_expected,
    data_pp_trailers_expected,
    trailer_continuation_expected,
    done,
};

class h2_stream {
public:
    int64_t stream_current_window = 0;
    // size_t m_stream_id; // implicit
    std::atomic<stream_state> state = stream_state::idle;
    stream_frame_state client_sent_headers = headers_expected;
    stream_frame_state server_sent_headers = headers_expected;
    std::unordered_map<std::string, std::string> m_received_headers;
    std::unordered_map<std::string, std::string> m_received_trailers;
    void receive_headers(std::unordered_map<std::string, std::string> headers); // populate headers
    void receive_trailers(std::unordered_map<std::string, std::string> headers); // populate headers
    std::queue<h2_data> inbox;

    std::atomic<std::coroutine_handle<>> m_reader { nullptr };
    std::atomic<std::coroutine_handle<>> m_writer { nullptr };

    ~h2_stream();
};

struct setting_values {
    bool push_promise_enabled = true;
    uint32_t compression_table_size = 4096;
    uint32_t max_concurrent_streams = 0x7fffffff;
    int32_t initial_window_size = 65535;
    uint32_t max_frame_size = 16384;
    uint32_t max_header_size = 0x7fffffff;
};

// When we receive a 'go-away', we might have a bunch of coroutine handles (and new ones may arrive)
// initially set a 'goaway sent' flag. 
class HTTP2 : public std::enable_shared_from_this<HTTP2> {

public:
    [[nodiscard]] task<void> client();
    HTTP2(std::unique_ptr<stream> stream, std::string folder);

    task<stream_result> handle_frame(const h2frame& frame);
    void process_streams();
    void set_peer_settings(h2_settings settings);
    void handle_headers_frame(const h2_headers& frame);
    void handle_continuation_frame(const h2_continuation& frame);
    void handle_rst_stream(const h2_rst_stream& frame);
    void handle_data_frame(const h2_data& frame);

    hpack m_hpack;

    bool notify_close_sent = false;
    std::unique_ptr<stream> m_stream;

    task<stream_result> read_append_safe(ustring &, std::optional<std::chrono::milliseconds> timeout);
    task<stream_result> write_safe(ustring data, std::optional<milliseconds> timeout);
    task<stream_result> write_close_safe(ustring data, std::optional<milliseconds> timeout);

    async_mutex co_mutex;
    
    std::unordered_map<size_t, std::shared_ptr<h2_stream>> m_h2streams; // contains all streams but not all coroutines, only updated by owner
    void* connection_owner = nullptr; // sentinel, do not resume


    // bookkeeping
    // - increment when stream is created (unique)
    // - decrement when resuming a stream coroutine (unique)
    // - leave when a stream coroutine suspends on write because window
    // - leave when a stream exits
    // - when a stream coroutine suspends on write (written some) - (runtime yield and) resume if we are not the owner otherwise increment (unique) // todo
    // - leave when a stream coroutine suspends on read
    // - increment when a stream data queue becomes non-empty or window widens (unique)

    // i.e. if all streams are 'elsewhere' or waiting for data, then we should suspend to read more data
    ssize_t processable_streams = 0; // todo, updates to this value (consider concurrency)

    std::string m_folder;
    uint32_t last_stream_id = 0; // most recent id

    setting_values server_settings; // applies to server, sent by client
    setting_values client_settings;

    bool received_settings = false;

    int64_t connection_current_window = 0;

    
    [[nodiscard]] task<void> send_goaway(h2_code);
};

std::vector<h2frame> extract_frames(ustring& buffer);


} // namespace fbw
#endif // http2_hpp