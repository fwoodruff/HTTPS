//
//  HTTP2.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 26/07/2024.
//


#ifndef http2_hpp
#define http2_hpp

#include "../TCP/tcp_stream.hpp"
#include "string_utils.hpp"
#include "../global.hpp"
#include "../Runtime/task.hpp"
#include "../Runtime/concurrent_queue.hpp"
#include "http2frame.hpp"
#include <queue>
#include <unordered_map>

#include <memory>
#include <string>

namespace fbw {

// if after .resume() a coroutine hasn't landed back, await its return on the main event loop rather than blocking on read
// then keep writes on the main thread.

class h2_stream {
public:
    int64_t stream_current_window = 0;
    size_t m_stream_id;
    stream_state state = stream_state::idle;
    bool client_sent_headers = false;
    bool server_sent_headers = false;
    std::unordered_map<std::string, std::string> m_received_headers;
    void receive_headers(std::unordered_map<std::string, std::string> headers); // populate headers
    std::queue<h2_data> inbox;

    std::atomic<std::coroutine_handle<>> m_reader { nullptr };
    std::atomic<std::coroutine_handle<>> m_writer { nullptr }; // atomic?

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

    concurrent_queue<std::pair<std::unique_ptr<h2frame>, std::chrono::milliseconds>> outbox;

    task<stream_result> handle_frame(const h2frame& frame);
    task<stream_result> process_streams();
    void set_peer_settings(h2_settings settings);
    void handle_client_headers(const h2_headers& frame);
    void handle_rst_stream(const h2_rst_stream& frame);
    std::unique_ptr<stream> m_stream;

    task<stream_result> write_one();
    task<stream_result> flush();

    std::unordered_map<uint32_t, ustring> HPACK;

    mutable std::mutex conn_mut;
    std::unordered_map<size_t, std::shared_ptr<h2_stream>> m_h2streams; // contains all streams but not all coroutines

    std::string m_folder;
    uint32_t last_stream_id = 0;

    setting_values server_settings; // applies to server, sent by client
    setting_values client_settings;

    std::atomic<uint32_t> running_streams = 0; // increment on resume, decrement on suspend
    // hard to safely block on both read and write while respecting lower levels' protocols, particularly close_notfiy
    // so instead, if we are waiting for a proxy call, block on the proxy not on read when nothing to do
    // later implement a way to block until either coroutine wakes

    bool received_settings = false;

    int64_t connection_current_window = 0;

    
    [[nodiscard]] task<void> send_goaway(h2_code);
};

std::vector<h2frame> extract_frames(ustring& buffer);

task<void> handle_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id);

} // namespace fbw
#endif // http2_hpp