//
//  h2_ctx.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 03/04/2025.
//

#ifndef h2_ctx_hpp
#define h2_ctx_hpp

#include "../../TCP/tcp_stream.hpp"
#include "../../global.hpp"
#include "../../Runtime/task.hpp"
#include "../../Runtime/concurrent_queue.hpp"
#include "../../TLS/protocol.hpp"
#include "hpack.hpp"
#include "h2awaitable.hpp"
#include "h2frame.hpp"
#include <queue>
#include <unordered_map>
#include <memory>
#include <string>

namespace fbw {


struct stream_ctx {
    // connect these buffers to the application layer
    std::deque<uint8_t> inbox; // data for reading
    std::deque<uint8_t> outbox; // data for writing
    bool application_server_data_done = false;
    std::vector<uint8_t> header_block;
    std::vector<entry_t> m_received_headers;
    std::vector<entry_t> m_received_trailers;
    uint32_t m_stream_id;
    int32_t stream_current_window_remaining; // how much data we can send
    int32_t stream_current_receive_window_remaining; // how much data we can receive
    int32_t bytes_consumed_since_last_stream_window_update = 0;
    bool sent_rst = false;
    stream_state strm_state = stream_state::idle;
};

enum class wake_action {
    new_stream,
    wake_read,
    wake_write,
    wake_any
};

struct id_new {
    uint32_t stream_id;
    wake_action m_action;
};

class h2_context {
public:
    h2_context();

    // receives a frame from over the network
    // updates internal state for streams
    // saves to inbox for particular stream
    // enqueues errors and acks to outbox
    // returns the stream that can now make progress, and whether it is new
    // returns 0 for change at connection level
    std::vector<id_new> receive_peer_frame(const h2frame& frame);

    // todo: nonblocking write that only writes the allowed amount.
    stream_result buffer_data(const std::span<const uint8_t> app_data, uint32_t stream_id, bool end);
    bool buffer_headers(const std::vector<entry_t>& headers, uint32_t stream_id, bool end = false);

    // read data into the supplied span
    // return std::nullopt if we need to block
    // returns 0 if read fails (connection closed)
    // returns true, if client data done
    std::optional<std::pair<size_t, bool>> read_data(const std::span<uint8_t> app_data, uint32_t stream_id);
    std::vector<entry_t> get_headers(uint32_t stream_id);

    stream_result stream_status(uint32_t stream_id);

    void close_connection();
    void send_initial_settings();
    
    // returns bytes to send and whether that's the end of data 
    std::pair<std::deque<std::vector<uint8_t>>, bool> extract_outbox(bool flush);

private:
    std::vector<id_new> receive_data_frame(const h2_data& frame);
    std::vector<id_new> receive_headers_frame(const h2_headers& frame);
    std::vector<id_new> receive_continuation_frame(const h2_continuation& frame);
    std::vector<id_new> receive_rst_stream(const h2_rst_stream& frame);
    std::vector<id_new> receive_peer_settings(const h2_settings& frame);
    std::vector<id_new> receive_window_frame(const h2_window_update& frame);
    void raise_stream_error(h2_code, uint32_t stream_id);
    void enqueue_goaway(h2_code code, std::string message);
    stream_result stage_buffer(stream_ctx& stream); // returns suspend

    static constexpr int32_t WINDOW_UPDATE_INCREMENT_THRESHOLD = 32768;


    hpack m_hpack;
    store_buffer outbox; // send to network
    

    std::unordered_map<uint32_t, stream_ctx> stream_ctx_map; // processed by streams
    uint32_t last_server_stream_id;
    uint32_t last_client_stream_id;
    int32_t connection_current_window_remaining;
    int32_t connection_current_receive_window_remaining;
    setting_values server_settings;
    setting_values client_settings; // sent by client
    std::mutex m_mut;
    bool awaiting_settings_ack = false;
    bool go_away_sent = false;
    bool go_away_received = false; // if true, don't open new streams in inbox
    bool initial_settings_done = false;

    uint32_t headers_partially_sent_stream_id = 0;

    uint32_t bytes_consumed_since_last_connection_window_update = 0;
};

}

#endif