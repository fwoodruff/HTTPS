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
#include "hpack.hpp"
#include "h2awaitable.hpp"
#include "h2frame.hpp"
#include <queue>
#include <unordered_map>
#include <memory>
#include <string>

namespace fbw {

struct setting_values {
    uint32_t header_table_size = SETTINGS_HEADER_TABLE_SIZE;
    uint32_t max_concurrent_streams = INITIAL_MAX_CONCURRENT_STREAMS;
    uint32_t initial_window_size = INITIAL_WINDOW_SIZE;
    uint32_t max_frame_size = MINIMUM_MAX_FRAME_SIZE;
    uint32_t max_header_size = HEADER_LIST_SIZE;
    bool push_promise_enabled = false;
};

enum stream_frame_state {
    headers_expected,
    headers_cont_expected,
    data_expected,
    trailer_expected,
    trailer_cont_expected,
    done,
};

struct stream_ctx {
    // connect these buffers to the application layer
    std::deque<uint8_t> inbox; // data for reading
    std::deque<uint8_t> outbox; // data for writing
    stream_frame_state client_sent_headers = headers_expected;
    bool server_data_done = false;
    std::vector<entry_t> m_received_headers;
    std::vector<entry_t> m_received_trailers;
    uint32_t m_stream_id;
    int32_t stream_current_window_remaining; // how much data we can send
    int32_t stream_current_receive_window_remaining; // how much data we can receive
    stream_state strm_state = stream_state::idle;
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
    std::optional<uint32_t> receive_peer_frame(const h2frame& frame);

    // receive data from stream (application)
    // write full amount to stream buffer
    // assesses windowing allowances
    // updates internal state
    // enqueues sendable to outbox
    // returns true if WINDOW_FRAME receipt required to continue
    stream_result buffer_data(const std::span<const uint8_t> app_data, uint32_t stream_id, bool end);
    bool buffer_headers(const std::vector<entry_t>& headers, uint32_t stream_id);

    // read data into the supplied span
    // return std::nullopt if we need to block
    // returns 0 if read fails (connection closed)
    // returns true, if client data done
    std::optional<std::pair<size_t, bool>> read_data(const std::span<uint8_t> app_data, uint32_t stream_id);
    std::vector<entry_t> get_headers(uint32_t stream_id);

    // todo: remove need for these functions?
    bool can_resume(uint32_t stream_id, bool as_reader);
    stream_result is_closed(uint32_t stream_id);

    void close_connection();
    
    // returns bytes to send and whether that's the end of data 
    std::pair<std::deque<ustring>, bool> extract_outbox(); 
    
private:
    std::optional<uint32_t> receive_data_frame(const h2_data& frame);
    std::optional<uint32_t> receive_headers_frame(const h2_headers& frame);
    std::optional<uint32_t> receive_continuation_frame(const h2_continuation& frame);
    uint32_t receive_rst_stream(const h2_rst_stream& frame);
    void receive_peer_settings(const h2_settings& frame);
    std::optional<uint32_t> receive_window_frame(const h2_window_update& frame);
    void raise_stream_error(h2_code, uint32_t stream_id);
    void enqueue_goaway(h2_code code, std::string message);
    stream_result stage_buffer(stream_ctx& stream); // returns suspend

    // todo:
    // after stage_buffer we always check if the stream needs to be deleted.
    // receiving a connection window frame we need to run a lot of stage buffer calls

    hpack m_hpack;
    std::deque<ustring> outbox; // send to network
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
};

}

#endif