//
//  h2stream.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/11/2024.
//

#ifndef h2stream_hpp
#define h2stream_hpp

#include "h2frame.hpp"
#include "hpack.hpp"
#include "../../Runtime/task.hpp"
#include "../../global.hpp"
#include "../../TCP/tcp_stream.hpp"

#include <queue>

namespace fbw {

// revisit
enum stream_frame_state {
    headers_expected,
    headers_cont_expected,
    data_expected,
    trailer_expected,
    trailer_cont_expected,
    done,
};

class HTTP2;

class h2_stream : public http_ctx, public std::enable_shared_from_this<h2_stream> {
public:
    int64_t stream_current_window_remaining = INITIAL_WINDOW_SIZE;
    uint32_t m_stream_id;

    stream_state state = stream_state::idle;
    stream_frame_state client_sent_headers = headers_expected;
    stream_frame_state server_sent_headers = headers_expected;
    std::vector<entry_t> m_received_headers;
    std::vector<entry_t> m_received_trailers;
    void receive_headers(std::vector<entry_t> headers); // populate headers
    void receive_trailers(std::vector<entry_t> headers); // populate headers after data
    std::queue<h2_data> inbox;

    std::coroutine_handle<> m_reader { nullptr };
    std::coroutine_handle<> m_writer { nullptr };

    std::coroutine_handle<> m_read_headers { nullptr };

    task<stream_result> write_headers(const std::vector<entry_t>& headers, bool end = false) override;
    task<stream_result> write_data(std::span<const uint8_t> data, bool end = true) override;
    task<stream_result> read_headers(std::vector<entry_t>& headers) override;

    std::weak_ptr<HTTP2> wp_connection;

    ~h2_stream();
};

} // namespace

#endif