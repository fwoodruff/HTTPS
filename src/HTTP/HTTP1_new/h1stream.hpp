//
//  h1stream.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 18/04/2025.
//

#ifndef h1stream_hpp
#define h1stream_hpp

#include "../../Runtime/task.hpp"
#include "../../global.hpp"
#include "../../TCP/tcp_stream.hpp"
#include "../http_ctx.hpp"
#include "../HTTP1_1/string_utils.hpp"
#include "../../TLS/protocol.hpp"
#include <functional>

namespace fbw {

class HTTP1 : public http_ctx {

public:
    [[nodiscard]] task<void> client();
    HTTP1(std::unique_ptr<stream> stream, callback handler);
    HTTP1(const HTTP1&) = delete;
    HTTP1& operator=(const HTTP1&) = delete;

    std::unique_ptr<stream> m_stream;
    
    std::vector<entry_t> get_headers() override;
    task<stream_result> write_headers(const std::vector<entry_t>& headers) override;
    task<stream_result> write_data(std::span<const uint8_t> data, bool end = false, bool do_flush = false) override;
    task<std::pair<stream_result, bool>> append_http_data(std::deque<uint8_t>& buffer) override;
    bool is_done() override;

    callback m_application_handler;
private:
    buffer m_buffered_writer;
    ssize_t content_length_to_read = 0;
    std::vector<entry_t> headers;
    std::deque<uint8_t> m_read_buffer; // todo: deque
};

} // namespace

#endif