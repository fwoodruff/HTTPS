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
#include <functional>

namespace fbw {

class HTTP1 : public http_ctx, std::enable_shared_from_this<HTTP1> {

public:
    [[nodiscard]] task<void> client();
    HTTP1(std::unique_ptr<stream> stream, std::function<task<bool>(std::shared_ptr<http_ctx>)> handler);
    HTTP1(const HTTP1&) = delete;
    HTTP1& operator=(const HTTP1&) = delete;

    std::unique_ptr<stream> m_stream;
    
    std::vector<entry_t> get_headers() override;
    task<stream_result> write_headers(const std::vector<entry_t>& headers) override;
    task<stream_result> write_data(std::span<const uint8_t> data, bool end = false) override;
    task<std::pair<stream_result, bool>> append_http_data(ustring& buffer) override;
    bool is_done() override;

    std::function<task<bool>(std::shared_ptr<http_ctx>)> m_handler;
private:
    int32_t content_length_to_read = 0;
    std::vector<entry_t> headers;
    ustring m_read_buffer;

    task<void> send_error(http_error http_err);
};

} // namespace

#endif