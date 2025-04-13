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

class HTTP2;

class h2_stream : public http_ctx, public std::enable_shared_from_this<h2_stream> {
public:

    std::vector<entry_t> get_headers() override;
    task<stream_result> write_headers(const std::vector<entry_t>& headers) override;
    task<stream_result> write_data(std::span<const uint8_t> data, bool end = true) override;
    task<std::pair<stream_result, bool>> append_http_data(ustring& buffer) override;

    h2_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id);
private:
    std::weak_ptr<HTTP2> m_connection;
    uint32_t m_stream_id;
};

} // namespace

#endif