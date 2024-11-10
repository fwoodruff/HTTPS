//
//  H2handler.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/09/2024.
//

#include "../Runtime/task.hpp"
#include "h2handler.hpp"
#include "h2proto.hpp"
#include "h2awaitable.hpp"
#include "../global.hpp"

namespace fbw {

task<void> handle_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id) {
    
    auto [ conn, stream ] = lock_stream(connection, stream_id);
    auto headers = stream->m_received_headers;

    ustring bytes;

    std::span<const uint8_t> sp (bytes.cbegin(), bytes.cend());
    while(!sp.empty()) {
        auto stres = co_await write_some_data(conn, stream_id, sp);
        if(stres != stream_result::ok) {
            co_return;
        }
    }
    // ensure we are running on the same thread as the connection here
    conn->m_h2streams.erase(stream_id);
    co_return;
}

}