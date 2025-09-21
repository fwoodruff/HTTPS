//
//  websockets.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 10/05/2025.
//

#ifndef websockets_hpp
#define  websockets_hpp

#include "../Runtime/task.hpp"
#include "../HTTP/common/http_ctx.hpp"


namespace fbw {

struct websocket_handler {
    websocket_handler(std::shared_ptr<http_ctx> conn);
    std::function<void(std::string)> on_text_message;
    std::function<void(std::vector<uint8_t>)> on_binary_message;
    std::shared_ptr<std::atomic<bool>> did_close;
    task<stream_result> send_text_message(const std::string& message);
    task<stream_result> listen(const std::vector<entry_t>& headers);
private:
    static task<void> handle_incoming(std::shared_ptr<http_ctx> connection, websocket_handler handler);
    std::shared_ptr<http_ctx> m_conn;
};

bool is_websocket_upgrade(const std::vector<entry_t>& headers);

}

#endif