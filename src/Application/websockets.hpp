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

task<void> handle_websocket(http_ctx& connection, const std::vector<entry_t>& headers);
bool is_websocket_upgrade(const std::vector<entry_t>& headers);

}

#endif