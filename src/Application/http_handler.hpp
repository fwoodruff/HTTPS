//
//  H2handler.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/09/2024.
//

#ifndef h2handler_hpp
#define h2handler_hpp

#include "../Runtime/task.hpp"
#include "../HTTP/http_ctx.hpp"

#include <memory>

namespace fbw {

[[nodiscard]] task<bool> application_handler(http_ctx& connection);
[[nodiscard]] task<bool> redirect_handler(http_ctx& connection);
task<void> send_error(http_ctx& connection, uint32_t status_code, std::string status_message);

} // namespace fbw

#endif