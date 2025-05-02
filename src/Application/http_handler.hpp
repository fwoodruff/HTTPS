//
//  H2handler.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/09/2024.
//

#ifndef h2handler_hpp
#define h2handler_hpp

#include "../Runtime/task.hpp"
#include "../HTTP/common/http_ctx.hpp"

#include <memory>

namespace fbw {

[[nodiscard]] task<bool> application_handler(http_ctx& connection);
[[nodiscard]] task<bool> redirect_handler(http_ctx& connection);


} // namespace fbw

#endif