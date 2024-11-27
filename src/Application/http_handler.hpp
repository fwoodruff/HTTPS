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

class http_ctx;
[[nodiscard]] task<void> application_handler(std::shared_ptr<http_ctx> connection);

} // namespace fbw

#endif