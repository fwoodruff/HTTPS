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
[[nodiscard]] task<bool> application_handler(std::shared_ptr<http_ctx> connection);



// utils
std::vector<entry_t> headers_to_send(ssize_t file_size, std::string mime, bool full = true);
std::optional<std::string> find_header(const std::vector<entry_t>& request_headers, std::string header);
std::string app_error_to_html(std::string error);

} // namespace fbw

#endif