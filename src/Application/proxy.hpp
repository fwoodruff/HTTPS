//
//  proxy.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 14/03/2026.
//

#ifndef proxy_hpp
#define proxy_hpp

#include "../HTTP/common/http_ctx.hpp"
#include "../Runtime/task.hpp"
#include "../global.hpp"

namespace fbw {

task<void> handle_proxy_request(http_ctx& conn,
                                const std::string& method,
                                const std::string& path,
                                const std::vector<entry_t>& headers,
                                const proxy_rule& rule);

} // namespace fbw

#endif // proxy_hpp
