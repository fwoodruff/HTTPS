//
//  H2handler.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 22/09/2024.
//

#ifndef h2handler_hpp
#define h2handler_hpp

#include "../Runtime/task.hpp"
#include <memory>

namespace fbw {

class HTTP2;
task<void> handle_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id);

} // namespace fbw

#endif