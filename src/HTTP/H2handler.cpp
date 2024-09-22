

#include "../Runtime/task.hpp"
#include "H2handler.hpp"

namespace fbw {


task<void> handle_stream(std::weak_ptr<HTTP2> connection, uint32_t stream_id) {
    // await on connection, woken by data available
    // on wake, extract self from connection in case we want to wait somewhere else
    // on sleep readd to connection
    // await write
    co_return;
}

}