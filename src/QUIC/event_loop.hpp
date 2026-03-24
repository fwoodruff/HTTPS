//
//  event_loop.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 22/11/2025.
//

#ifndef quic_event_loop_hpp
#define quic_event_loop_hpp

#include "../Runtime/task.hpp"
#include "../IP/Awaitables/await_message.hpp"
#include "../IP/udp_server.hpp"

#include "retransmission.hpp"
#include "../IP/udp_server.hpp"

namespace fbw::quic {

task<void> quic_event_loop(std::shared_ptr<udp_connection> conn);
}

#endif