//
//  event_loop.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 22/11/2025.
//


#include "event_loop.hpp"
#include "retransmission.hpp"
#include "../IP/Awaitables/await_message.hpp"
#include "types.hpp"
#include "visitor.hpp"
#include <variant>


namespace fbw::quic {

task<void> visit_datagram(const std::vector<uint8_t>& data) {
    auto parsed = parse_datagram(data);
    for(auto packet : parsed) {
        visit_packet(packet);
    }
    co_return;
}

task<void> quic_event_loop(std::shared_ptr<udp_connection> conn) {
    retransmission_state rst;
    using enum k_packet_number_space;
    for(;;) {

        const auto [ loss_time, loss_space ] = rst.get_loss_time_and_space();
        const auto [ pto_time, pto_space ] = rst.get_pto_time_and_space();

        steady_clock::time_point next_deadline = steady_clock::time_point::max();

        if (loss_time != steady_clock::time_point::max()) {
            next_deadline = loss_time;
        }
        if (pto_time != steady_clock::time_point::max() && pto_time < next_deadline) {
            next_deadline = pto_time;
        }

        if (next_deadline == steady_clock::time_point::max()) {
            next_deadline = steady_clock::now() + 500ms;
        }

        std::optional<datagram> maybe_datagram = co_await conn->receive_until(next_deadline);
        if(!maybe_datagram.has_value()) {
            rst.on_loss_detection_timeout();
            continue; // or return if connection should timeout?
        }
        datagram d = *maybe_datagram;
        
        co_await visit_datagram(d.data);

        co_await conn->send(d);
    }
    co_return;
}

}