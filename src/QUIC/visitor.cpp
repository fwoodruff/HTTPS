#include "visitor.hpp"

#include <variant>

#include "../Runtime/task.hpp"

#include "types.hpp"

namespace fbw::quic {

template<class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
template<class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

task<void> visit_frame(const var_frame& frame) {
    std::visit(overloaded {
        [](const padding_frame& f) {

        },
        [](const ping_frame& f) {

        },
        [](const ack_frame& f) {

        },
        [](const reset_stream& f) {

        },
        [](const stop_sending& f) {

        },
        [](const crypto& f) {

        },
        [](const new_token& f) {

        },
        [](const stream_frame& f) {

        },
        [](const max_data& f) {

        },
        [](const max_stream_data& f) {

        },
        [](const max_streams& f) {

        },
        [](const data_blocked& f) {

        },
        [](const stream_data_blocked& f) {

        },
        [](const streams_blocked& f) {

        },
        [](const new_connection_id& f) {

        },
        [](const retire_connection_id& f) {

        },
        [](const path_challenge& f) {

        },
        [](const path_response& f) {

        },
        [](const connection_close& f) {

        },
        [](const handshake_done& f) {

        }
        }, frame);
    co_return;
}

task<void> visit_payload(const std::vector<var_frame>& payload) {
    for(const auto& frame : payload) {
        visit_frame(frame);
    }
    co_return;
}

task<void> visit_packet(const var_packet& packet) {
    std::visit(overloaded {
        [](const version_negotiation_packet& p) {
            
        },
        [](const initial_packet& p) {
            visit_payload(p.packet_payload);
        },
        [](const zero_rtt_packet& p) {
            
        },
        [](const handshake_packet& p) {

        },
        [](const retry_packet& p) {

        },
        [](const one_rtt_packet& p) {

        },
    }, packet);
    co_return;
}

}