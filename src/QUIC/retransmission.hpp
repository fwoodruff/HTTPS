//
//  quic_frame.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 22/11/2025.
//

#ifndef quic_retransmission_hpp
#define quic_retransmission_hpp

#include <string>
#include <mutex>
#include <deque>
#include <memory>
#include <map>
#include <unordered_map>
#include <vector>

#include "quic_utils.hpp"
#include "types.hpp"

namespace fbw::quic {

enum class k_packet_number_space {
    initial,
    handshake,
    application_data,
};
constexpr static auto size_k_packet_number_space = 3;

struct congestion_control {
    static constexpr uint64_t k_initial_window = 0;
    static constexpr uint64_t k_minimum_window = 0;
    static constexpr uint64_t k_loss_reduction_factor = 0;
    static constexpr uint64_t k_persistent_congestion_threshold = 0;

    uint64_t max_datagram_size;
    std::array<uint64_t, 3> ecn_ce_counters;
    uint64_t bytes_in_flight;
    uint64_t congestion_window;
    uint64_t congestion_recovery_start_time;
    uint64_t ssthresh;
};

struct sent_packet{
    uint64_t packet_number;
    steady_clock::time_point time_sent;
    bool ack_eliciting;
    bool in_flight;
    bool sent_bytes;
};

using namespace std::chrono_literals;
struct retransmission_state {
    static constexpr uint64_t k_packet_threshold = 3;
    static constexpr double k_time_threshold = 9.0 / 8.0;
    static constexpr std::chrono::nanoseconds k_granularity{1};
    static constexpr auto k_initial_rtt = 333ms;

    nanoseconds latest_rtt;
    nanoseconds smoothed_rtt;
    nanoseconds rttvar;
    nanoseconds min_rtt;
    
    steady_clock::time_point first_rtt_sample;

    nanoseconds max_ack_delay;
    
    uint64_t pto_count;

    std::array<steady_clock::time_point, size_k_packet_number_space> time_of_last_ack_eliciting_packet;
    std::array<uint64_t, size_k_packet_number_space> largest_acked_packet;
    std::array<steady_clock::time_point, size_k_packet_number_space> loss_time;
    std::array<std::map<uint64_t, sent_packet>, size_k_packet_number_space> sent_packets;

    uint64_t bytes_in_flight = 0;

    std::deque<var_frame> frames_to_send;
    
    congestion_control cc;

    retransmission_state();

    void on_packet_sent(uint64_t packet_number, k_packet_number_space pn_space, bool ack_eliciting, bool in_flight, uint64_t sent_bytes);
    void on_packet_sent_congestion_control(uint64_t sent_bytes);
    void set_loss_detection_timer();
    void on_ack_received(ack_frame ack, k_packet_number_space pn);
    void on_packets_lost(std::vector<sent_packet> packets);

    void on_packet_acked(sent_packet);
    void on_packets_acked(std::vector<sent_packet> packets);

    void on_loss_detection_timeout();

    bool is_app_or_flow_control_limited();
    bool in_congestion_recovery(steady_clock::time_point time);

    void update_rtt(nanoseconds ack_delay);

    std::vector<sent_packet> detect_and_remove_lost_packets(k_packet_number_space space);
    std::vector<sent_packet> detect_and_remove_acked_packets(ack_frame frame, k_packet_number_space space);

    std::pair<steady_clock::time_point, k_packet_number_space> get_loss_time_and_space();
    std::pair<steady_clock::time_point, k_packet_number_space> get_pto_time_and_space();

};

}

#endif