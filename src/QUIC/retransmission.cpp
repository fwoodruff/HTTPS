//
//  quic_frame.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 22/11/2025.
//

#include "../IP/Awaitables/await_message.hpp"
#include "retransmission.hpp"
#include "types.hpp"

#include <vector>
#include <map>
#include <span>
#include <limits>
#include <cassert>

// see RFC 9002 for pseudocode

namespace fbw::quic {

retransmission_state::retransmission_state() :
    latest_rtt(0),
    smoothed_rtt(k_initial_rtt),
    rttvar(k_initial_rtt / 2),
    min_rtt(0),
    first_rtt_sample(),
    pto_count(0),
    time_of_last_ack_eliciting_packet{},
    largest_acked_packet{std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max(), std::numeric_limits<uint64_t>::max()},
    loss_time{}
{}

void retransmission_state::on_packet_sent(uint64_t packet_number, k_packet_number_space pn_space, bool ack_eliciting, bool in_flight, uint64_t sent_bytes) {
    size_t pn_idx = static_cast<size_t>(pn_space);
    sent_packet packet;
    packet.packet_number = packet_number;
    packet.time_sent = steady_clock::now();
    packet.ack_eliciting = ack_eliciting;
    packet.in_flight = in_flight;
    packet.sent_bytes = sent_bytes;
    sent_packets[pn_idx][packet_number] = packet;
    if (in_flight) {
        if (ack_eliciting) {
            time_of_last_ack_eliciting_packet[pn_idx] = steady_clock::now();
        }
        on_packet_sent_congestion_control(sent_bytes);
        set_loss_detection_timer();
    }
}

void retransmission_state::on_packet_sent_congestion_control(uint64_t sent_bytes) {
    bytes_in_flight += sent_bytes;
}

std::pair<steady_clock::time_point, k_packet_number_space> retransmission_state::get_loss_time_and_space() {
    using enum k_packet_number_space;
    auto time = loss_time[static_cast<size_t>(initial)];
    auto space = initial;
    for(auto pn_space : {handshake, application_data}) {
        auto pn_idx = static_cast<size_t>(pn_space);
        if (time == steady_clock::time_point{} || loss_time[pn_idx] < time) {
            time = loss_time[pn_idx];
            space = pn_space;
        }
    }
    return {time, space};
}

void retransmission_state::set_loss_detection_timer() {
    auto [ earliest_loss_time, _ ] = get_loss_time_and_space();
    if (earliest_loss_time != steady_clock::time_point{}) {
        // Time threshold loss detection.
        
        return;
    }

    //if (server is at anti-amplification limit) {
        // The server's timer is not set if nothing can be sent.
    //    loss_detection_timer.cancel();
    //    return;
    //}

    //if (no ack-eliciting packets in flight &&
    //    PeerCompletedAddressValidation()):
        // There is nothing to detect lost, so no timer is set.
        // However, the client needs to arm the timer if the
        // server might be blocked by the anti-amplification limit.
    //    loss_detection_timer.cancel()
    //    return

    //timeout, _ = GetPtoTimeAndSpace()
    //loss_detection_timer.update(timeout)
}

bool peer_completed_address_validation() {
    // Assume clients validate the server's address implicitly.
    if (false /*endpoint is server*/) {
        return true;
    }
    // Servers complete address validation when a
    // protected packet is received.
    //return has received Handshake ACK || handshake confirmed
    return false;
}

std::pair<steady_clock::time_point, k_packet_number_space> retransmission_state::get_pto_time_and_space() {
    using enum k_packet_number_space;
    auto duration = (smoothed_rtt + std::max(4 * rttvar, k_granularity)) * (2 ^ pto_count);
    // Anti-deadlock PTO starts from the current time
    if (false /*no ack-eliciting packets in flight*/) {
        //assert(!peer_completed_address_validation());
        if (false /*has handshake keys*/) {
            return {(steady_clock::now() + duration), handshake};
        } else {
            return {(steady_clock::now() + duration), initial};
        }
    }

    std::optional<steady_clock::time_point> pto_timeout = std::nullopt;
    auto pto_space = initial;
    for (auto space : {initial, handshake, application_data }) {
        //if (no ack-eliciting packets in flight in space):
        //    continue;
        //}
        if (space == application_data) {
        // Skip Application Data until handshake confirmed.
            //if (handshake is not confirmed) {}
            //    return pto_timeout, pto_space;
            //}
            // Include max_ack_delay and backoff for Application Data.
            duration += max_ack_delay * (2 ^ pto_count);
        }

        auto t = time_of_last_ack_eliciting_packet[static_cast<size_t>(space)] + duration;
        if (t < pto_timeout) {
            pto_timeout = t;
            pto_space = space;
        }
    }
    return {*pto_timeout, pto_space};
}

void retransmission_state::on_loss_detection_timeout() {
    auto [ earliest_loss_time, pn_space ] = get_loss_time_and_space();
    if (earliest_loss_time != steady_clock::time_point{}) {
        // Time threshold loss Detection
        auto lost_packets = detect_and_remove_lost_packets(pn_space);
        assert(!lost_packets.empty());
        on_packets_lost(lost_packets);
        set_loss_detection_timer();
        return;
    }

    if (false /*no ack-eliciting packets in flight*/) {
        assert(!peer_completed_address_validation());
        // Client sends an anti-deadlock packet: Initial is padded
        // to earn more anti-amplification credit,
        // a Handshake packet proves address ownership.
        if (false /*has Handshake keys*/) {
            ack_frame ack_elicit;
            frames_to_send.push_back(ack_elicit);
        } else {
            ack_frame ack_elicit_initial_padded;
            frames_to_send.push_back(ack_elicit_initial_padded);
        }
    } else {
        // PTO. Send new data if available, else retransmit old data.
        // If neither is available, send a single PING frame.
        //auto [ _, pn_space ] = get_pto_time_and_space();
        ack_frame ack_elicit;
        frames_to_send.push_back(ack_elicit);
        frames_to_send.push_back(ack_elicit);
    }
    pto_count++;
    set_loss_detection_timer();
}

void on_probe_timeout() {

}

std::vector<sent_packet> retransmission_state::detect_and_remove_lost_packets(k_packet_number_space space) {
    return {};
}

std::vector<sent_packet> retransmission_state::detect_and_remove_acked_packets(ack_frame packet, k_packet_number_space space) {
    return {};
}

bool includes_ack_eliciting(std::vector<sent_packet> packets) {
    for(auto& packet : packets) {
        if (packet.ack_eliciting) {
            return true;
        }
    }
    return false;
}

void retransmission_state::update_rtt(nanoseconds ack_delay) {
    if (first_rtt_sample == steady_clock::time_point{}) {
        min_rtt = latest_rtt;
        smoothed_rtt = latest_rtt;
        rttvar = latest_rtt / 2;
        first_rtt_sample = steady_clock::now();
        return;
    }

    // min_rtt ignores acknowledgment delay.
    min_rtt = min(min_rtt, latest_rtt);
    // Limit ack_delay by max_ack_delay after handshake
    // confirmation.
    if (true/*handshake confirmed*/) {
        ack_delay = std::min(ack_delay, max_ack_delay);
    }

    // Adjust for acknowledgment delay if plausible.
    auto adjusted_rtt = latest_rtt;
    if (latest_rtt >= min_rtt + ack_delay) {
        adjusted_rtt = latest_rtt - ack_delay;
    }

    rttvar = 3/4 * rttvar + 1/4 * abs(smoothed_rtt - adjusted_rtt);
    smoothed_rtt = 7/8 * smoothed_rtt + 1/8 * adjusted_rtt;
}

void retransmission_state::on_ack_received(ack_frame ack, k_packet_number_space pn_space) {
    using enum k_packet_number_space;
    size_t pn_idx = static_cast<size_t>(pn_space);
    if (largest_acked_packet[pn_idx] == std::numeric_limits<uint64_t>::max()) {
        largest_acked_packet[pn_idx] = ack.largest_acknowledged;
    } else {
        largest_acked_packet[pn_idx] = std::max(largest_acked_packet[pn_idx], ack.largest_acknowledged);
    }

    // DetectAndRemoveAckedPackets finds packets that are newly
    // acknowledged and removes them from sent_packets.
    auto newly_acked_packets = detect_and_remove_acked_packets(ack, pn_space);
    // Nothing to do if there are no newly acked packets.
    if (newly_acked_packets.empty()) {
        return;
    }

    // Update the RTT if the largest acknowledged is newly acked
    // and at least one ack-eliciting was newly acked.
    auto largest_it = std::max_element(newly_acked_packets.begin(), newly_acked_packets.end(), [](const sent_packet& a, const sent_packet& b){ return a.sent_bytes < b.sent_bytes; });

    if (largest_it->packet_number == ack.largest_acknowledged && includes_ack_eliciting(newly_acked_packets)) {
        latest_rtt = steady_clock::now() - largest_it->time_sent;
        update_rtt(ack.ack_delay);
    }

    // Process ECN information if present.
    //if (ACK frame contains ECN information):
    //    ProcessECN(ack, pn_space)

    auto lost_packets = detect_and_remove_lost_packets(pn_space);
    if (!lost_packets.empty()) {
        on_packets_lost(lost_packets);
    }
    on_packets_acked(newly_acked_packets);

    // Reset pto_count unless the client is unsure if
    // the server has validated the client's address.
    if (peer_completed_address_validation()) {
        pto_count = 0;
    }
    set_loss_detection_timer();
}

void retransmission_state::on_packets_acked(std::vector<sent_packet> acked_packets) {
    for(const auto& packet : acked_packets) {
        on_packet_acked(packet);
    }
}

bool retransmission_state::is_app_or_flow_control_limited() {
    return false;
}

bool retransmission_state::in_congestion_recovery(steady_clock::time_point time) {
    return false;
}

void retransmission_state::on_packet_acked(sent_packet acked_packet) {
    if (!acked_packet.in_flight) {
        return;
    }
    // Remove from bytes_in_flight.
    bytes_in_flight -= acked_packet.sent_bytes;
    // Do not increase congestion_window if application
    // limited or flow control limited.
    if (is_app_or_flow_control_limited()) {
        return;
    }
    // Do not increase congestion window in recovery period.
    if (in_congestion_recovery(acked_packet.time_sent)) {
        return;
    }
    if (cc.congestion_window < cc.ssthresh) {
        // Slow start.
        cc.congestion_window += acked_packet.sent_bytes;
    } else {
        // Congestion avoidance.
        cc.congestion_window += cc.max_datagram_size * acked_packet.sent_bytes / cc.congestion_window;
    }
}

void retransmission_state::on_packets_lost(std::vector<sent_packet> packets) {}

}