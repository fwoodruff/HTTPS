//
//  types.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 06/12/2025.
//

#ifndef quic_types_hpp
#define quic_types_hpp

#include <variant>
#include <vector>
#include <optional>


namespace fbw::quic {

struct ack_range {
    uint64_t gap;
    uint64_t ack_range_length;
};

struct ec_counts {
    uint64_t ect0_count;
    uint64_t ect1_count;
    uint64_t ecn_ce_count;
};

struct padding_frame {};
struct ping_frame {};
struct ack_frame {
    uint64_t largest_acknowledged;
    std::chrono::nanoseconds ack_delay;
    uint64_t ack_range_count;
    uint64_t first_ack_range;
    std::vector<ack_range> ranges;
    std::optional<ec_counts> counts;
};
struct reset_stream {
    uint64_t stream_id;
    uint64_t application_protocol_error_code;
    uint64_t final_size;
};

struct stop_sending {
    uint64_t stream_id;
    uint64_t application_protocol_error_code;
};

struct crypto {
    uint64_t offset;
    std::vector<uint8_t> crypto_data;
};

struct new_token {
    std::vector<uint8_t> token;
};

struct stream_frame {
    uint64_t stream_id;
    uint64_t offset {};
    uint64_t length {};
    std::vector<uint8_t> stream_data;
};

struct max_data {
    uint64_t maximum_data;
};

struct max_stream_data {
    uint64_t stream_id;
    uint64_t max_stream_data;
};

struct max_streams {
    bool bidirectional;
    uint64_t maximum_streams;
};

struct data_blocked {
    uint64_t maximum_data;
};

struct stream_data_blocked {
    uint64_t stream_id;
    uint64_t maximum_stream_data;
};

struct streams_blocked {
    bool bidirectional;
    uint64_t maximum_streams;
};

struct new_connection_id {
    uint64_t sequence_number;
    uint64_t retire_prior_to;
    std::vector<uint8_t> connection_id;
    std::array<uint8_t, 16> stateless_reset_token;
};

struct retire_connection_id {
    uint64_t sequence_number;
};

struct path_challenge {
    uint64_t data;
};

struct path_response {
    uint64_t data;
};

struct connection_close {
    bool erroneous;
    uint64_t error_code;
    uint64_t frame_type;
    std::string reason_phrase;
};

struct handshake_done {};

using var_frame = std::variant<
    padding_frame,
    ping_frame,
    ack_frame,
    reset_stream,
    stop_sending,
    crypto,
    new_token,
    stream_frame,
    max_data,
    max_stream_data,
    max_streams,
    data_blocked,
    stream_data_blocked,
    streams_blocked,
    new_connection_id,
    retire_connection_id,
    path_challenge,
    path_response,
    connection_close,
    handshake_done
>;

enum class transport_error_code : uint16_t {
INTERNAL_ERROR,
CONNECTION_REFUSED,
FLOW_CONTROL_ERROR,
STREAM_LIMIT_ERROR,
STREAM_STATE_ERROR,
FINAL_SIZE_ERROR,
FRAME_ENCODING_ERROR,
TRANSPORT_PARAMETER_ERROR,
CONNECTION_ID_LIMIT_ERROR,
PROTOCOL_VIOLATION,
INVALID_TOKEN,
APPLICATION_ERROR,
CRYPTO_BUFFER_EXCEEDED,
KEY_UPDATE_ERROR,
AEAD_LIMIT_REACHED,
NO_VIABLE_PATH,
CRYPTO_ERROR = 0x0100,
};


struct version_negotiation_packet {
    uint32_t version;
    std::vector<uint8_t> destination_connection_id;
    std::vector<uint8_t> source_connection_id;
    uint32_t supported_version;
};

struct initial_packet {
    uint8_t packet_number_length;
    uint32_t version;
    std::vector<uint8_t> destination_connection_id;
    std::vector<uint8_t> source_connection_id;
    std::vector<uint8_t> token;
    uint32_t packet_number;
    std::vector<var_frame> packet_payload;
};

struct zero_rtt_packet {
    uint8_t packet_number_length;
    uint32_t version;
    std::vector<uint8_t> destination_connection_id;
    std::vector<uint8_t> source_connection_id;
    uint64_t length;
    uint32_t packet_number;
    std::vector<var_frame> packet_payload;
};

struct handshake_packet {
    uint8_t packet_number_length;
    uint32_t version;
    std::vector<uint8_t> destination_connection_id;
    std::vector<uint8_t> source_connection_id;
    uint64_t length;
    uint32_t packet_number;
    std::vector<var_frame> packet_payload;
};

struct retry_packet {
    uint8_t long_packet_type;
    uint32_t version;
    std::vector<uint8_t> destination_connection_id;
    std::vector<uint8_t> source_connection_id;
    std::vector<uint8_t> retry_token;
    std::array<uint8_t, 16> retry_integrity_tag;
};

struct one_rtt_packet {
    bool spin;
    bool key_phase;
    uint8_t packet_number_length;
    std::vector<uint8_t> destination_connection_id;
    uint32_t packet_number;
    std::vector<var_frame> packet_payload;
};

enum class packet_type : uint8_t {
    initial,
    zero_rtt,
    handshake,
    retry,
};

using var_packet = std::variant<
    version_negotiation_packet,
    initial_packet,
    zero_rtt_packet,
    handshake_packet,
    retry_packet,
    one_rtt_packet
>;

std::vector<var_packet> parse_datagram(const std::vector<uint8_t>& bytes);


}

#endif