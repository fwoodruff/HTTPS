//
//  types.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 06/12/2025.
//

#include "types.hpp"
#include "quic_utils.hpp"
#include <span>
#include <vector>

namespace fbw::quic {

static ack_frame parse_ack(std::span<const uint8_t>& payload, uint64_t frame_type) {
    using namespace std::chrono;
    ack_frame out;
    out.largest_acknowledged = read_varint(payload);
    uint64_t micros = read_varint(payload);
    out.ack_delay = duration_cast<nanoseconds>(microseconds{micros});
    out.ack_range_count = read_varint(payload);
    out.first_ack_range = read_varint(payload);
    out.ranges.reserve(out.ack_range_count);
    for (uint64_t i = 0; i < out.ack_range_count; i++) {
        ack_range r;
        r.gap = read_varint(payload);
        r.ack_range_length = read_varint(payload);
        out.ranges.push_back(r);
    }
    if (frame_type == 0x03) {
        ec_counts ec;
        ec.ect0_count = read_varint(payload);
        ec.ect1_count = read_varint(payload);
        ec.ecn_ce_count = read_varint(payload);
        out.counts = ec;
    }
    return out;
}

static reset_stream parse_reset_stream(std::span<const uint8_t>& payload) {
    reset_stream out;
    out.stream_id = read_varint(payload);
    out.application_protocol_error_code = read_varint(payload);
    out.final_size = read_varint(payload);
    return out;
}

static stop_sending parse_stop_sending(std::span<const uint8_t>& payload) {
    stop_sending out;
    out.stream_id = read_varint(payload);
    out.application_protocol_error_code = read_varint(payload);
    return out;
}

static crypto parse_crypto(std::span<const uint8_t>& payload) {
    crypto out;
    out.offset = read_varint(payload);
    auto len = read_varint(payload);
    auto data = payload.subspan(0, len);
    out.crypto_data = std::vector<uint8_t>(data.begin(), data.end());
    payload = payload.subspan(len);
    return out;
}

static new_token parse_new_token(std::span<const uint8_t>& payload) {
    new_token out;
    auto len = read_varint(payload);
    auto data = payload.subspan(0, len); // todo check size
    out.token = std::vector<uint8_t>(data.begin(), data.end());
    payload = payload.subspan(len);
    return out;
}

static stream_frame parse_stream(std::span<const uint8_t>& payload,  uint64_t frame_type) {
    stream_frame out;
    bool offset = !!(frame_type & 0x04);
    bool len = !!(frame_type & 0x02); 
    bool fin = !!(frame_type & 0x01);
    out.stream_id = read_varint(payload);
    if(offset) {
        out.offset = read_varint(payload);
    }
    if(len) {
        out.length = read_varint(payload);
    }
    auto data = payload.subspan(0, len); // todo check size
    out.stream_data = std::vector<uint8_t>(data.begin(), data.end());
    payload = payload.subspan(len);
    return out;
}

static max_data parse_max_data(std::span<const uint8_t>& payload) {
    max_data out;
    return out;
}

static max_stream_data parse_max_stream_data(std::span<const uint8_t>& payload) {
    max_stream_data out;
    return out;
}

static max_streams parse_max_streams(std::span<const uint8_t>& payload, uint64_t frame_type) {
    max_streams out;
    return out;
}

static data_blocked parse_data_blocked(std::span<const uint8_t>& payload) {
    data_blocked out;
    return out;
}

static stream_data_blocked parse_stream_data_blocked(std::span<const uint8_t>& payload) {
    stream_data_blocked out;
    return out;
}

static streams_blocked parse_streams_blocked(std::span<const uint8_t>& payload) {
    streams_blocked out;
    return out;
}

static new_connection_id parse_new_connection_id(std::span<const uint8_t>& payload) {
    new_connection_id out;
    return out;
}

static retire_connection_id parse_retire_connection_id(std::span<const uint8_t>& payload) {
    retire_connection_id out;
    return out;
}

static path_challenge parse_path_challenge(std::span<const uint8_t>& payload) {
    path_challenge out;
    return out;
}

static path_response parse_path_response(std::span<const uint8_t>& payload) {
    path_response out;
    return out;
}

static connection_close parse_connection_close(std::span<const uint8_t>& payload) {
    connection_close out;
    return out;
}

static handshake_done parse_handshake_done(std::span<const uint8_t>& payload) {
    handshake_done out;
    return out;
}

static std::vector<var_frame> parse_frames(std::span<const uint8_t> payload) {
    std::vector<var_frame> out;
    while (!payload.empty()) {
        auto frame_type = read_varint(payload);
        
        switch (frame_type) {
            case 0x00: out.push_back(padding_frame{}); break;
            case 0x01: out.push_back(ping_frame{}); break;
            case 0x02 ... 0x03: out.push_back(parse_ack(payload, frame_type)); break;
            case 0x04: out.push_back(parse_reset_stream(payload)); break;
            case 0x05: out.push_back(parse_stop_sending(payload)); break;
            case 0x06: out.push_back(parse_crypto(payload)); break;
            case 0x07: out.push_back(parse_new_token(payload)); break;
            case 0x08 ... 0x0f: out.push_back(parse_stream(payload, frame_type)); break;
            case 0x10: out.push_back(parse_max_data(payload)); break;
            case 0x11: out.push_back(parse_max_stream_data(payload)); break;
            case 0x12 ... 0x13: out.push_back(parse_max_streams(payload, frame_type)); break;
            case 0x14: out.push_back(parse_data_blocked(payload)); break;
            case 0x15: out.push_back(parse_stream_data_blocked(payload)); break;
            case 0x16 ... 0x17: out.push_back(parse_streams_blocked(payload)); break;
            case 0x18: out.push_back(parse_new_connection_id(payload)); break;
            case 0x19: out.push_back(parse_retire_connection_id(payload)); break;
            case 0x1a: out.push_back(parse_path_challenge(payload)); break;
            case 0x1b: out.push_back(parse_path_response(payload)); break;
            case 0x1c ... 0x1d: out.push_back(parse_connection_close(payload)); break;
            case 0x1e: out.push_back(parse_handshake_done(payload)); break; // todo: treat as PROTOCOL_VIOLATION
            default: break; // todo: treat as PROTOCOL_VIOLATION
        }
    }
    return out;
}

static uint32_t read_u32(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) |
           (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |
            uint32_t(p[3]);
}

static uint32_t consume_u32(std::span<const uint8_t>& s) {
    if (s.size() < 4) { 
        s = {};
        return 0;
    }
    auto res = read_u32(s.data());
    s = s.subspan(4);
    return res;
}


static std::vector<uint8_t> consume_cid(std::span<const uint8_t>& s) {
    std::vector<uint8_t> out;
    if (s.empty()) {
        return {};
    }
    uint8_t len = s[0];
    if (s.size() < len + 1) {
        return {};
    }
    out.assign(s.begin() + 1, s.begin() + 1 + len);
    s = s.subspan(len + 1);
    return out;
}

static version_negotiation_packet consume_version_negotiation(std::span<const uint8_t>& s) {
    version_negotiation_packet p;
    // todo check the fixed bit
    s = s.subspan(1);
    p.version = consume_u32(s);
    p.destination_connection_id = consume_cid(s);
    p.source_connection_id = consume_cid(s);
    p.supported_version = consume_u32(s);
    return p;
}

static initial_packet consume_initial(std::span<const uint8_t>& s) {
    initial_packet p;
    s = s.subspan(1);
    p.version = consume_u32(s);
    p.destination_connection_id = consume_cid(s);
    p.source_connection_id = consume_cid(s);
    auto token_len = read_varint(s);
    if(s.size() < token_len) {
        return {};
    }
    p.token = std::vector<uint8_t>(s.begin(), s.begin() + token_len);
    auto length = read_varint(s);
    p.packet_payload = parse_frames(s);
    s = s.subspan(length);
    return p;
}

static zero_rtt_packet consume_zero_rtt(std::span<const uint8_t>& s) {
    // TODO
    return {};
}

static handshake_packet consume_handshake(std::span<const uint8_t>& s) {
    // TODO
    return {};
}

static retry_packet consume_retry(std::span<const uint8_t>& s) {
    // TODO
    return {};
}

static one_rtt_packet consume_one_rtt(std::span<const uint8_t>& s) {
    // TODO
    return {};
}

std::vector<var_packet> parse_datagram(const std::vector<uint8_t>& bytes) {
    std::span<const uint8_t> data_span(bytes.data(), bytes.size());
    std::vector<var_packet> out;

    while (!data_span.empty()) {
        if (data_span.size() < 6) {
            break;
        }
        uint8_t first = data_span[0];
        bool is_short_header = (first & 0x80) == 0;
        if (is_short_header) {
            out.push_back(consume_one_rtt(data_span));
            continue;
        }
        uint32_t version = read_u32(data_span.data()+1);
        if (version == 0) {
            out.push_back(consume_version_negotiation(data_span));
            continue;
        }
        uint8_t type = (first >> 4) & 0x03;
        using enum packet_type;
        switch (static_cast<packet_type>(type)) {
            case initial: {
                out.push_back(consume_initial(data_span));
                break;
            }
            case zero_rtt: {
                out.push_back(consume_zero_rtt(data_span));
                break;
            }
            case handshake: {
                out.push_back(consume_handshake(data_span));
                break;
            }
            case retry: {
                out.push_back(consume_retry(data_span));
                break;
            }
            default:
                data_span = {};
                return {};
        }
    }
    return out;
}

}
