//
//  quic_utils.cpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 28/11/2025.
//

#include "quic_utils.hpp"

namespace fbw::quic {

uint64_t read_varint(std::span<const uint8_t>& buf) {
    if (buf.empty()) {
        throw std::runtime_error("read_varint: buffer exhausted");
    }

    uint8_t first = buf[0];
    uint8_t prefix = first >> 6;       // top 2 bits determine length
    size_t len = 1ULL << prefix;       // 1, 2, 4, or 8 bytes

    if (buf.size() < len) {
        throw std::runtime_error("read_varint: truncated varint");
    }

    uint64_t value = 0;
    switch (len) {
        case 1:
            value = first & 0x3F;      // low 6 bits
            break;

        case 2:
            value = (uint64_t)(first & 0x3F) << 8 |
                    (uint64_t)buf[1];
            break;

        case 4:
            value = (uint64_t)(first & 0x3F) << 24 |
                    (uint64_t)buf[1] << 16 |
                    (uint64_t)buf[2] <<  8 |
                    (uint64_t)buf[3];
            break;

        case 8:
            value = (uint64_t)(first & 0x3F) << 56 |
                    (uint64_t)buf[1] << 48 |
                    (uint64_t)buf[2] << 40 |
                    (uint64_t)buf[3] << 32 |
                    (uint64_t)buf[4] << 24 |
                    (uint64_t)buf[5] << 16 |
                    (uint64_t)buf[6] <<  8 |
                    (uint64_t)buf[7];
            break;
    }

    if(value > (0x1ull << 62)) {
        throw std::runtime_error("read_varint: connection error");
    }

    buf = buf.subspan(len);
    return value;
}

// QUIC variable-length integer writer
// Appends the encoding to `out`.
void write_varint(uint64_t value, std::vector<uint8_t>& out) {
    if (value > 0x3FFFFFFFFFFFFFFFULL)
        throw std::runtime_error("write_varint: value exceeds QUIC maximum");

    if (value < (1ULL << 6)) {
        // 1 byte: 00xxxxxx
        uint8_t b = static_cast<uint8_t>(value & 0x3F);
        out.push_back(b | 0x00); // prefix 00
        return;
    }

    if (value < (1ULL << 14)) {
        // 2 bytes: 01xxxxxx ...
        uint8_t b0 = static_cast<uint8_t>((value >> 8) & 0x3F);
        uint8_t b1 = static_cast<uint8_t>(value & 0xFF);
        out.push_back(b0 | 0x40); // prefix 01
        out.push_back(b1);
        return;
    }

    if (value < (1ULL << 30)) {
        // 4 bytes: 10xxxxxx ...
        uint8_t b0 = static_cast<uint8_t>((value >> 24) & 0x3F);
        out.push_back(b0 | 0x80); // prefix 10
        out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((value >>  8) & 0xFF));
        out.push_back(static_cast<uint8_t>((value      ) & 0xFF));
        return;
    }

    // 8 bytes: 11xxxxxx ...
    uint8_t b0 = static_cast<uint8_t>((value >> 56) & 0x3F);
    out.push_back(b0 | 0xC0); // prefix 11
    out.push_back(static_cast<uint8_t>((value >> 48) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 40) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 32) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value      ) & 0xFF));
}


}