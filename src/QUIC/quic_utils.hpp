//
//  quic_utils.hpp
//  HTTPS20
//
//  Created by Frederick Benjamin Woodruff on 28/11/2025.
//

#ifndef quic_utils_hpp
#define quic_utils_hpp

#include <vector>

#include "../IP/Awaitables/await_message.hpp"

#include "retransmission.hpp"

#include <chrono>

namespace fbw::quic {

uint64_t read_varint(std::span<const uint8_t>& buf);
void write_varint(uint64_t value, std::vector<uint8_t>& out);

}
#endif