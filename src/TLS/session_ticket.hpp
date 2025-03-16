//
//  handshake.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 16/03/2025.
//

#ifndef session_ticket_hpp
#define session_ticket_hpp

#include "../global.hpp"
#include "TLS_enums.hpp"
#include "TLS_utils.hpp"

#include <array>
#include <string>
#include <span>
#include <optional>
#include <atomic>

namespace fbw {

struct TLS13SessionTicket {
    uint16_t version;
    uint32_t ticket_lifetime;
    uint64_t issued_at;
    uint32_t ticket_age_add;
    cipher_suites cipher_suite;
    bool  early_data_allowed;
    ustring resumption_secret;
    std::string sni;
    
    static std::optional<TLS13SessionTicket> decrypt(ustring ticket, std::array<uint8_t, 16> encryption_key);
    static std::optional<tls_record> server_session_ticket_record(TLS13SessionTicket ticket, std::array<uint8_t, 16> encryption_key, ustring nonce);
private:
    ustring encrypt(std::array<uint8_t, 16> encryption_key);
    ustring serialise();
    static std::optional<TLS13SessionTicket> deserialise(ustring ticket);
};



}

#endif // session_ticket_hpp
