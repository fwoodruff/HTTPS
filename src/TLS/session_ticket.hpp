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

extern std::array<uint8_t, 16> session_ticket_master_secret;
constexpr uint32_t MAX_EARLY_DATA = 0x4000;


struct TLS13SessionTicket {
    uint16_t version;
    uint32_t ticket_lifetime;
    uint64_t issued_at;
    uint32_t ticket_age_add;
    cipher_suites cipher_suite;
    bool  early_data_allowed;
    uint64_t number_once;
    ustring resumption_secret;
    std::string sni;
    //std::string alpn;
    
    static std::optional<TLS13SessionTicket> decrypt_ticket(ustring ticket, const std::array<uint8_t, 16>& encryption_key);
    static std::optional<tls_record> server_session_ticket_record(TLS13SessionTicket ticket, std::array<uint8_t, 16> encryption_key, uint64_t number_once);

private:
    ustring encrypt_ticket(const std::array<uint8_t, 16>& encryption_key, uint64_t number_once);
    ustring serialise();
    static std::optional<TLS13SessionTicket> deserialise(ustring ticket);
};

void write_early_data_ticket_ext(tls_record& record);


}

#endif // session_ticket_hpp
