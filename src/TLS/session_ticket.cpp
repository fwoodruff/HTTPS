
#include "session_ticket.hpp"
#include "../global.hpp"
#include "TLS_enums.hpp"
#include "TLS_utils.hpp"
#include "Cryptography/one_way/keccak.hpp"

namespace fbw {
ustring TLS13SessionTicket::serialise() {
    ustring out;
    out.reserve(22+resumption_secret.size());
    out.resize(22);
    checked_bigend_write(version, out, 0, 2);
    checked_bigend_write(ticket_lifetime, out, 2, 4);
    checked_bigend_write(issued_at, out, 6, 8);
    checked_bigend_write(ticket_age_add, out, 14, 4);
    checked_bigend_write(uint16_t(cipher_suite), out, 18, 2);
    checked_bigend_write(uint8_t(early_data_allowed), out, 20, 1);
    assert(resumption_secret.size() < 256);
    checked_bigend_write(resumption_secret.size(), out, 21, 1);
    out.append(resumption_secret.begin(), resumption_secret.end());
    return out;
}

std::optional<TLS13SessionTicket> TLS13SessionTicket::deserialise(ustring ticket) {
    if(ticket.size() < 22) {
        return std::nullopt;
    }
    TLS13SessionTicket out;
    out.version = try_bigend_read(ticket, 0, 2);
    out.ticket_lifetime = try_bigend_read(ticket, 2, 4);
    out.issued_at = try_bigend_read(ticket, 6, 8);
    out.ticket_age_add = try_bigend_read(ticket, 14, 4);
    out.cipher_suite = static_cast<cipher_suites>(try_bigend_read(ticket, 18, 2));
    out.early_data_allowed = try_bigend_read(ticket, 20, 1) != 0ull;
    uint8_t size = try_bigend_read(ticket, 21, 1);
    out.resumption_secret.assign(ticket.begin() + 22, ticket.end());
    if(size != ticket.size()) {
        return std::nullopt;
    }
    return out;
}

ustring TLS13SessionTicket::encrypt(std::array<uint8_t, 16> encryption_key) {
    return serialise(); // todo:
}

std::optional<TLS13SessionTicket> TLS13SessionTicket::decrypt(ustring ticket, std::array<uint8_t, 16> encryption_key) {
    auto out = deserialise(ticket); // todo
    return out;
}

static std::atomic<uint64_t> global_nonce = 0;
std::optional<tls_record> TLS13SessionTicket::server_session_ticket_record(TLS13SessionTicket ticket, std::array<uint8_t, 16> encryption_key) {
    constexpr uint32_t MAX_TICKET_LIFETIME = 604800;
    tls_record record(ContentType::Handshake);
    if(ticket.ticket_lifetime > MAX_TICKET_LIFETIME) {
        return std::nullopt;
    }
    record.write1(HandshakeType::new_session_ticket);
    record.start_size_header(3);

    std::array<uint8_t, 4> ticket_lifetime_bytes;
    checked_bigend_write(ticket.ticket_lifetime, ticket_lifetime_bytes, 0, 4);
    record.write(ticket_lifetime_bytes);

    std::array<uint8_t, 4> ticket_age_add;
    randomgen.randgen(ticket_age_add);
    record.write(ticket_age_add);
    
    std::array<uint8_t, 8> ticket_nonce_bytes;
    checked_bigend_write(global_nonce, ticket_nonce_bytes, 0, 8);
    global_nonce.fetch_add(1,std::memory_order_relaxed);
    record.start_size_header(1);
    record.write(ticket_nonce_bytes);
    record.end_size_header();

    record.start_size_header(2);
    ustring session_ticket_bytes = ticket.encrypt(encryption_key);
    record.write(session_ticket_bytes);
    record.end_size_header();

    record.start_size_header(2);
    // extensions - 0-RTT
    record.end_size_header();

    record.end_size_header();
    return record;
}

}
