
#include "session_ticket.hpp"
#include "../global.hpp"
#include "TLS_enums.hpp"
#include "TLS_utils.hpp"
#include "Cryptography/one_way/keccak.hpp"

namespace fbw {
ustring TLS13SessionTicket::serialise() {
    constexpr int header_size = 22;
    ustring out;
    out.reserve(header_size + resumption_secret.size() + sni.size() + 2);
    out.resize(header_size);
    checked_bigend_write(version, out, 0, 2);
    checked_bigend_write(ticket_lifetime, out, 2, 3);
    checked_bigend_write(issued_at, out, 5, 8);
    checked_bigend_write(ticket_age_add, out, 13, 4);
    checked_bigend_write(uint16_t(cipher_suite), out, 17, 2);
    checked_bigend_write(uint8_t(early_data_allowed), out, 19, 1);
    assert(resumption_secret.size() < 256);
    checked_bigend_write(resumption_secret.size(), out, 20, 1);
    checked_bigend_write(sni.size(), out, 21, 1);
    out.append(resumption_secret.begin(), resumption_secret.end());
    out.append(sni.begin(), sni.end());
    return out;
}

std::optional<TLS13SessionTicket> TLS13SessionTicket::deserialise(ustring ticket) {
    constexpr size_t header_size = 22;
    if(ticket.size() < header_size) {
        return std::nullopt;
    }
    TLS13SessionTicket out;
    out.version = try_bigend_read(ticket, 0, 2);
    out.ticket_lifetime = try_bigend_read(ticket, 2, 3);
    out.issued_at = try_bigend_read(ticket, 5, 8);
    out.ticket_age_add = try_bigend_read(ticket, 13, 4);
    out.cipher_suite = static_cast<cipher_suites>(try_bigend_read(ticket, 17, 2));
    out.early_data_allowed = try_bigend_read(ticket, 19, 1) != 0ull;
    const size_t resumption_secret_len = try_bigend_read(ticket, 20, 1);
    const size_t sni_len = try_bigend_read(ticket, 21, 1);
    if(ticket.size() != header_size + resumption_secret_len + sni_len) {
        return std::nullopt;
    }
    auto it = ticket.begin() + header_size;
    out.resumption_secret.assign(it, it + resumption_secret_len);
    it += resumption_secret_len;
    out.sni.assign(it, it + sni_len);
    return out;
}

ustring TLS13SessionTicket::encrypt(std::array<uint8_t, 16> encryption_key) {
    return serialise(); // todo:
}

std::optional<TLS13SessionTicket> TLS13SessionTicket::decrypt(ustring ticket, std::array<uint8_t, 16> encryption_key) {
    auto out = deserialise(ticket); // todo
    return out;
}

std::optional<tls_record> TLS13SessionTicket::server_session_ticket_record(TLS13SessionTicket ticket, std::array<uint8_t, 16> encryption_key, ustring nonce) {
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
    checked_bigend_write(ticket.ticket_age_add, ticket_age_add, 0, 4);
    record.write(ticket_age_add);
    
    record.start_size_header(1);
    record.write(nonce);
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
