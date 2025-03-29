
#include "session_ticket.hpp"
#include "../global.hpp"
#include "TLS_enums.hpp"
#include "TLS_utils.hpp"
#include "Cryptography/one_way/keccak.hpp"

namespace fbw {

std::array<uint8_t, 16> session_ticket_master_secret {};

ustring TLS13SessionTicket::serialise() {
    constexpr int header_size = 23;
    ustring out;
    out.reserve(header_size + resumption_secret.size() + sni.size() + alpn.size() + 2);
    out.resize(header_size);
    checked_bigend_write(version, out, 0, 2);
    checked_bigend_write(ticket_lifetime, out, 2, 3);
    checked_bigend_write(issued_at, out, 5, 8);
    checked_bigend_write(ticket_age_add, out, 13, 4);
    checked_bigend_write(uint16_t(cipher_suite), out, 17, 2);
    checked_bigend_write(uint8_t(early_data_allowed), out, 19, 1);
    assert(resumption_secret.size() < 256);
    assert(sni.size() < 256);
    assert(alpn.size() < 256);
    checked_bigend_write(resumption_secret.size(), out, 20, 1);
    checked_bigend_write(sni.size(), out, 21, 1);
    checked_bigend_write(alpn.size(), out, 22, 1);

    out.append(resumption_secret.begin(), resumption_secret.end());
    out.append(sni.begin(), sni.end());
    out.append(alpn.begin(), alpn.end());
    return out;
}

std::optional<TLS13SessionTicket> TLS13SessionTicket::deserialise(ustring ticket) {
    constexpr size_t header_size = 23;

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
    out.number_once = 0;
    const size_t resumption_secret_len = try_bigend_read(ticket, 20, 1);
    const size_t sni_len = try_bigend_read(ticket, 21, 1);
    const size_t alpn_len = try_bigend_read(ticket, 22, 1);
    if(ticket.size() != header_size + resumption_secret_len + sni_len + alpn_len) {
        return std::nullopt;
    }
    auto it = ticket.begin() + header_size;
    out.resumption_secret.assign(it, it + resumption_secret_len);
    it += resumption_secret_len;
    out.sni.assign(it, it + sni_len);
    it += sni_len;
    out.alpn.assign(it, it + alpn_len);
    return out;
}

ustring encrypt_message(ustring plaintext, const std::array<uint8_t, 16>& encryption_key, uint64_t number_once) {
    constexpr size_t number_once_size = 8;
    constexpr size_t mac_size = 16;
    std::array<uint8_t, number_once_size> number_once_bytes;

    checked_bigend_write(number_once, number_once_bytes, 0, 8);
    
    keccak_sponge bytestream;
    bytestream.absorb(encryption_key.data(), encryption_key.size());
    bytestream.absorb(number_once_bytes.data(), number_once_bytes.size());

    for(size_t i = 0; i < plaintext.size(); i++) {
        uint8_t c;
        bytestream.squeeze(&c, 1);
        plaintext[i] ^= c;
    }
    plaintext.append(number_once_bytes.begin(), number_once_bytes.end());

    keccak_sponge macgen;
    macgen.absorb(encryption_key.data(), encryption_key.size());
    macgen.absorb(plaintext.data(), plaintext.size());

    plaintext.resize(plaintext.size() + mac_size);
    macgen.squeeze(plaintext.data() + plaintext.size() - mac_size, mac_size);
    return plaintext;
}

std::optional<std::pair<ustring, uint64_t>> decrypt_message(ustring ciphertext, const std::array<uint8_t, 16>& encryption_key) {
    constexpr size_t number_once_size = 8;
    constexpr size_t mac_size = 16;
    if(ciphertext.size() < (number_once_size + mac_size)) {
        return std::nullopt;
    }
    std::array<uint8_t, mac_size> mac;

    keccak_sponge macgen;
    macgen.absorb(encryption_key.data(), encryption_key.size());
    macgen.absorb(ciphertext.data(), ciphertext.size() - mac_size);
    macgen.squeeze(mac.data(), mac.size());

    if(!std::equal(mac.begin(), mac.end(), ciphertext.end() - mac_size)) {
        return std::nullopt;
    }
    ciphertext.resize(ciphertext.size() - mac_size);

    keccak_sponge bytestream;
    bytestream.absorb(encryption_key.data(), encryption_key.size());
    bytestream.absorb(ciphertext.data() + ciphertext.size() - number_once_size, number_once_size);

    uint64_t number_once = try_bigend_read(ciphertext, ciphertext.size() - number_once_size, 8);

    ciphertext.resize(ciphertext.size() - number_once_size);

    for(size_t i = 0; i < ciphertext.size(); i++) {
        uint8_t c;
        bytestream.squeeze(&c, 1);
        ciphertext[i] ^= c;
    }
    return {{ std::move(ciphertext), number_once }};
}

ustring TLS13SessionTicket::encrypt_ticket(const std::array<uint8_t, 16>& encryption_key, uint64_t number_once) {
    auto plaintext = serialise();
    return encrypt_message(std::move(plaintext), encryption_key, number_once);
}

std::optional<TLS13SessionTicket> TLS13SessionTicket::decrypt_ticket(ustring ticket, const std::array<uint8_t, 16>& encryption_key) {
    auto opt_ticket_bytes_number_once = decrypt_message(ticket, encryption_key);
    if(!opt_ticket_bytes_number_once) {
        return std::nullopt;
    }
    auto opt_ticket = deserialise(std::move(opt_ticket_bytes_number_once->first));
    if(!opt_ticket) {
        return std::nullopt;
    }
    opt_ticket->number_once = opt_ticket_bytes_number_once->second;
    assert(opt_ticket->number_once != 0);
    return opt_ticket;
}

void write_early_data_ticket_ext(tls_record& record) {
    record.write2(ExtensionType::early_data);
    record.start_size_header(2);
    std::array<uint8_t, 4> max_0rtt_bytes;
    checked_bigend_write(MAX_EARLY_DATA, max_0rtt_bytes, 0, 4);
    record.write(max_0rtt_bytes);
    record.end_size_header();
}

std::optional<tls_record> TLS13SessionTicket::server_session_ticket_record(TLS13SessionTicket ticket, std::array<uint8_t, 16> encryption_key, uint64_t number_once) {

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

    std::array<uint8_t, 8> number_once_bytes;
    checked_bigend_write(number_once, number_once_bytes, 0, 8);
    
    record.start_size_header(1);
    record.write(number_once_bytes);
    record.end_size_header();

    record.start_size_header(2);
    ustring session_ticket_bytes = ticket.encrypt_ticket(encryption_key, number_once);
    record.write(session_ticket_bytes);
    record.end_size_header();

    record.start_size_header(2);

    if(ticket.early_data_allowed) {
        write_early_data_ticket_ext(record);
    }
    
    record.end_size_header();

    record.end_size_header();
    return record;
}

}
