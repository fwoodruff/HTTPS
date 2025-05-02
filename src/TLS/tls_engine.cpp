//
//  tls_engine.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 25/03/2025.
//  Refactored from protocol.cpp written 25/11/2021

#include "protocol.hpp"

#include "Cryptography/assymetric/x25519.hpp"
#include "Cryptography/one_way/sha2.hpp"
#include "Cryptography/assymetric/secp256r1.hpp"
#include "PEMextract.hpp"
#include "TLS_enums.hpp"
#include "../global.hpp"
#include "Cryptography/one_way/keccak.hpp"
#include "Cryptography/cipher/block_chain.hpp"
#include "Cryptography/cipher/galois_counter.hpp"
#include "Cryptography/cipher/chacha20poly1305.hpp"
#include "Cryptography/key_derivation.hpp"
#include "TLS_utils.hpp"
#include "session_ticket.hpp"
#include "tls_engine.hpp"

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <utility>
#include <thread>

#include <queue>

namespace fbw {

using enum ContentType;

tls_engine::tls_engine() {
    handshake.p_cipher_context = &cipher_context;
    handshake.p_tls_version = &tls_protocol_version;
}

// application layer protocol negotiation
std::string tls_engine::alpn() {
    return handshake.alpn;
}

HandshakeStage tls_engine::process_net_read(std::queue<packet_timed>& network_output, std::deque<uint8_t>& application_data, const std::deque<uint8_t>& bio_input, std::optional<milliseconds> app_timeout) {
    try {
        if(m_expected_read_record == HandshakeStage::application_data or m_expected_read_record == HandshakeStage::client_early_data) {
            std::scoped_lock lk { m_write_queue_mut };
            update_sync(network_output);
        }
        if(m_expected_read_record == HandshakeStage::application_closed) {
            return m_expected_read_record;
        }
        m_buffer.insert(m_buffer.end(), bio_input.begin(), bio_input.end() );
        while(auto opt_record = pop_record_from_buffer()) {
            
            assert(opt_record);
            auto record = *opt_record;
            record = decrypt_record(record);
            switch (static_cast<ContentType>(record.get_type()) ) {
                case Handshake:
                {
                    std::scoped_lock lk { m_write_queue_mut };
                    client_handshake_record_sync(network_output, std::move(record));
                    break;
                }
                [[unlikely]] case ChangeCipherSpec:
                    client_change_cipher_spec(std::move(record));
                    break;
                case Application:
                    if(m_expected_read_record == HandshakeStage::application_data) {
                        application_data.insert(application_data.end(), record.m_contents.begin(), record.m_contents.end());
                        continue;
                    }
                    if(m_expected_read_record == HandshakeStage::client_early_data or m_expected_read_record == HandshakeStage::client_handshake_finished) {
                        early_data_received += record.m_contents.size();
                        if(early_data_received > MAX_EARLY_DATA) {
                            throw ssl_error("too much early data", AlertLevel::fatal, AlertDescription::unexpected_message);
                        }
                        if(!handshake.zero_rtt) {
                            break;
                        }
                        application_data.insert(application_data.end(), record.m_contents.begin(), record.m_contents.end());
                        break;
                    }
                    throw ssl_error("handshake not done yet", AlertLevel::fatal, AlertDescription::insufficient_security);
                case Alert: {
                    std::scoped_lock lk { m_write_queue_mut };
                    client_alert_sync(network_output, std::move(record), project_options.error_timeout);
                    return m_expected_read_record;
                }
                case Heartbeat: {
                    std::scoped_lock lk { m_write_queue_mut };
                    client_heartbeat(network_output, std::move(record), project_options.session_timeout);
                    break;
                }
                [[unlikely]] case Invalid:
                    throw ssl_error("invalid record type", AlertLevel::fatal, AlertDescription::unexpected_message);
                [[unlikely]] default:
                    throw ssl_error("nonexistent record type", AlertLevel::fatal, AlertDescription::decode_error);
            }
        }
    } catch(const ssl_error& e) {
        std::scoped_lock lk { m_write_queue_mut };
        server_alert_sync(network_output, e.m_l, e.m_d);
        return m_expected_read_record;
    } catch(const std::exception& e) {
        std::scoped_lock lk { m_write_queue_mut };
        server_alert_sync(network_output, AlertLevel::fatal, AlertDescription::decode_error);
        return m_expected_read_record;
    }
    return m_expected_read_record;;
}

void tls_engine::update_sync(std::queue<packet_timed>& output) {
    if(auto* ctx = dynamic_cast<cipher_base_tls13*>(cipher_context.get())) {
        if(ctx->do_key_reset()) {
            server_key_update_sync(output);
        }
    }
}

// if the last record is going to be really small, just add that data to the penultimate record
bool squeeze_last_chunk(ssize_t additional_data_len) {
    return  size_t(additional_data_len) < WRITE_RECORD_SIZE and 
            additional_data_len != 0 and 
            additional_data_len + WRITE_RECORD_SIZE + 50 < TLS_RECORD_SIZE and
            size_t(additional_data_len) * 3 < WRITE_RECORD_SIZE * 2;
}

stream_result tls_engine::process_net_write(std::queue<packet_timed>& output, std::vector<uint8_t> data, std::optional<milliseconds> timeout) {
    std::optional<ssl_error> error_ssl{};
    std::scoped_lock lk { m_write_queue_mut };
    assert(server_cipher_spec);
    if(write_connection_done) {
        return stream_result::closed;
    }
    try {
        size_t idx = 0;
        while(idx < data.size()) {
            tls_record record(Application);
            size_t write_size = std::min(WRITE_RECORD_SIZE, data.size() - idx);
            record.m_contents.assign(data.begin() + idx, data.begin() + idx + write_size);
            idx += write_size;
            write_record_sync(output, std::move(record), timeout);
        }
    } catch(const ssl_error& e) {
        error_ssl = e;
        server_alert_sync(output, error_ssl->m_l, error_ssl->m_d);
    } catch(const std::exception& e) {
        server_alert_sync(output, AlertLevel::fatal, AlertDescription::decode_error);
    }
    return stream_result::ok;
}

// When the server encounters an error, it sends that error here
void tls_engine::server_alert_sync(std::queue<packet_timed>& output, AlertLevel level, AlertDescription description) {
    auto r = tls_record(Alert);
    r.write1(level);
    r.write1(description);
    write_record_sync(output, std::move(r), project_options.error_timeout);
    write_connection_done = true;
}

// called internally to decrypt a client record on receipt
tls_record tls_engine::decrypt_record(tls_record record) {
    if(record.get_type() == Alert and tls_protocol_version == TLS13) {
        if(m_expected_read_record != HandshakeStage::application_data) {
            // A client could send an Alert record complaining about the Server Hello message while the Encrypted Extensions message is in-flight.
            // If a client has successfully processed a Server Hello message, record protection would disguise an Alert record as an Application record.
            // If a record has content type Alert and we haven't received the Client Finished message yet, we can infer this has occurred.
            // We would then reach this branch, and so we need to relax encryption requirements here.
            // See RFC 8446 Appendix A.1
            return record;
        }
    }
    if(record.get_type() == ChangeCipherSpec) {
        if(m_expected_read_record == HandshakeStage::application_data) {
            throw ssl_error("received change cipher spec after handshake finished", AlertLevel::fatal, AlertDescription::unexpected_message);
        }
        return record;
    }
    if(client_cipher_spec) {
        assert(cipher_context);
        auto encrypted_size = record.m_contents.size();
        try {
            record = cipher_context->deprotect(std::move(record));
        } catch(ssl_error& e) {
            if(record.get_type() == Application and 
                m_expected_read_record == HandshakeStage::client_handshake_finished and 
                handshake.client_hello.parsed_extensions.contains(ExtensionType::early_data) and
                !handshake.zero_rtt) {
                    // RFC 8446 4.2.10
                    //     The server then skips past early data by attempting to deprotect
                    //     received records using the handshake traffic key, discarding records
                    //     which fail deprotection up to the configured max_early_data_size
                    auto blank_record = tls_record(Application);
                    blank_record.m_contents.resize(encrypted_size);
                    return blank_record;
            }
            throw;
        }
    }
    return record;
}

std::optional<tls_record> tls_engine::pop_record_from_buffer() {
    auto record = try_extract_record(m_buffer);
    if(record == std::nullopt) {
        if (m_buffer.size() > TLS_RECORD_SIZE + TLS_HEADER_SIZE + TLS_EXPANSION_MAX) [[unlikely]] {
            throw ssl_error("oversized record", AlertLevel::fatal, AlertDescription::record_overflow);
        }
        return std::nullopt;
    }
    if (record->get_major_version() != 3) {
        throw ssl_error("unsupported version", AlertLevel::fatal, AlertDescription::protocol_version);
    }
    return *record;
}

void tls_engine::write_record_sync(std::queue<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout) {
    if(write_connection_done) {
        return;
    }
    if(server_cipher_spec and record.get_type() != ChangeCipherSpec) {
        assert(cipher_context);
        record = cipher_context->protect(record);
    }
    output.push({record.serialise(), timeout});
}

std::vector<std::vector<uint8_t>> extract_handshake_messages(tls_record handshake_record, std::vector<uint8_t>& fragment) {
    std::vector<std::vector<uint8_t>> messages;
    fragment.insert(fragment.end(), handshake_record.m_contents.begin(), handshake_record.m_contents.end());

    size_t offset = 0;
    while(offset + 4 <= fragment.size()) {
        size_t message_size = try_bigend_read(fragment, offset + 1, 3);
        if (offset + 4 + message_size > fragment.size()) {
            fragment.assign(fragment.begin() + offset, fragment.end());
            break;
        }
        messages.emplace_back(fragment.begin() + offset, fragment.begin() + offset + 4 + message_size);
        offset += 4 + message_size;
    }
    if (offset == fragment.size()) {
        fragment.clear();
    }
    return { handshake_record.m_contents };
}

void tls_engine::client_handshake_record_sync(std::queue<packet_timed>& output, tls_record record) {
    auto messages = extract_handshake_messages(std::move(record), m_handshake_fragment); // consider extracting one by one
    for(const auto& message : messages) {
        client_handshake_message_sync(output, message);
    }
}

void tls_engine::client_handshake_message_sync(std::queue<packet_timed>& output, const std::vector<uint8_t>& handshake_message) {
    switch (static_cast<HandshakeType>(handshake_message.at(0))) {
        [[unlikely]] case HandshakeType::hello_request:
            throw ssl_error("client should not send hello request", AlertLevel::fatal, AlertDescription::unexpected_message);
        case HandshakeType::client_hello:
        {
            client_hello(std::move(handshake_message));
            server_response_to_hello_sync(output);
            break;
        }
        case HandshakeType::end_of_early_data:
            client_end_of_early_data(std::move(handshake_message));
            break;
        case HandshakeType::client_key_exchange:
            client_key_exchange(std::move(handshake_message));
            break;
        // mTLS receive client certificate would go here
        case HandshakeType::finished:
            if(tls_protocol_version == TLS13) {
                client_handshake_finished13(std::move(handshake_message));
                server_session_ticket_sync(output);
            } else {
                client_handshake_finished12(std::move(handshake_message));
                server_change_cipher_spec(output);
                server_handshake_finished12(output);
            }
            break;
        case HandshakeType::key_update:
        {
            auto update_request = client_key_update_received(std::move(handshake_message));
            if(update_request == KeyUpdateRequest::update_requested) {
                server_key_update_sync(output);
            }
            break;
        }
        [[unlikely]] default:
            throw ssl_error("unsupported handshake record type", AlertLevel::fatal, AlertDescription::decode_error);
    }
    return;
}

void tls_engine::client_hello(const std::vector<uint8_t>& handshake_message) {
    if(m_expected_read_record != HandshakeStage::client_hello) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    handshake.client_hello_record(handshake_message);
    if(tls_protocol_version == TLS13) {
        if (handshake.zero_rtt) {
            m_expected_read_record = HandshakeStage::client_early_data;
        } else if(handshake.server_hello_type == ServerHelloType::hello_retry) {
            m_expected_read_record = HandshakeStage::client_hello;
        } else {
            m_expected_read_record = HandshakeStage::client_handshake_finished;
        }
    } else {
        m_expected_read_record = HandshakeStage::client_key_exchange;
    }
}

void tls_engine::server_response_to_hello_sync(std::queue<packet_timed>& output) {
    server_hello_sync(output);
    if(tls_protocol_version == TLS13) {
        if(handshake.server_hello_type == ServerHelloType::hello_retry) {
            // server hello message was a hello retry message so next record is client hello
            return;
        }
        if(handshake.middlebox_compatibility()) {
            server_change_cipher_spec(output);
        }
        server_encrypted_extensions(output);
        if(handshake.server_hello_type == ServerHelloType::preshared_key or handshake.server_hello_type == ServerHelloType::preshared_key_dh) {
        } else {
            // mTLS client_certificate_request message would go here
            server_certificate(output);
            server_certificate_verify(output);
        }
        server_handshake_finished13(output);
        
    }
    if(tls_protocol_version == TLS12) {
        server_certificate(output);
        server_key_exchange(output);
        server_hello_done(output);
    }
    return;
}

KeyUpdateRequest tls_engine::client_key_update_received(const std::vector<uint8_t>& handshake_message) {
    if(tls_protocol_version != TLS13) {
        throw ssl_error("key updates supported for TLS 1.3 only", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    if(m_expected_read_record != HandshakeStage::application_data) {
        throw ssl_error("key updates are post handshake only", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    auto key_update_message = der_span_read(handshake_message, 1, 3);
    if(key_update_message.size() != 1) {
        throw ssl_error("bad key update message", AlertLevel::fatal, AlertDescription::illegal_parameter);
    }
    auto update_request = static_cast<KeyUpdateRequest>(key_update_message[0]);
    if(update_request != KeyUpdateRequest::update_not_requested and update_request != KeyUpdateRequest::update_requested) {
        throw ssl_error("bad key update message", AlertLevel::fatal, AlertDescription::illegal_parameter);
    }
    
    auto& cli_key = handshake.tls13_key_schedule.client_application_traffic_secret;
    cli_key = hkdf_expand_label(*handshake.hash_ctor, cli_key, "traffic upd", std::string(""), handshake.hash_ctor->get_hash_size());
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_client_traffic_key(cli_key);
    
    return update_request;
}



void tls_engine::server_hello_sync(std::queue<packet_timed>& output) {
    auto hello_record = handshake.server_hello_record();
    write_record_sync(output, hello_record, project_options.handshake_timeout);

    if(tls_protocol_version == TLS13) {
        if(handshake.server_hello_type != ServerHelloType::hello_retry) {
            auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
            server_cipher_spec = true;
            client_cipher_spec = true;
            tls13_context.set_server_traffic_key(handshake.tls13_key_schedule.server_handshake_traffic_secret);
            if(handshake.client_hello.parsed_extensions.contains(ExtensionType::early_data)) {
                tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_early_traffic_secret);
            } else {
                tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_handshake_traffic_secret);
            }
        }
    }
}

void tls_engine::server_encrypted_extensions(std::queue<packet_timed>& output) {
    tls_record out = handshake.server_encrypted_extensions_record();
    write_record_sync(output, out, project_options.handshake_timeout);
}

void tls_engine::server_certificate(std::queue<packet_timed>& output) {
    tls_record certificate_record = handshake.server_certificate_record();
    write_record_sync(output, certificate_record, project_options.handshake_timeout);
}

void tls_engine::server_certificate_verify(std::queue<packet_timed>& output) {
    auto record = handshake.server_certificate_verify_record();
    write_record_sync(output, record, project_options.handshake_timeout);
}

void tls_engine::server_handshake_finished13(std::queue<packet_timed>& output) {
    auto record = handshake.server_handshake_finished13_record();
    write_record_sync(output, record, project_options.handshake_timeout);
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_server_traffic_key(handshake.tls13_key_schedule.server_application_traffic_secret);
}

void tls_engine::client_handshake_finished13(const std::vector<uint8_t>& handshake_message) {
    if(m_expected_read_record != HandshakeStage::client_handshake_finished) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    assert(tls_protocol_version == TLS13);
    handshake.client_handshake_finished13_record(handshake_message);
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_application_traffic_secret);
    m_expected_read_record = HandshakeStage::application_data;
}

static std::atomic<uint64_t> global_number_once = 1;

void tls_engine::server_session_ticket_sync(std::queue<packet_timed>& output) {
    const auto number_once = global_number_once.fetch_add(1, std::memory_order_relaxed);
    std::vector<uint8_t> number_once_bytes(8, 0);
    checked_bigend_write(number_once, number_once_bytes, 0, 8);
    assert(handshake.hash_ctor != nullptr);
    const auto resumption_ticket_psk = hkdf_expand_label(*handshake.hash_ctor, handshake.tls13_key_schedule.resumption_master_secret, "resumption", number_once_bytes, handshake.hash_ctor->get_hash_size());

    session_ticket_numbers_once[number_once % SESSION_HASHSET_SIZE].store(number_once, std::memory_order::relaxed);

    // RFC 8446 4.2
    //      The server MAY also send unsolicited extensions in the NewSessionTicket
    const bool offer_0rtt = true;

    TLS13SessionTicket ticket;
    ticket.version = 1;
    ticket.ticket_lifetime = 7200; // seconds
    ticket.issued_at = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    ticket.ticket_age_add = randomgen.randgen64();
    ticket.cipher_suite = handshake.cipher;
    ticket.early_data_allowed = offer_0rtt;

    ticket.number_once = number_once;
    ticket.resumption_secret = resumption_ticket_psk;
    ticket.alpn = alpn();

    const auto record = TLS13SessionTicket::server_session_ticket_record(ticket, session_ticket_master_secret, number_once);

    if(record) {
        write_record_sync(output, *record, project_options.handshake_timeout);
    }
}

void tls_engine::server_key_exchange(std::queue<packet_timed>& output) {
    tls_record record = handshake.server_key_exchange_record();
    write_record_sync(output, record, project_options.handshake_timeout);
}

void tls_engine::server_hello_done(std::queue<packet_timed>& output) {
    auto record = handshake.server_hello_done_record();
    write_record_sync(output, record, project_options.handshake_timeout);
}

void tls_engine::client_key_exchange(std::vector<uint8_t> handshake_message) {
    if(m_expected_read_record != HandshakeStage::client_key_exchange) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    assert(tls_protocol_version == TLS12);
    auto key_material = handshake.client_key_exchange_receipt(handshake_message);
    auto& tls12_context = dynamic_cast<cipher_base_tls12&>(*cipher_context);
    tls12_context.set_key_material_12(key_material);
    m_expected_read_record = HandshakeStage::client_change_cipher_spec;
}

void tls_engine::client_end_of_early_data(std::vector<uint8_t> handshake_message) {
    if(m_expected_read_record != HandshakeStage::client_early_data) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    handshake.client_end_of_early_data_record(handshake_message);
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_handshake_traffic_secret);
    if(handshake.server_hello_type == ServerHelloType::hello_retry) {
        m_expected_read_record = HandshakeStage::client_hello;
    } else {
        m_expected_read_record = HandshakeStage::client_handshake_finished;
    }
    
}

void tls_engine::client_change_cipher_spec( tls_record record) {
    if(record.m_contents.size() != 1 or record.m_contents.at(0) != static_cast<uint8_t>(EnumChangeCipherSpec::change_cipher_spec)) [[unlikely]]  {
        throw ssl_error("bad cipher spec", AlertLevel::fatal, AlertDescription::decode_error);
    }
    if(tls_protocol_version == TLS13) {
        return;
    }
    if(m_expected_read_record != HandshakeStage::client_change_cipher_spec) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    client_cipher_spec = true;
    m_expected_read_record = HandshakeStage::client_handshake_finished;
}

void tls_engine::client_handshake_finished12(const std::vector<uint8_t>& handshake_message) {
    if(m_expected_read_record != HandshakeStage::client_handshake_finished) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    handshake.client_handshake_finished12_record(handshake_message);
    m_expected_read_record = HandshakeStage::application_data;
}

void tls_engine::server_change_cipher_spec(std::queue<packet_timed>& output) {
    tls_record record { ChangeCipherSpec };
    record.write1(EnumChangeCipherSpec::change_cipher_spec);
    write_record_sync(output, record, project_options.handshake_timeout);
    if(tls_protocol_version == TLS12) {
        server_cipher_spec = true;
    }
}

void tls_engine::server_handshake_finished12(std::queue<packet_timed>& output) {
    tls_record out(Handshake);
    out.write1(HandshakeType::finished);
    out.start_size_header(3);
    
    assert(handshake.handshake_hasher);
    auto handshake_hash = handshake.handshake_hasher->hash();
    assert(handshake_hash.size() == 32);
    
    std::vector<uint8_t> server_finished = prf(*handshake.hash_ctor, handshake.tls12_master_secret, "server finished", handshake_hash, 12);
    
    out.write(server_finished);
    out.end_size_header();
    write_record_sync(output, out, project_options.handshake_timeout);
}

void tls_engine::client_alert_sync(std::queue<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout) {
    m_expected_read_record = HandshakeStage::application_closed;
    const auto& alert_message = record.m_contents;
    if(alert_message.size() != 2) {
        return; // do not send anything after receiving malformed alert
    }
    switch(alert_message[0]) {
        case static_cast<uint8_t>(AlertLevel::warning):
            switch(alert_message[1]) {
                case static_cast<uint8_t>(AlertDescription::close_notify):
                {
                    tls_record record{ Alert};
                    record.m_contents = { static_cast<uint8_t>(AlertLevel::warning), static_cast<uint8_t>(AlertDescription::close_notify) };
                    write_record_sync(output, record, timeout);
                }
                break;
                default:
                    return;
            }
            break;
        default:
            return;
    }
}

void tls_engine::client_heartbeat(std::queue<packet_timed>& output, tls_record client_record, std::optional<milliseconds> timeout) {
    auto [heartblead, heartbeat_record] = client_heartbeat_record(client_record, can_heartbeat);
    if(heartblead) {
        // co_await m_client->write(to_unsigned("heartbleed?"), project_options.error_timeout);
        throw ssl_error("unexpected heartbeat response", AlertLevel::fatal, AlertDescription::access_denied);
    }
    write_record_sync(output, heartbeat_record, timeout);
}

std::pair<bool, tls_record> tls_engine::client_heartbeat_record(tls_record record, bool can_heartbeat) {
    if(!can_heartbeat) [[unlikely]] {
        throw ssl_error("bad heartbeat payload length", AlertLevel::fatal, AlertDescription::illegal_parameter);
    }
    auto heartbeat_message = record.m_contents;

    if (heartbeat_message.size() < 1 or heartbeat_message[0] != 0x01 ) [[unlikely]] {
        throw ssl_error("unexpected heartbeat response", AlertLevel::fatal, AlertDescription::access_denied);
    }

    auto payload_length = try_bigend_read(heartbeat_message, 1, 2);
    if (payload_length >  heartbeat_message.size() - 3) {
        return { true, {}};
    }

    std::vector<uint8_t> length_and_payload(heartbeat_message.begin() + 1,
                                            heartbeat_message.begin() + 3 + payload_length);

    

    tls_record heartbeat_record( Heartbeat);
    heartbeat_record.m_contents = { 0x02 };
    heartbeat_record.m_contents.insert(heartbeat_record.m_contents.end(), length_and_payload.begin(), length_and_payload.end());
    return {false, heartbeat_record} ;
}

tls_record server_key_update_record(KeyUpdateRequest req) {
    tls_record keyupdate(ContentType::Handshake);
    keyupdate.write1(HandshakeType::key_update);
    keyupdate.start_size_header(3);
    keyupdate.write1(req);
    keyupdate.end_size_header();
    return keyupdate;
}

void tls_engine::server_key_update_sync(std::queue<packet_timed>& output) {
    assert(tls_protocol_version == TLS13);
    auto keyupdate = server_key_update_record(KeyUpdateRequest::update_requested);
    write_record_sync(output, std::move(keyupdate), project_options.session_timeout);
    auto& srv_key = handshake.tls13_key_schedule.server_application_traffic_secret;
    srv_key = hkdf_expand_label(*handshake.hash_ctor, srv_key, "traffic upd", std::string(""), handshake.hash_ctor->get_hash_size());
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_server_traffic_key(srv_key);
}

// applications call this when graceful not abrupt closing of a connection is desired
void tls_engine::process_close_notify(std::queue<packet_timed>& output) {
    std::scoped_lock lk { m_write_queue_mut };
    server_alert_sync(output, AlertLevel::warning, AlertDescription::close_notify);
}

stream_result tls_engine::close_notify_finish(const std::deque<uint8_t>& bio_input) {
    m_buffer.insert(m_buffer.end(), bio_input.begin(), bio_input.end());
    auto opt_record = pop_record_from_buffer();
    if(!opt_record) {
        return stream_result::awaiting;
    }
    m_expected_read_record = HandshakeStage::application_closed;
    return stream_result::closed;
}


}
