//
//  TLS.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

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
#include "../Runtime/task.hpp"
#include "../TCP/tcp_stream.hpp"
#include "Cryptography/key_derivation.hpp"
#include "TLS_utils.hpp"
#include "session_ticket.hpp"

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

#ifdef __cpp_impl_coroutine
#include <coroutine>
#else
#include <experimental/coroutine>
namespace std {
    namespace experimental {}
    using namespace experimental;
}
#endif

namespace fbw {

using enum ContentType;

TLS::TLS(std::unique_ptr<stream> output_stream) : m_client(std::move(output_stream) ) {}

// application code calls this to decrypt and read data
task<stream_result> TLS::read_append(ustring& data, std::optional<milliseconds> timeout) {
    std::optional<ssl_error> error_ssl {};
    try {
        assert(m_expected_record == HandshakeStage::application_data);

        auto res = co_await flush();
        if(res != stream_result::ok) {
            co_return res;
        }

        if(auto* ctx = dynamic_cast<cipher_base_tls13*>(cipher_context.get())) {
            if(ctx->do_key_reset()) {
                co_await server_key_update();
            }
        }

        auto [record, result] = co_await try_read_record(timeout);
        if(result != stream_result::ok) {
            co_return result;
        }
        record = decrypt_record(record);
        switch (static_cast<ContentType>(record.get_type()) ) {
            case Handshake:
                co_return co_await client_post_handshake(std::move(record.m_contents), timeout);
            [[unlikely]] case ChangeCipherSpec:
                co_await server_alert(AlertLevel::fatal, AlertDescription::unexpected_message);
                co_return stream_result::closed;
            case Application:
                data.append(std::move(record.m_contents));
                co_return stream_result::ok;
            case Alert:
                co_await client_alert(std::move(record), timeout);
                co_return stream_result::closed;
            case Heartbeat:
                co_await client_heartbeat(std::move(record), timeout);
                co_return stream_result::ok;
            [[unlikely]] case Invalid:
                    throw ssl_error("invalid record type", AlertLevel::fatal, AlertDescription::unexpected_message);
            [[unlikely]] default:
                throw ssl_error("nonexistent record type", AlertLevel::fatal, AlertDescription::decode_error);

        }
    } catch(const ssl_error& e) {
        error_ssl = e;
        goto END; // cannot co_await inside a catch block
    } catch(const std::exception& e) {
        goto END2;
    }
END:
    co_await server_alert(error_ssl->m_l, error_ssl->m_d);
    co_return stream_result::closed;
END2:
    co_await server_alert(AlertLevel::fatal, AlertDescription::decode_error);
    co_return stream_result::closed;
}

// if the last record is going to be really small, just add that data to the penultimate record
bool squeeze_last_chunk(ssize_t additional_data_len) {
    return  size_t(additional_data_len) < WRITE_RECORD_SIZE and 
            additional_data_len != 0 and 
            additional_data_len + WRITE_RECORD_SIZE + 50 < TLS_RECORD_SIZE and
            size_t(additional_data_len) * 3 < WRITE_RECORD_SIZE * 2;
}

// application code calls this to send data to the client
task<stream_result> TLS::write(ustring data, std::optional<milliseconds> timeout) {
    std::optional<ssl_error> error_ssl{};
    try {
        size_t idx = 0;
        while(idx < data.size()) {
            if(encrypt_send.empty()) {
                encrypt_send.emplace_back(Application);
            }
            auto& active_record = encrypt_send.back();
            size_t write_size = std::min(WRITE_RECORD_SIZE - active_record.m_contents.size(), data.size() - idx);
            encrypt_send.back().m_contents.append( data.begin() + idx,  data.begin() + idx + write_size);
            idx += write_size;
            if (active_record.m_contents.size() == WRITE_RECORD_SIZE) {
                encrypt_send.emplace_back(Application);
                if(encrypt_send.size() > 2) {
                    auto res = co_await write_record(std::move(encrypt_send.front()), timeout);
                    encrypt_send.pop_front();
                    if (res != stream_result::ok) {
                        co_return res;
                    }
                }
            }
        }
        co_return stream_result::ok;
    } catch(const ssl_error& e) {
        error_ssl = e;
        goto END; // cannot co_await inside a catch block
    } catch(const std::exception& e) {
        goto END2;
    }
END:
    co_await server_alert(error_ssl->m_l, error_ssl->m_d);
    co_return stream_result::closed;
END2:
    co_await server_alert(AlertLevel::fatal, AlertDescription::decode_error);
    co_return stream_result::closed;
}

// application data is sent on a buffered stream so the pattern of record sizes reveals much less
task<stream_result> TLS::flush() {
    if(encrypt_send.size() >= 2) {
        if(squeeze_last_chunk(encrypt_send.back().m_contents.size())) {
            auto back = std::move(encrypt_send.back());
            encrypt_send.pop_back();
            encrypt_send.back().m_contents.append(back.m_contents);
        }
    }
    while(!encrypt_send.empty()) {
        auto& record = encrypt_send.front();
        if(record.m_contents.empty()) {
            encrypt_send.pop_front();
            continue;
        }
        auto res = co_await write_record(std::move(record), project_options.session_timeout);
        encrypt_send.pop_front();
        if (res != stream_result::ok) {
            co_return res;
        }
    }
    co_return stream_result::ok;
}

// applications call this when graceful not abrupt closing of a connection is desired
task<void> TLS::close_notify() {
    try {
        co_await flush();
        co_await server_alert(AlertLevel::warning, AlertDescription::close_notify);
        auto [record, result] = co_await try_read_record(project_options.error_timeout);
        if(result != stream_result::ok) {
            co_return;
        }
        if(static_cast<ContentType>(record.get_type()) != Alert) {
            co_await server_alert(AlertLevel::fatal, AlertDescription::unexpected_message);
            co_return;
        }
        using namespace std::literals::chrono_literals;
        co_await m_client->close_notify();
    } catch(const std::exception& e) { }
}

// When the server encounters an error, it sends that error here
task<void> TLS::server_alert(AlertLevel level, AlertDescription description) {
    auto r = tls_record(Alert);
    r.write1(level);
    r.write1(description);
    co_await write_record(std::move(r), project_options.error_timeout);
}

// Called when a client connects, to secure the channel
task<std::string> TLS::perform_handshake() {
    std::optional<ssl_error> error_ssl {};
    try {
        handshake.p_cipher_context = &cipher_context;
        handshake.p_tls_version = &tls_protocol_version;
        bool hello_request_sent = false;
        for(;;) {
            auto [record, result] = co_await try_read_record(project_options.handshake_timeout);
            if(result == stream_result::read_timeout) {
                if(!hello_request_sent) {
                    auto res = co_await server_hello_request();
                    if(res == stream_result::ok) {
                        hello_request_sent = true;
                        continue;
                    }
                }
                co_return "";
            }
            if(result != stream_result::ok) {
                co_return "";
            }
            record = decrypt_record(record);
            switch ( static_cast<ContentType>(record.get_type()) ) {
                case Handshake:
                    if(co_await client_handshake_record(std::move(record)) != stream_result::ok) {
                        co_return "";
                    }
                    if(m_expected_record == HandshakeStage::application_data) {
                        co_return handshake.alpn;
                    }
                    break;
                case ChangeCipherSpec:
                    client_change_cipher_spec(std::move(record));
                    break;
                [[unlikely]] case Application:
                    throw ssl_error("handshake not done yet", AlertLevel::fatal, AlertDescription::insufficient_security);
                case Alert:
                    co_await client_alert(std::move(record), project_options.handshake_timeout);
                    co_return "";
                case Heartbeat:
                    {
                        auto res = co_await client_heartbeat(std::move(record), project_options.handshake_timeout);
                        if(res != stream_result::ok) {
                            co_return "";
                        }
                    }
                    break;
                [[unlikely]] case Invalid:
                    throw ssl_error("invalid record type", AlertLevel::fatal, AlertDescription::unexpected_message);
                [[unlikely]] default:
                    throw ssl_error("nonexistent record type", AlertLevel::fatal, AlertDescription::decode_error);
            }
        }
    } catch(const ssl_error& e) {
        error_ssl = e;
        goto END; // cannot co_await inside a catch block
    } catch(const std::exception& e) {
        goto END2;
    }
END:
    co_await server_alert(error_ssl->m_l, error_ssl->m_d);
    co_return "";
END2:
    co_await server_alert(AlertLevel::fatal, AlertDescription::decode_error);
    co_return "";
}

// called internally to decrypt a client record on receipt
tls_record TLS::decrypt_record(tls_record record) {
    if(record.get_type() == Alert and tls_protocol_version == TLS13) {
        if(m_expected_record != HandshakeStage::application_data) {
            // A client could send an Alert record complaining about the Server Hello message while the Encrypted Extensions message is in-flight.
            // If a client has successfully processed a Server Hello message, record protection would disguise an Alert record as an Application record.
            // If a record has content type Alert and we haven't received the Client Finished message yet, we can infer this has occurred.
            // We would then reach this branch, and so we need to relax encryption requirements here.
            // See RFC 8446 Appendix A.1
            return record;
        }
    }
    if(record.get_type() == ChangeCipherSpec) {
        if(m_expected_record == HandshakeStage::application_data) {
            throw ssl_error("received change cipher spec after handshake finished", AlertLevel::fatal, AlertDescription::unexpected_message);
        }
        return record;
    }
    if(client_cipher_spec) {
        record = cipher_context->decrypt(std::move(record));
    }
    return record;
}

task<stream_result> TLS::server_hello_request() {
    if(m_expected_record == HandshakeStage::client_hello) { // no handshake renegotiations after renegotiation indicator sent
        tls_record hello_request{Handshake};
        hello_request.write1(HandshakeType::hello_request);
        hello_request.start_size_header(3);
        hello_request.end_size_header();
        co_return co_await write_record(hello_request, project_options.handshake_timeout);
    }
    co_return stream_result::closed;
}

task<std::pair<tls_record, stream_result>> TLS::try_read_record(std::optional<milliseconds> timeout) {
    for(;;) {
        auto record = try_extract_record(m_buffer);
        if(record) {
            if (record->get_major_version() != 3) {
                throw ssl_error("unsupported version", AlertLevel::fatal, AlertDescription::protocol_version);
            }
            co_return { *record, stream_result::ok };
        }
        if (m_buffer.size() > TLS_RECORD_SIZE + TLS_HEADER_SIZE + TLS_EXPANSION_MAX) [[unlikely]] {
            throw ssl_error("oversized record", AlertLevel::fatal, AlertDescription::record_overflow);
        }
        stream_result connection_alive = co_await m_client->read_append(m_buffer, timeout);
        if(connection_alive != stream_result::ok) {
            co_return { {}, connection_alive };
        }
    }
}

task<stream_result> TLS::write_record(tls_record record, std::optional<milliseconds> timeout) {
    if(server_cipher_spec && record.get_type() != ChangeCipherSpec) {
        record = cipher_context->encrypt(record);
    }
    co_return co_await m_client->write(record.serialise(), timeout);
}

std::vector<ustring> extract_handshake_messages(tls_record handshake_record, ustring& fragment) {
    std::vector<ustring> messages;
    fragment.append(handshake_record.m_contents.begin(), handshake_record.m_contents.end());

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

task<stream_result> TLS::client_handshake_record(tls_record record) {
    auto messages = extract_handshake_messages(std::move(record), m_handshake_fragment);
    for(const auto& message : messages) {
        auto res = co_await client_handshake_message(message);
        if(res != stream_result::ok) {
            co_return res;
        }
    }
    co_return stream_result::ok;
}

task<stream_result> TLS::client_handshake_message(const ustring& handshake_message) {
    switch (handshake_message.at(0)) {
        [[unlikely]] case static_cast<uint8_t>(HandshakeType::hello_request):
            throw ssl_error("client should not send hello request", AlertLevel::fatal, AlertDescription::unexpected_message);
        case static_cast<uint8_t>(HandshakeType::client_hello):
            client_hello(std::move(handshake_message));
            if(auto result = co_await server_hello(); result != stream_result::ok) {
                co_return result;
            }
            if(tls_protocol_version == TLS13) {
                if(handshake.is_hello_retry()) {
                    co_return stream_result::ok;
                }
                if(handshake.middlebox_compatibility()) {
                    if(auto result = co_await server_change_cipher_spec(); result != stream_result::ok) {
                        co_return result;
                    }
                }
                if(auto result = co_await server_encrypted_extensions(); result != stream_result::ok) {
                    co_return result;
                }
                // mTLS client_certificate_request message would go here
                if(auto result = co_await server_certificate(); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_certificate_verify(); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_handshake_finished13(); result != stream_result::ok) {
                    co_return result;
                }
            }
            if(tls_protocol_version == TLS12) {
                if(auto result = co_await server_certificate(); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_key_exchange(); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_hello_done(); result != stream_result::ok) {
                    co_return result;
                }
            }
            break;
        case static_cast<uint8_t>(HandshakeType::client_key_exchange):
            client_key_exchange(std::move(handshake_message));
            break;
        // mTLS receive client certificate would go here
        case static_cast<uint8_t>(HandshakeType::finished):
            if(tls_protocol_version == TLS13) {
                client_handshake_finished13(std::move(handshake_message));
                if(auto result = co_await server_session_ticket(); result != stream_result::ok) {
                    co_return result;
                }
            } else {
                client_handshake_finished12(std::move(handshake_message));
                if(auto result = co_await server_change_cipher_spec(); result != stream_result::ok) {
                    co_return std::move(result);
                }
                if(auto result = co_await server_handshake_finished12(); result != stream_result::ok) {
                    co_return std::move(result);
                }
            }
            co_return stream_result::ok;
        [[unlikely]] default:
            throw ssl_error("unsupported handshake record type", AlertLevel::fatal, AlertDescription::decode_error);
    }
    co_return stream_result::ok;
}

void TLS::client_hello(const ustring& handshake_message) {
    if(m_expected_record != HandshakeStage::client_hello) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    handshake.client_hello_record(handshake_message);
    m_expected_record = HandshakeStage::server_hello;
}

task<stream_result> TLS::server_hello() {
    assert(m_expected_record == HandshakeStage::server_hello);
    auto hello_record = handshake.server_hello_record();
    auto result = co_await write_record(hello_record, project_options.handshake_timeout);

    if(tls_protocol_version == TLS13) {
        if(handshake.is_hello_retry()) {
            m_expected_record = HandshakeStage::client_hello;
        } else {
            auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
            tls13_context.set_server_traffic_key(handshake.tls13_key_schedule.server_handshake_traffic_secret);
            tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_handshake_traffic_secret);
            server_cipher_spec = true;
            client_cipher_spec = true;
            m_expected_record = HandshakeStage::server_encrypted_extensions;
        }
    } else {
        m_expected_record = HandshakeStage::server_certificate;
    }
    co_return result;
}

task<stream_result> TLS::server_encrypted_extensions() {
    assert(m_expected_record == HandshakeStage::server_encrypted_extensions);
    tls_record out = handshake.server_encrypted_extensions_record();
    m_expected_record = HandshakeStage::server_certificate;
    co_return co_await write_record(out, project_options.handshake_timeout);
}

task<stream_result> TLS::server_certificate() {
    assert(m_expected_record == HandshakeStage::server_certificate);
    tls_record certificate_record = handshake.server_certificate_record();
    if(tls_protocol_version == TLS13) {
        m_expected_record = HandshakeStage::server_certificate_verify;
    } else {
        m_expected_record = HandshakeStage::server_key_exchange;
    }
    co_return co_await write_record(certificate_record, project_options.handshake_timeout);
}

task<stream_result> TLS::server_certificate_verify() {
    assert(m_expected_record == HandshakeStage::server_certificate_verify);
    auto record = handshake.server_certificate_verify_record();
    m_expected_record = HandshakeStage::server_handshake_finished;
    co_return co_await write_record(record, project_options.handshake_timeout);
}

task<stream_result> TLS::server_handshake_finished13() {
    assert(m_expected_record == HandshakeStage::server_handshake_finished);
    auto record = handshake.server_handshake_finished13_record();
    m_expected_record = HandshakeStage::client_handshake_finished; // mTLS would change this
    auto res = co_await write_record(record, project_options.handshake_timeout);
    co_return res;
}

void TLS::client_handshake_finished13(const ustring& handshake_message) {
    if(m_expected_record != HandshakeStage::client_handshake_finished) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    assert(tls_protocol_version == TLS13);
    handshake.client_handshake_finished13_record(handshake_message);
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_server_traffic_key(handshake.tls13_key_schedule.server_application_traffic_secret);
    tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_application_traffic_secret);
    m_expected_record = HandshakeStage::application_data;
}

static std::atomic<uint64_t> global_nonce = 0;
task<stream_result> TLS::server_session_ticket() {
    assert(m_expected_record == HandshakeStage::application_data);
    auto nonce = global_nonce.fetch_add(1, std::memory_order_relaxed);
    ustring nonce_bytes(8, 0);
    checked_bigend_write(nonce, nonce_bytes, 0, 8);
    assert(handshake.hash_ctor != nullptr);
    auto resumption_ticket_psk = hkdf_expand_label(*handshake.hash_ctor, handshake.tls13_key_schedule.resumption_master_secret, "resumption", nonce_bytes, handshake.hash_ctor->get_hash_size());

    TLS13SessionTicket ticket;
    ticket.version = 1;
    ticket.ticket_lifetime = 7200; // seconds
    ticket.issued_at = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    ticket.ticket_age_add = randomgen.randgen64();
    ticket.cipher_suite = handshake.cipher;
    ticket.early_data_allowed = false;
    ticket.resumption_secret = resumption_ticket_psk;
    
    auto record = TLS13SessionTicket::server_session_ticket_record(ticket, {}, nonce_bytes); // todo: use secure key
    if(record) {
        auto res = co_await write_record(*record, project_options.handshake_timeout);
        co_return res;
    }
    co_return stream_result::ok;
}

task<stream_result> TLS::server_key_exchange() {
    
    tls_record record = handshake.server_key_exchange_record();
    
    m_expected_record = HandshakeStage::server_hello_done;
    co_return co_await write_record(record, project_options.handshake_timeout);
}

task<stream_result> TLS::server_hello_done() {
    assert(m_expected_record == HandshakeStage::server_hello_done);
    auto record = handshake.server_hello_done_record();
    
    m_expected_record = HandshakeStage::client_key_exchange;
    co_return co_await write_record(record, project_options.handshake_timeout);
}

void TLS::client_key_exchange(ustring handshake_message) {
    if(m_expected_record != HandshakeStage::client_key_exchange) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    assert(tls_protocol_version == TLS12);
    auto key_material = handshake.client_key_exchange_receipt(handshake_message);
    auto& tls12_context = dynamic_cast<cipher_base_tls12&>(*cipher_context);
    tls12_context.set_key_material_12(key_material);
    m_expected_record = HandshakeStage::client_change_cipher_spec;
}

void TLS::client_change_cipher_spec( tls_record record) {
    if(record.m_contents.size() != 1 or record.m_contents.at(0) != static_cast<uint8_t>(EnumChangeCipherSpec::change_cipher_spec)) [[unlikely]]  {
        throw ssl_error("bad cipher spec", AlertLevel::fatal, AlertDescription::decode_error);
    }
    if(tls_protocol_version == TLS13) {
        return;
    }
    if(m_expected_record != HandshakeStage::client_change_cipher_spec) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    client_cipher_spec = true;
    m_expected_record = HandshakeStage::client_handshake_finished;
}

void TLS::client_handshake_finished12(const ustring& handshake_message) {
    if(m_expected_record != HandshakeStage::client_handshake_finished) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    handshake.client_handshake_finished12_record(handshake_message);
    m_expected_record = HandshakeStage::server_change_cipher_spec;
}

task<stream_result> TLS::server_change_cipher_spec() {
    assert(m_expected_record == HandshakeStage::server_change_cipher_spec or tls_protocol_version == TLS13);
    
    tls_record record { ChangeCipherSpec };
    record.write1(EnumChangeCipherSpec::change_cipher_spec);
    auto res = co_await write_record(record, project_options.handshake_timeout);
    if(tls_protocol_version == TLS13) {
        m_expected_record = HandshakeStage::server_encrypted_extensions;
    } else {
        m_expected_record = HandshakeStage::server_handshake_finished;
        server_cipher_spec = true;
    }
    co_return res;
}

task<stream_result> TLS::server_handshake_finished12() {
    assert(m_expected_record == HandshakeStage::server_handshake_finished);

    tls_record out(Handshake);
    out.write1(HandshakeType::finished);
    out.start_size_header(3);
    
    assert(handshake.handshake_hasher);
    auto handshake_hash = handshake.handshake_hasher->hash();
    assert(handshake_hash.size() == 32);
    
    ustring server_finished = prf(*handshake.hash_ctor, handshake.tls12_master_secret, "server finished", handshake_hash, 12);
    
    out.write(server_finished);
    out.end_size_header();
    
    m_expected_record = HandshakeStage::application_data;
    co_return co_await write_record(out, project_options.handshake_timeout);
}


task<void> TLS::client_alert(tls_record record, std::optional<milliseconds> timeout) {
    const auto& alert_message = record.m_contents;
    if(alert_message.size() != 2) {
        co_return; // do not send anything after receiving malformed alert
    }
    switch(alert_message[0]) {
        case static_cast<uint8_t>(AlertLevel::warning):
            switch(alert_message[1]) {
                case static_cast<uint8_t>(AlertDescription::close_notify):
                {
                    tls_record record{ Alert};
                    record.m_contents = { static_cast<uint8_t>(AlertLevel::warning), static_cast<uint8_t>(AlertDescription::close_notify) };
                    co_await write_record(record, timeout);
                }
                break;
                default:
                    co_return;
            }
            break;
        default:
            co_return;
    }
}

task<stream_result> TLS::client_heartbeat(tls_record client_record, std::optional<milliseconds> timeout) {
    auto [heartblead, heartbeat_record] = client_heartbeat_record(client_record, can_heartbeat);
    if(heartblead) {
        co_await m_client->write(to_unsigned("heartbleed?"), project_options.error_timeout);
        throw ssl_error("unexpected heartbeat response", AlertLevel::fatal, AlertDescription::access_denied);
    }
    co_return co_await write_record(heartbeat_record, timeout);
}


std::pair<bool, tls_record> TLS::client_heartbeat_record(tls_record record, bool can_heartbeat) {
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

    auto length_and_payload = heartbeat_message.substr(1, payload_length + 2);

    tls_record heartbeat_record( Heartbeat);
    heartbeat_record.m_contents = { 0x02 };
    heartbeat_record.m_contents.append( length_and_payload );
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

task<stream_result> TLS::server_key_update() {
    assert(m_expected_record == HandshakeStage::application_data);
    assert(tls_protocol_version == TLS13);
    auto keyupdate = server_key_update_record(KeyUpdateRequest::update_requested);
    auto res = co_await write_record(std::move(keyupdate), project_options.session_timeout);
    if(res != stream_result::ok) {
        co_return res;
    }
    auto& srv_key = handshake.tls13_key_schedule.client_application_traffic_secret;
    srv_key = hkdf_expand_label(*handshake.hash_ctor, srv_key, "traffic upd", std::string(""), handshake.hash_ctor->get_hash_size());
    auto* tls13_context = dynamic_cast<cipher_base_tls13*>(cipher_context.get());
    assert(tls13_context != nullptr);
    tls13_context->set_server_traffic_key(srv_key);
    co_return stream_result::ok;
}

task<stream_result> TLS::client_post_handshake(const ustring& message,  std::optional<milliseconds> timeout) {
    assert(m_expected_record == HandshakeStage::application_data);
    if(tls_protocol_version != TLS13) {
        co_await server_alert(AlertLevel::fatal, AlertDescription::unexpected_message);
        co_return stream_result::closed;
    }
    if(message.size() < 5) {
        co_await server_alert(AlertLevel::fatal, AlertDescription::decode_error);
        co_return stream_result::closed;
    }
    switch(static_cast<HandshakeType>(message[0])) {
        case HandshakeType::key_update:
        {
            auto key_update_message = der_span_read(message, 1, 3);
            if(key_update_message.size() != 1) {
                throw ssl_error("bad key update message", AlertLevel::fatal, AlertDescription::illegal_parameter);
            }
            switch(static_cast<KeyUpdateRequest>(key_update_message[0])) {
                case KeyUpdateRequest::update_not_requested:
                {
                    auto& cli_key = handshake.tls13_key_schedule.client_application_traffic_secret;
                    cli_key = hkdf_expand_label(*handshake.hash_ctor, cli_key, "traffic upd", std::string(""), handshake.hash_ctor->get_hash_size());
                    auto* tls13_context = dynamic_cast<cipher_base_tls13*>(cipher_context.get());
                    assert(tls13_context != nullptr);
                    tls13_context->set_client_traffic_key(cli_key);
                    break;
                }
                case KeyUpdateRequest::update_requested:
                {
                    tls_record keyupdate = server_key_update_record(KeyUpdateRequest::update_not_requested);
                    auto res = co_await write_record(std::move(keyupdate), timeout);
                    if(res != stream_result::ok) {
                        co_return res;
                    }
                    auto& cli_key = handshake.tls13_key_schedule.client_application_traffic_secret;
                    cli_key = hkdf_expand_label(*handshake.hash_ctor, cli_key, "traffic upd", std::string(""), handshake.hash_ctor->get_hash_size());
                    auto& srv_key = handshake.tls13_key_schedule.server_application_traffic_secret;
                    srv_key = hkdf_expand_label(*handshake.hash_ctor, srv_key, "traffic upd", std::string(""), handshake.hash_ctor->get_hash_size());
                    auto* tls13_context = dynamic_cast<cipher_base_tls13*>(cipher_context.get());
                    assert(tls13_context != nullptr);
                    tls13_context->set_server_traffic_key(srv_key);
                    tls13_context->set_client_traffic_key(cli_key);
                    break;
                }
                default:
                    throw ssl_error("bad key update message", AlertLevel::fatal, AlertDescription::illegal_parameter);
            }
            break;
        }
        default:
            break;
    }
    co_return stream_result::ok;
}

}// namespace fbw
