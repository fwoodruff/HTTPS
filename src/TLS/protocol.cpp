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
#include "../Runtime/executor.hpp"

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

task<stream_result> TLS::read_append(ustring& data, std::optional<milliseconds> timeout) {
    co_return co_await read_append_impl(data, timeout, false, false);
}

task<stream_result> TLS::read_append_early(ustring& data, std::optional<milliseconds> timeout) {
    co_return co_await read_append_impl(data, timeout, true, false);
}

task<stream_result> TLS::await_handshake_finished() {
    ustring dummy;
    co_return co_await read_append_impl(dummy, project_options.handshake_timeout, false, true);
    assert(dummy.empty());
}

std::pair<stream_result, bool> TLS::read_append_impl_sync(std::vector<packet_timed>& network_output, ustring& application_data, const ustring& bio_input, std::optional<milliseconds> app_timeout, bool return_early_data, bool return_client_finished) {
    std::optional<ssl_error> error_ssl {};
    try {
        if(!early_buffer.empty()) {
            application_data.append(std::move(early_buffer));
            early_buffer.clear();
        }
        if(m_expected_record == HandshakeStage::application_data or m_expected_record == HandshakeStage::client_early_data) {
            flush_update_sync(network_output);
        }
        bio_read(bio_input);
        while(!inbox.empty()) {
            auto record = std::move(inbox.front());
            inbox.pop();
            record = decrypt_record(record);
            switch (static_cast<ContentType>(record.get_type()) ) {
                case Handshake:
                {
                    bool handshake_done = client_handshake_record_sync(network_output, std::move(record));
                    return {stream_result::ok, handshake_done};
                }
                [[unlikely]] case ChangeCipherSpec:
                    client_change_cipher_spec(std::move(record));
                    break;
                case Application:
                    if(m_expected_record == HandshakeStage::application_data) {
                        application_data.append(std::move(record.m_contents));
                        return {stream_result::ok, true};
                    }
                    if(m_expected_record == HandshakeStage::client_early_data) {
                        if(!handshake.zero_rtt) {
                            break;
                        }
                        early_data_received += record.m_contents.size();
                        if(early_data_received > MAX_EARLY_DATA) {
                            throw ssl_error("too much early data", AlertLevel::fatal, AlertDescription::unexpected_message);
                        }
                        if(return_client_finished) {
                            early_buffer.append(std::move(record.m_contents));
                        } else {
                            application_data.append(std::move(record.m_contents));
                        }
                        if(return_early_data) {
                            return {stream_result::ok, false};
                        }
                        break;
                    }
                    throw ssl_error("handshake not done yet", AlertLevel::fatal, AlertDescription::insufficient_security);
                case Alert:
                    client_alert_sync(network_output, std::move(record), project_options.error_timeout);
                    return {stream_result::closed, false};
                case Heartbeat:
                    client_heartbeat(network_output, std::move(record), project_options.session_timeout);
                    return {stream_result::ok, false};
                [[unlikely]] case Invalid:
                    throw ssl_error("invalid record type", AlertLevel::fatal, AlertDescription::unexpected_message);
                [[unlikely]] default:
                    throw ssl_error("nonexistent record type", AlertLevel::fatal, AlertDescription::decode_error);
            }
        }

        
    } catch(const ssl_error& e) {
        server_alert_sync(network_output, error_ssl->m_l, error_ssl->m_d);
    } catch(const std::exception& e) {
        server_alert_sync(network_output, AlertLevel::fatal, AlertDescription::decode_error);
    }
    return {stream_result::ok, false};
}

// application code calls this to decrypt and read data
task<stream_result> TLS::read_append_impl(ustring& app_data, std::optional<milliseconds> app_timeout, bool return_early_data, bool return_client_finished) {
    size_t initial_size = app_data.size();
    for(;;) {
        if(return_client_finished and m_expected_record == HandshakeStage::application_data) {
            co_return stream_result::ok;
        }
        ustring input_data;
        std::vector<packet_timed> output;
        auto res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
        auto [result, handshake_done] = read_append_impl_sync(output, app_data, input_data, app_timeout, return_early_data, return_client_finished);
        if(result != stream_result::ok) {
            co_return result;
        }
        auto res2 = co_await bio_write_all(output);
        if(res2 != stream_result::ok) {
            co_return res2;
        }
        if(handshake_done and return_client_finished) {
            co_return stream_result::ok;
        }
        if(initial_size != app_data.size()) {
            co_return stream_result::ok;
        }
    }
}

task<std::string> TLS::perform_hello() {
    for(;;) {
        ustring data;
        std::vector<packet_timed> output;
        auto res = co_await m_client->read_append(data, project_options.handshake_timeout);
        if(res != stream_result::ok) {
            co_return "";
        }
        auto opt_alpn = perform_hello_sync(output, data);
        
        auto res1 = co_await bio_write_all(output);
        if(res1 != stream_result::ok) {
            co_return "";
        }
        if(opt_alpn) {
            co_return *opt_alpn;
        }
    }
}

std::optional<std::string> TLS::perform_hello_sync(std::vector<packet_timed>& output, const ustring& bio_input) {
    std::optional<ssl_error> error_ssl {};
    try {
        handshake.p_cipher_context = &cipher_context;
        handshake.p_tls_version = &tls_protocol_version;
        bio_read(bio_input);
        while(!inbox.empty()) {
            auto record = std::move(inbox.front());
            inbox.pop();
            switch ( static_cast<ContentType>(record.get_type()) ) {
                case Handshake:
                    client_handshake_record_sync(output, std::move(record));
                    if(m_expected_record != HandshakeStage::client_hello) {
                        return handshake.alpn;
                    }
                    break;
                case Alert:
                    client_alert_sync(output, std::move(record), project_options.handshake_timeout);
                    return "";
                case Invalid: [[fallthrough]];
                case Heartbeat: [[fallthrough]];
                case ChangeCipherSpec: [[fallthrough]];
                case Application: 
                    throw ssl_error("invalid record type", AlertLevel::fatal, AlertDescription::unexpected_message);
                [[unlikely]] default:
                    throw ssl_error("nonexistent record type", AlertLevel::fatal, AlertDescription::decode_error);
            }
        }
    } catch(const ssl_error& e) {
        server_alert_sync(output, error_ssl->m_l, error_ssl->m_d);
    } catch(const std::exception& e) {
        server_alert_sync(output, AlertLevel::fatal, AlertDescription::decode_error);
    }
    return "";
}

void TLS::flush_update_sync(std::vector<packet_timed>& output) {
    flush_sync(output);
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

void TLS::write_sync(std::vector<packet_timed>& output, ustring data, std::optional<milliseconds> timeout) {
    assert(m_expected_record == HandshakeStage::application_data or m_expected_record == HandshakeStage::client_early_data);
    std::optional<ssl_error> error_ssl{};
    try {
        size_t idx = 0;
        while(idx < data.size()) {
            if(encrypt_send.empty()) {
                encrypt_send.emplace_back(Application);
            }
            auto& active_record = encrypt_send.back();
            size_t write_size = std::min(WRITE_RECORD_SIZE - active_record.m_contents.size(), data.size() - idx);
            encrypt_send.back().m_contents.append( data.begin() + idx, data.begin() + idx + write_size);
            idx += write_size;
            if (active_record.m_contents.size() == WRITE_RECORD_SIZE) {
                encrypt_send.emplace_back(Application);
                if(encrypt_send.size() > 2) {
                    write_record_sync(output, std::move(encrypt_send.front()), timeout);
                    encrypt_send.pop_front();
                }
            }
        }
        return;
    } catch(const ssl_error& e) {
        error_ssl = e;
        server_alert_sync(output, error_ssl->m_l, error_ssl->m_d);
    } catch(const std::exception& e) {
        server_alert_sync(output, AlertLevel::fatal, AlertDescription::decode_error);
    }
}

// application code calls this to send data to the client
task<stream_result> TLS::write(ustring data, std::optional<milliseconds> timeout) {
    std::vector<packet_timed> output;
    write_sync(output, data, timeout); // todo : bring these back
    co_return co_await bio_write_all(output);
}

void TLS::flush_sync(std::vector<packet_timed>& output) {
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
        write_record_sync(output, std::move(record), project_options.session_timeout);
        encrypt_send.pop_front();
    }
}

task<stream_result> TLS::bio_write_all(const std::vector<packet_timed>& packets) const{
    for(auto& packet : packets) {
        stream_result res = co_await m_client->write(packet.data, packet.timeout);
        if(res != stream_result::ok) {
            co_return res;
        }
    }
    co_return stream_result::ok;
}

// application data is sent on a buffered stream so the pattern of record sizes reveals much less
task<stream_result> TLS::flush() {
    std::vector<packet_timed> output;
    flush_sync(output);
    co_return co_await bio_write_all(output);
}

// applications call this when graceful not abrupt closing of a connection is desired
task<void> TLS::close_notify() {
    // todo: this is a mess
    std::vector<packet_timed> output;
    flush_sync(output);
    server_alert_sync(output, AlertLevel::warning, AlertDescription::close_notify);
    auto res = co_await bio_write_all(output);
    if(res != stream_result::ok) {
        co_return;
    }

    for(;;) {
        ustring input_data;
        auto res = co_await m_client->read_append(input_data, project_options.handshake_timeout);
        if(res != stream_result::ok) {
            co_return;
        }
        bio_read(input_data);
        if(inbox.empty()) {
            continue;
        }
        while(!inbox.empty()) {
            auto record = std::move(inbox.front());
            inbox.pop();
            if(static_cast<ContentType>(record.get_type()) != Alert) {
                server_alert_sync(output, AlertLevel::fatal, AlertDescription::unexpected_message);
                co_await bio_write_all(output);
                co_return;
            }
            co_await m_client->close_notify();
            co_return;
        }
        
    }    
}

// When the server encounters an error, it sends that error here
void TLS::server_alert_sync(std::vector<packet_timed>& output, AlertLevel level, AlertDescription description) {
    auto r = tls_record(Alert);
    r.write1(level);
    r.write1(description);
    write_record_sync(output, std::move(r), project_options.error_timeout);
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
        assert(cipher_context);
        record = cipher_context->decrypt(std::move(record));
    }
    return record;
}

void TLS::server_hello_request(std::vector<packet_timed>& output) {
    if(m_expected_record == HandshakeStage::client_hello) { // no handshake renegotiations after renegotiation indicator sent
        tls_record hello_request{Handshake};
        hello_request.write1(HandshakeType::hello_request);
        hello_request.start_size_header(3);
        hello_request.end_size_header();
        write_record_sync(output, hello_request, project_options.handshake_timeout);
    }
    return; // throw?
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
        assert(m_client);
        stream_result connection_alive = co_await m_client->read_append(m_buffer, timeout);
        if(connection_alive != stream_result::ok) {
            co_return { {}, connection_alive };
        }
    }
}

void TLS::bio_read(const ustring& bio_input) {
    m_buffer.append(bio_input);
    for(;;) {
        auto record = try_extract_record(m_buffer);
        if(record == std::nullopt) {
            break;
        }
        if (record->get_major_version() != 3) {
            throw ssl_error("unsupported version", AlertLevel::fatal, AlertDescription::protocol_version);
        }
        inbox.push(*record);
    }
    if (m_buffer.size() > TLS_RECORD_SIZE + TLS_HEADER_SIZE + TLS_EXPANSION_MAX) [[unlikely]] {
        throw ssl_error("oversized record", AlertLevel::fatal, AlertDescription::record_overflow);
    }
}

void TLS::write_record_sync(std::vector<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout) {
    if(server_cipher_spec && record.get_type() != ChangeCipherSpec) {
        assert(cipher_context);
        record = cipher_context->encrypt(record);
    }
    output.push_back({record.serialise(), timeout});
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

bool TLS::client_handshake_record_sync(std::vector<packet_timed>& output, tls_record record) {
    auto messages = extract_handshake_messages(std::move(record), m_handshake_fragment); // consider extracting one by one
    bool handshake_done = false;
    for(const auto& message : messages) {
        bool done = client_handshake_message_sync(output, message);
        if(done) {
            handshake_done = true;
        }
    }
    return handshake_done;
}

bool TLS::client_handshake_message_sync(std::vector<packet_timed>& output, const ustring& handshake_message) {
    switch (static_cast<HandshakeType>(handshake_message.at(0))) {
        [[unlikely]] case HandshakeType::hello_request:
            throw ssl_error("client should not send hello request", AlertLevel::fatal, AlertDescription::unexpected_message);
        case HandshakeType::client_hello:
        {
            client_hello(std::move(handshake_message));
            server_response_to_hello_sync(output);
            return false;
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
            return true;
        case HandshakeType::key_update:
        {
            auto update_request = client_key_update_received(std::move(handshake_message));
            if(update_request == KeyUpdateRequest::update_requested) {
                server_key_update_respond(output);
            }
            return true;
        }
        [[unlikely]] default:
            throw ssl_error("unsupported handshake record type", AlertLevel::fatal, AlertDescription::decode_error);
    }
    return false;
}

task<void> make_write_task(task<stream_result> write_task, std::shared_ptr<TLS> this_ptr) {
    std::optional<ssl_error> error_ssl;
    std::vector<fbw::packet_timed> output;
    co_await this_ptr->m_async_mut.lock();
    guard {&this_ptr->m_async_mut};
    try {
        if(this_ptr->connection_done) {
            co_return;
        }
        co_await write_task;
        co_return;
    } catch(const ssl_error& e) {
        error_ssl = e;
        goto END; // cannot co_await inside a catch block
    } catch(const std::exception& e) {
        goto END2;
    }
    END:
    this_ptr->server_alert_sync(output, error_ssl->m_l, error_ssl->m_d);
    this_ptr->connection_done = true;
    co_await this_ptr->bio_write_all(output);
    co_return;
    END2:
    this_ptr->server_alert_sync(output, AlertLevel::fatal, AlertDescription::decode_error);
    this_ptr->connection_done = true;
    co_await this_ptr->bio_write_all(output);
    co_return;
}

void TLS::schedule(task<stream_result> write_task) {
    sync_spawn(make_write_task(std::move(write_task), shared_from_this()));
}

void TLS::client_hello(const ustring& handshake_message) {
    if(m_expected_record != HandshakeStage::client_hello) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    handshake.client_hello_record(handshake_message);
    m_expected_record = HandshakeStage::server_hello;
}

void TLS::server_response_to_hello_sync(std::vector<packet_timed>& output) {
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
            m_expected_record = HandshakeStage::server_handshake_finished;
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

KeyUpdateRequest TLS::client_key_update_received(const ustring& handshake_message) {
    if(tls_protocol_version != TLS13) {
        throw ssl_error("key updates supported for TLS 1.3 only", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    if(m_expected_record != HandshakeStage::application_data) {
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

void TLS::server_key_update_respond(std::vector<packet_timed>& output) {
    auto& srv_key = handshake.tls13_key_schedule.server_application_traffic_secret;
    srv_key = hkdf_expand_label(*handshake.hash_ctor, srv_key, "traffic upd", std::string(""), handshake.hash_ctor->get_hash_size());
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_server_traffic_key(srv_key);
    tls_record keyupdate = server_key_update_record(KeyUpdateRequest::update_not_requested);
    write_record_sync(output, std::move(keyupdate), project_options.handshake_timeout);
}

void TLS::server_hello_sync(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::server_hello);
    auto hello_record = handshake.server_hello_record();
    write_record_sync(output, hello_record, project_options.handshake_timeout);

    if(tls_protocol_version == TLS13) {
        if(handshake.server_hello_type == ServerHelloType::hello_retry) {
            m_expected_record = HandshakeStage::client_hello;
        } else {
            auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
            server_cipher_spec = true;
            client_cipher_spec = true;
            tls13_context.set_server_traffic_key(handshake.tls13_key_schedule.server_handshake_traffic_secret);
            if(handshake.client_hello.parsed_extensions.contains(ExtensionType::early_data)) {
                tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_early_traffic_secret);
            } else {
                tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_handshake_traffic_secret);
            }
            m_expected_record = HandshakeStage::server_encrypted_extensions;
        }
    } else {
        m_expected_record = HandshakeStage::server_certificate;
    }
}

void TLS::server_encrypted_extensions(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::server_encrypted_extensions);
    tls_record out = handshake.server_encrypted_extensions_record();
    m_expected_record = HandshakeStage::server_certificate;
    write_record_sync(output, out, project_options.handshake_timeout);
}

void TLS::server_certificate(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::server_certificate);
    tls_record certificate_record = handshake.server_certificate_record();
    if(tls_protocol_version == TLS13) {
        m_expected_record = HandshakeStage::server_certificate_verify;
    } else {
        m_expected_record = HandshakeStage::server_key_exchange;
    }
    write_record_sync(output, certificate_record, project_options.handshake_timeout);
}

void TLS::server_certificate_verify(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::server_certificate_verify);
    auto record = handshake.server_certificate_verify_record();
    m_expected_record = HandshakeStage::server_handshake_finished;
    write_record_sync(output, record, project_options.handshake_timeout);
}

void TLS::server_handshake_finished13(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::server_handshake_finished);
    auto record = handshake.server_handshake_finished13_record();
    if(handshake.client_hello.parsed_extensions.contains(ExtensionType::early_data)) {
        m_expected_record = HandshakeStage::client_early_data;
    } else {
        m_expected_record = HandshakeStage::client_handshake_finished; // mTLS would change this
    }
    write_record_sync(output, record, project_options.handshake_timeout);
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_server_traffic_key(handshake.tls13_key_schedule.server_application_traffic_secret);
}

void TLS::client_handshake_finished13(const ustring& handshake_message) {
    if(m_expected_record != HandshakeStage::client_handshake_finished) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    assert(tls_protocol_version == TLS13);
    handshake.client_handshake_finished13_record(handshake_message);
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_application_traffic_secret);
    m_expected_record = HandshakeStage::application_data;
}

static std::atomic<uint64_t> global_nonce = 1;

void TLS::server_session_ticket_sync(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::application_data);
    const auto nonce = global_nonce.fetch_add(1, std::memory_order_relaxed);
    ustring nonce_bytes(8, 0);
    checked_bigend_write(nonce, nonce_bytes, 0, 8);
    assert(handshake.hash_ctor != nullptr);
    const auto resumption_ticket_psk = hkdf_expand_label(*handshake.hash_ctor, handshake.tls13_key_schedule.resumption_master_secret, "resumption", nonce_bytes, handshake.hash_ctor->get_hash_size());

    session_ticket_nonces[nonce % SESSION_HASHSET_SIZE].store(nonce, std::memory_order::relaxed);

    const bool offer_0rtt = handshake.client_hello.parsed_extensions.contains(ExtensionType::early_data);

    TLS13SessionTicket ticket;
    ticket.version = 1;
    ticket.ticket_lifetime = 7200; // seconds
    ticket.issued_at = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();
    ticket.ticket_age_add = randomgen.randgen64();
    ticket.cipher_suite = handshake.cipher;
    ticket.early_data_allowed = offer_0rtt;

    ticket.nonce = nonce;
    ticket.resumption_secret = resumption_ticket_psk;

    const auto record = TLS13SessionTicket::server_session_ticket_record(ticket, session_ticket_master_secret, nonce);

    if(record) {
        write_record_sync(output, *record, project_options.handshake_timeout);
    }
}

void TLS::server_key_exchange(std::vector<packet_timed>& output) {
    tls_record record = handshake.server_key_exchange_record();
    m_expected_record = HandshakeStage::server_hello_done;
    write_record_sync(output, record, project_options.handshake_timeout);
}

void TLS::server_hello_done(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::server_hello_done);
    auto record = handshake.server_hello_done_record();
    
    m_expected_record = HandshakeStage::client_key_exchange;
    write_record_sync(output, record, project_options.handshake_timeout);
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

void TLS::client_end_of_early_data(ustring handshake_message) {
    if(m_expected_record != HandshakeStage::client_early_data) [[unlikely]] {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    handshake.client_end_of_early_data_record(handshake_message);
    auto& tls13_context = dynamic_cast<cipher_base_tls13&>(*cipher_context);
    tls13_context.set_client_traffic_key(handshake.tls13_key_schedule.client_handshake_traffic_secret);
    m_expected_record = HandshakeStage::client_handshake_finished;
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

void TLS::server_change_cipher_spec(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::server_change_cipher_spec or tls_protocol_version == TLS13);
    
    tls_record record { ChangeCipherSpec };
    record.write1(EnumChangeCipherSpec::change_cipher_spec);
    write_record_sync(output, record, project_options.handshake_timeout);
    if(tls_protocol_version == TLS13) {
        m_expected_record = HandshakeStage::server_encrypted_extensions;
    } else {
        m_expected_record = HandshakeStage::server_handshake_finished;
        server_cipher_spec = true;
    }
}

void TLS::server_handshake_finished12(std::vector<packet_timed>& output) {
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
    write_record_sync(output, out, project_options.handshake_timeout);
}

void TLS::client_alert_sync(std::vector<packet_timed>& output, tls_record record, std::optional<milliseconds> timeout) {
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

void TLS::client_heartbeat(std::vector<packet_timed>& output, tls_record client_record, std::optional<milliseconds> timeout) {
    auto [heartblead, heartbeat_record] = client_heartbeat_record(client_record, can_heartbeat);
    if(heartblead) {
        assert(m_client);
        // co_await m_client->write(to_unsigned("heartbleed?"), project_options.error_timeout);
        throw ssl_error("unexpected heartbeat response", AlertLevel::fatal, AlertDescription::access_denied);
    }
    write_record_sync(output, heartbeat_record, timeout);
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

void TLS::server_key_update_sync(std::vector<packet_timed>& output) {
    assert(m_expected_record == HandshakeStage::application_data);
    assert(tls_protocol_version == TLS13);
    auto keyupdate = server_key_update_record(KeyUpdateRequest::update_requested);
    auto& srv_key = handshake.tls13_key_schedule.client_application_traffic_secret;
    srv_key = hkdf_expand_label(*handshake.hash_ctor, srv_key, "traffic upd", std::string(""), handshake.hash_ctor->get_hash_size());
    auto* tls13_context = dynamic_cast<cipher_base_tls13*>(cipher_context.get());
    assert(tls13_context != nullptr);
    tls13_context->set_server_traffic_key(srv_key);
    write_record_sync(output, std::move(keyupdate), project_options.session_timeout);
}

}// namespace fbw
