//
//  TLS.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "TLS.hpp"

#include "Cryptography/assymetric/x25519.hpp"
#include "Cryptography/one_way/secure_hash.hpp"
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

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>
#include <utility>

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

TLS::TLS(std::unique_ptr<stream> output_stream) : m_client(std::move(output_stream) ) {}

task<void> TLS::server_alert(AlertLevel level, AlertDescription description) {
    auto r = tls_record(ContentType::Alert);
    r.write1(level);
    r.write1(description);
    co_await write_record(std::move(r), option_singleton().error_timeout);
}

task<stream_result> TLS::read_append(ustring& data, std::optional<milliseconds> timeout) {
    std::optional<ssl_error> error_ssl {};
    try {
        assert(m_expected_record == HandshakeStage::application_data);

        auto res = co_await flush();
        if(res != stream_result::ok) {
            co_return res;
        }
        auto [record, result] = co_await try_read_record(timeout);
        if(result != stream_result::ok) {
            co_return result;
        }
        record = decrypt_record(record);
        switch (static_cast<ContentType>(record.get_type()) ) {
            case ContentType::Handshake:
            case ContentType::ChangeCipherSpec:
                co_await server_alert(AlertLevel::fatal, AlertDescription::unexpected_message);
                co_return stream_result::closed;
            case ContentType::Application:
                data.append(std::move(record.m_contents));
                co_return stream_result::ok;
            case ContentType::Alert:
                co_await client_alert(std::move(record), timeout);
                co_return stream_result::closed;
            case ContentType::Heartbeat:
                co_await client_heartbeat(std::move(record), timeout);
                co_return stream_result::ok;
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

task<stream_result> TLS::write(ustring data, std::optional<milliseconds> timeout) {
    std::optional<ssl_error> error_ssl{};
    try {
        size_t idx = 0;
        while(idx < data.size()) {
            size_t write_size = std::min(WRITE_RECORD_SIZE - m_write_buffer_idx, data.size() - idx);
            std::copy_n(data.data() + idx, write_size, m_write_buffer.data() + m_write_buffer_idx);
            m_write_buffer_idx += write_size;
            idx += write_size;

            if (m_write_buffer_idx == WRITE_RECORD_SIZE) {
                tls_record rec(ContentType::Application);
                rec.m_contents = ustring(m_write_buffer.data(), m_write_buffer.data() + WRITE_RECORD_SIZE);
                auto res = co_await write_record(std::move(rec), timeout);
                if (res != stream_result::ok) {
                    co_return res;
                }
                m_write_buffer_idx = 0;
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

task<stream_result> TLS::flush() {
    if (m_write_buffer_idx > 0) {
        tls_record rec(ContentType::Application);
        rec.m_contents = ustring(m_write_buffer.data(), m_write_buffer.data() + m_write_buffer_idx);
        auto res = co_await write_record(std::move(rec), option_singleton().session_timeout);
        m_write_buffer_idx = 0;
       co_return res;
    }
    co_return stream_result::ok;
}

task<void> TLS::close_notify() {
    try {
        co_await flush();
        co_await server_alert(AlertLevel::warning, AlertDescription::close_notify);
        auto [record, result] = co_await try_read_record(option_singleton().error_timeout);
        if(result != stream_result::ok) {
            co_return;
        }
        if(static_cast<ContentType>(record.get_type()) != ContentType::Alert) {
            co_await server_alert(AlertLevel::fatal, AlertDescription::unexpected_message);
            co_return;
        }
        using namespace std::literals::chrono_literals;
        co_await m_client->close_notify();
    } catch(const std::exception& e) { }
}

task<stream_result> TLS::server_hello_request() {
    if(m_expected_record == HandshakeStage::client_hello) { // no handshake renegotiations after renegotiation indicator sent
        tls_record hello_request{ContentType::Handshake};
        hello_request.write1(HandshakeType::hello_request);
        hello_request.push_der(3);
        hello_request.pop_der();
        co_return co_await write_record(hello_request, option_singleton().handshake_timeout);
    }
    co_return stream_result::closed;
}

tls_record TLS::decrypt_record(tls_record record) {
    if(m_expected_record > HandshakeStage::client_change_cipher_spec) {
        if(use_tls13) {
            auto type = record.m_contents.back();
            record.m_contents.pop_back();
            record = cipher_context->decrypt(std::move(record));
            record.m_type = type;
        } else {
            record = cipher_context->decrypt(std::move(record));
        }
    }
    return record;
}

task<std::string> TLS::perform_handshake() {
    std::optional<ssl_error> error_ssl {};
    try {
        key_schedule handshake;
        handshake.p_cipher_context = &cipher_context;
        handshake.p_use_tls13 = &use_tls13;
        bool hello_request_sent = false;
        for(;;) {
            auto [record, result] = co_await try_read_record(option_singleton().handshake_timeout);
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
                case ContentType::Handshake:
                    if(co_await client_handshake_record(handshake, std::move(record)) != stream_result::ok) {
                        co_return "";
                    }
                    if(m_expected_record == HandshakeStage::application_data) {
                        co_return handshake.alpn;
                    }
                    break;
                case ContentType::ChangeCipherSpec:
                    client_change_cipher_spec(std::move(record));
                    break;
                case ContentType::Application:
                    throw ssl_error("handshake not done yet", AlertLevel::fatal, AlertDescription::unexpected_message);
                case ContentType::Alert:
                    co_await client_alert(std::move(record), option_singleton().handshake_timeout);
                    co_return "";
                case ContentType::Heartbeat:
                    auto res = co_await client_heartbeat(std::move(record), option_singleton().handshake_timeout);
                    if(res != stream_result::ok) {
                        co_return "";
                    }
                    break;
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

task<std::pair<tls_record, stream_result>> TLS::try_read_record(std::optional<milliseconds> timeout) {
    for(;;) {
        auto record = try_extract_record(m_buffer);
        if(record) {
            if (record->get_major_version() != 3) {
                throw ssl_error("unsupported version", AlertLevel::fatal, AlertDescription::protocol_version);
            }
            co_return { *record, stream_result::ok };
        }
        if (m_buffer.size() > TLS_RECORD_SIZE + TLS_HEADER_SIZE + TLS_EXPANSION_MAX) {
            throw ssl_error("oversized record", AlertLevel::fatal, AlertDescription::record_overflow);
        }
        stream_result connection_alive = co_await m_client->read_append(m_buffer, timeout);
        if(connection_alive != stream_result::ok) {
            co_return { tls_record{}, connection_alive };
        }
    }
}

task<stream_result> TLS::write_record(tls_record record, std::optional<milliseconds> timeout) {
    if(m_expected_record > HandshakeStage::server_change_cipher_spec) {
        if(use_tls13) {
            auto type = record.m_type;
            record.m_type = static_cast<uint8_t>(ContentType::Application);
            record = cipher_context->encrypt(record);
            record.m_contents.push_back(type);
        } else {
            record = cipher_context->encrypt(record);
        }
    }
    co_return co_await m_client->write(record.serialise(), timeout);
}

task<stream_result> TLS::client_handshake_record(key_schedule& handshake, tls_record record) {
    ustring handshake_record = record.m_contents;
    switch (handshake_record.at(0)) {
        case static_cast<uint8_t>(HandshakeType::hello_request):
            throw ssl_error("client should not send hello request", AlertLevel::fatal, AlertDescription::unexpected_message);
        case static_cast<uint8_t>(HandshakeType::client_hello):
            client_hello(handshake, std::move(record));
            if(auto result = co_await server_hello(handshake); result != stream_result::ok) {
                co_return result;
            }
            if(use_tls13) {
                if(auto result = co_await server_change_cipher_spec(); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_encrypted_extensions(); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_certificate(handshake); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_certificate_verify(handshake); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_handshake_finished13(handshake); result != stream_result::ok) {
                    co_return result;
                }
            } else {
                if(auto result = co_await server_certificate(handshake); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_key_exchange(handshake); result != stream_result::ok) {
                    co_return result;
                }
                if(auto result = co_await server_hello_done(*handshake.handshake_hasher); result != stream_result::ok) {
                    co_return result;
                }
                break;
            }
        case static_cast<uint8_t>(HandshakeType::client_key_exchange):
            client_key_exchange(handshake, std::move(record));
            break;
        case static_cast<uint8_t>(HandshakeType::finished):
            if(use_tls13) {
                client_handshake_finished13(handshake, std::move(record));
            } else {
                client_handshake_finished12(handshake, std::move(record));
                if(auto result = co_await server_change_cipher_spec(); result != stream_result::ok) {
                    co_return std::move(result);
                }
                if(auto result = co_await server_handshake_finished12(handshake); result != stream_result::ok) {
                    co_return std::move(result);
                }
            }
            
            co_return stream_result::ok;
        default:
            throw ssl_error("unsupported handshake record type", AlertLevel::fatal, AlertDescription::decode_error);
    }
    co_return stream_result::ok;
}

void TLS::client_hello(key_schedule& handshake, tls_record record) {
    if(m_expected_record != HandshakeStage::client_hello) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    handshake.client_hello_record(record, can_heartbeat);
    m_expected_record = HandshakeStage::server_hello;
}

task<stream_result> TLS::server_hello(key_schedule& handshake) {
    assert(m_expected_record == HandshakeStage::server_hello);

    // server random
    handshake.m_server_random.resize(32);
    randomgen.randgen(handshake.m_server_random);
    auto hello_record = handshake.server_hello_record(use_tls13, client_session_id, can_heartbeat);
    if(use_tls13) {
        randomgen.randgen(handshake.server_private_key_ephem);
    }
    assert(hello_record.m_contents.size() >= 4);
    assert(handshake.handshake_hasher != nullptr);
    handshake.handshake_hasher->update(hello_record.m_contents);
    
    auto result = co_await write_record(hello_record, option_singleton().handshake_timeout);
    m_expected_record = HandshakeStage::server_certificate;
    auto [handshake_secret, handshake_context] = handshake.tls13_key_calc();
    cipher_context->set_key_material_13_handshake(handshake_secret, handshake_context);
    co_return std::move(result);
}

task<stream_result> TLS::server_certificate(key_schedule& handshake) {
    assert(m_expected_record == HandshakeStage::server_certificate);
    tls_record certificate_record = handshake.server_certificate_record(use_tls13);
    handshake.handshake_hasher->update(certificate_record.m_contents);
    m_expected_record = HandshakeStage::server_key_exchange;
    co_return co_await write_record(certificate_record, option_singleton().handshake_timeout);
}

task<stream_result> TLS::server_certificate_verify(key_schedule& handshake) {
    auto record = handshake.server_certificate_verify_record();
    co_return co_await write_record(record, option_singleton().handshake_timeout);
}

task<stream_result> TLS::server_key_exchange(key_schedule& handshake) {
    randomgen.randgen(handshake.server_private_key_ephem);
    std::array<uint8_t, 32> pubkey_ephem = curve25519::base_multiply(handshake.server_private_key_ephem);
    tls_record record = handshake.server_key_exchange_record(pubkey_ephem);
    handshake.handshake_hasher->update(record.m_contents);
    m_expected_record = HandshakeStage::server_hello_done;
    co_return co_await write_record(record, option_singleton().handshake_timeout);
}

task<stream_result> TLS::server_hello_done(hash_base& handshake_hasher) {
    assert(m_expected_record == HandshakeStage::server_hello_done);
    auto record = key_schedule::server_hello_done_record();
    handshake_hasher.update(record.m_contents);
    m_expected_record = HandshakeStage::client_key_exchange;
    co_return co_await write_record(record, option_singleton().handshake_timeout);
}

void TLS::client_key_exchange(key_schedule& handshake, tls_record record) {
    if(m_expected_record != HandshakeStage::client_key_exchange) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    auto key_material = handshake.client_key_exchange_receipt(record);
    cipher_context->set_key_material_12(key_material);
    handshake.handshake_hasher->update(record.m_contents);
    m_expected_record = HandshakeStage::client_change_cipher_spec;
}

void TLS::client_change_cipher_spec(tls_record record) {
    auto change_message = record.m_contents;
    if(m_expected_record != HandshakeStage::client_change_cipher_spec) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    if(change_message.size() != 1 and change_message.at(0) != static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)) {
        throw ssl_error("bad cipher spec", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    m_expected_record = HandshakeStage::client_handshake_finished;
}

void TLS::client_handshake_finished13(key_schedule& handshake, tls_record record) {
    if(m_expected_record != HandshakeStage::client_handshake_finished and m_expected_record != HandshakeStage::client_change_cipher_spec) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    auto finished_hash = handshake.handshake_hasher->hash();

    // todo: scope
    auto client_application_traffic_secret = hkdf_expand_label(*handshake.hash_ctor, handshake.master_secret, "c ap traffic", handshake.server_handshake_hash, handshake.hash_ctor->get_hash_size());
    auto finished_key = hkdf_expand_label(*handshake.hash_ctor, client_application_traffic_secret, "finished", ustring{}, handshake.hash_ctor->get_hash_size());
    resumption_master_secret13 = hkdf_expand_label(*handshake.hash_ctor, handshake.master_secret, "res master", finished_hash, handshake.hash_ctor->get_hash_size());

    auto verify_data = do_hmac(*handshake.hash_ctor, finished_key, finished_hash);

    if(verify_data != record.m_contents.substr(4)){
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    m_expected_record = HandshakeStage::application_data;
}

void TLS::client_handshake_finished12(key_schedule& handshake, tls_record record) {
    if(m_expected_record != HandshakeStage::client_handshake_finished) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    static_cast<void>(record.m_contents.at(0));
    if(record.m_contents[0] != static_cast<uint8_t>(HandshakeType::finished)) {
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    
    const size_t len = try_bigend_read(record.m_contents, 1, 3);
    if(len != 12) {
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    auto finish = record.m_contents.substr(4);
    auto handshake_hash = handshake.handshake_hasher->hash();
    ustring expected_finished = prf(*handshake.hash_ctor, handshake.master_secret, "client finished", handshake_hash, 12);

    if(expected_finished != finish) {
        throw ssl_error("handshake verification failed", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    handshake.handshake_hasher->update(record.m_contents);
    m_expected_record = HandshakeStage::server_change_cipher_spec;
}

task<stream_result> TLS::server_change_cipher_spec() {
    assert(m_expected_record == HandshakeStage::server_change_cipher_spec);
    tls_record record { ContentType::ChangeCipherSpec };
    record.write1(ChangeCipherSpec::change_cipher_spec);
    auto res = co_await write_record(record, option_singleton().handshake_timeout);
    m_expected_record = HandshakeStage::server_handshake_finished;
    co_return res;
}

task<stream_result> TLS::server_handshake_finished12(const key_schedule& handshake) {
    assert(m_expected_record == HandshakeStage::server_handshake_finished);
    tls_record out(ContentType::Handshake);
    out.write1(HandshakeType::finished);
    out.push_der(3);
    
    assert(handshake.handshake_hasher);
    auto handshake_hash = handshake.handshake_hasher->hash();
    assert(handshake_hash.size() == 32);
    
    ustring server_finished = prf(*handshake.hash_ctor, handshake.master_secret, "server finished", handshake_hash, 12);
    
    out.write(server_finished);
    out.pop_der();
    if(m_expected_record <= HandshakeStage::server_change_cipher_spec) {
        throw ssl_error("Unwilling to respond on unencrypted channel", AlertLevel::fatal, AlertDescription::insufficient_security);
    }
    m_expected_record = HandshakeStage::application_data;
    co_return co_await write_record(out, option_singleton().handshake_timeout);
}

task<stream_result> TLS::server_encrypted_extensions() {
    tls_record out = key_schedule::server_encrypted_extensions_record();
    co_return co_await write_record(out, option_singleton().handshake_timeout);
}

task<stream_result> TLS::server_handshake_finished13(key_schedule& handshake) {
    m_expected_record = HandshakeStage::client_change_cipher_spec;

    if(m_expected_record <= HandshakeStage::server_change_cipher_spec) {
        throw ssl_error("Unwilling to respond on unencrypted channel", AlertLevel::fatal, AlertDescription::insufficient_security);
    }
    handshake.server_handshake_hash = handshake.handshake_hasher->hash();
    exporter_master_secret13 = hkdf_expand_label(*handshake.hash_ctor, ustring{}, "exp master", handshake.server_handshake_hash, 32); // handshake.server_handshake_hash
    co_return stream_result::ok;
}

task<void> TLS::client_alert(tls_record record, std::optional<milliseconds> timeout) {
    auto alert_message = record.m_contents;
    if(alert_message.size() != 2) {
        co_return; // do not send anything after receiving malformed alert
    }
    switch(alert_message[0]) {
        case static_cast<uint8_t>(AlertLevel::warning):
            switch(alert_message[1]) {
                case static_cast<uint8_t>(AlertDescription::close_notify):
                {
                    tls_record record{ ContentType::Alert};
                    record.m_contents = { static_cast<uint8_t>(AlertLevel::warning), static_cast<uint8_t>(AlertDescription::close_notify) };
                    co_await write_record(record, timeout);
                }
                default:
                    co_return;
            }
            break;
        default:
            co_return;
    }
}

task<stream_result> TLS::client_heartbeat(tls_record client_record, std::optional<milliseconds> timeout) {
    auto [heartblead, heartbeat_record] = key_schedule::client_heartbeat_record(client_record, can_heartbeat);
    if(heartblead) {
        co_await m_client->write(to_unsigned("heartbleed?"), option_singleton().error_timeout);
        throw ssl_error("unexpected heartbeat response", AlertLevel::fatal, AlertDescription::access_denied);
    }
    co_return co_await write_record(heartbeat_record, timeout);
}

}// namespace fbw
