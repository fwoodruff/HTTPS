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
#include "TLS_helpers.hpp"

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

std::optional<tls_record> try_extract_record(ustring& input);

task<void> TLS::server_alert(AlertLevel level, AlertDescription description) {
    auto r = tls_record(ContentType::Alert);
    r.m_contents = { static_cast<uint8_t>(level), static_cast<uint8_t>(description) };
    co_await write_record(std::move(r), option_singleton().error_timeout);
}

task<stream_result> TLS::read_append(ustring& data, std::optional<milliseconds> timeout) {
    std::optional<ssl_error> error_ssl {};
    try {
        if(m_expected_record != HandshakeStage::application_data) {
            if(!co_await perform_handshake()) {
                co_return stream_result::closed;
            }
        }

        auto [record, result] = co_await try_read_record(timeout);
        if(result != stream_result::ok) {
            co_return std::move(result);
        }
        if(m_expected_record > HandshakeStage::client_change_cipher_spec) {
            record = cipher_context->decrypt(std::move(record));
        }
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
        if(m_expected_record != HandshakeStage::application_data) {
            if(!co_await perform_handshake()) {
                co_return stream_result::closed;
            }
        }
        constexpr size_t RECORD_SIZE = 1300;
        size_t idx = 0;
        while(idx < data.size()) {
            ustring contents = data.substr(idx, RECORD_SIZE);
            idx += RECORD_SIZE;
            tls_record rec(ContentType::Application);
            rec.m_contents = std::move(contents);
            auto res = co_await write_record(std::move(rec), timeout);
            if (res != stream_result::ok) {
                co_return res;
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


task<void> TLS::close_notify() {
    try {
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
        hello_request.m_contents = { static_cast<uint8_t>(HandshakeType::hello_request), 0, 0, 0};
        co_return co_await write_record(hello_request, option_singleton().handshake_timeout);
    }
    co_return stream_result::closed;
}

task<bool> TLS::perform_handshake() {
    // todo: TLS 1.3
    handshake_material handshake;
    bool hello_request_sent = false;
    for(;;) {
        auto [record, result] = co_await try_read_record(option_singleton().handshake_timeout);
        if(result == stream_result::closed) {
            co_return false;
        }
        if(result == stream_result::timeout) {
            if(!hello_request_sent) {
                auto res = co_await server_hello_request();
                if(res == stream_result::ok) {
                    hello_request_sent = true;
                    continue;
                }
            }
            co_return false;
        }
        if(m_expected_record > HandshakeStage::client_change_cipher_spec) {
            record = cipher_context->decrypt(std::move(record));
        }
        switch ( static_cast<ContentType>(record.get_type()) ) {
            case ContentType::Handshake:
                if(co_await client_handshake_record(handshake, std::move(record)) != stream_result::ok) {
                    co_return false;
                }
                if(m_expected_record == HandshakeStage::application_data) {
                    co_return true;
                }
                break;
            case ContentType::ChangeCipherSpec:
                client_change_cipher_spec(std::move(record));
                break;
            case ContentType::Application:
                throw ssl_error("handshake not done yet", AlertLevel::fatal, AlertDescription::unexpected_message);
            case ContentType::Alert:
                co_await client_alert(std::move(record), option_singleton().handshake_timeout);
                co_return false;
            case ContentType::Heartbeat:
                auto res = co_await client_heartbeat(std::move(record), option_singleton().handshake_timeout);
                if(res != stream_result::ok) {
                    co_return false;
                }
                break;
        }
    }
}

task<std::pair<tls_record, stream_result>> TLS::try_read_record(std::optional<milliseconds> timeout) {
    if (m_buffered_record) {
        auto record = *m_buffered_record;
        m_buffered_record = std::nullopt;
        co_return {record, stream_result::ok};
    }
    for(;;) {
        if (m_buffer.size() > TLS_RECORD_SIZE + 6) {
            throw ssl_error("oversized record", AlertLevel::fatal, AlertDescription::record_overflow);
        }
        auto record = try_extract_record(m_buffer);
        if(record) {
            if (record->get_major_version() != 3) {
                throw ssl_error("unsupported version", AlertLevel::fatal, AlertDescription::protocol_version);
            }
            co_return {*record, stream_result::ok};
        }
        stream_result connection_alive = co_await m_client->read_append(m_buffer, timeout);
        if(connection_alive != stream_result::ok) {
            co_return {tls_record{}, connection_alive};
        }
    }
}

task<stream_result> TLS::write_record(tls_record record, std::optional<milliseconds> timeout) {
    if(m_expected_record > HandshakeStage::server_change_cipher_spec) {
        record = cipher_context->encrypt(record);
    }
    co_return co_await m_client->write(record.serialise(), timeout);
}

task<stream_result> TLS::client_handshake_record(handshake_material& handshake, tls_record record) {
    ustring handshake_record = record.m_contents;
    switch (handshake_record.at(0)) {
        case static_cast<uint8_t>(HandshakeType::hello_request):
            throw ssl_error("hello_request not supported", AlertLevel::fatal, AlertDescription::handshake_failure);
        case static_cast<uint8_t>(HandshakeType::client_hello):
            client_hello(handshake, std::move(record));
            if(auto result = co_await server_hello(handshake); result != stream_result::ok) {
                co_return std::move(result);
            }
            //co_return stream_result::ok;
            if(auto result = co_await server_certificate(*handshake.handshake_hasher); result != stream_result::ok) {
                co_return std::move(result);
            }
            if(auto result = co_await server_key_exchange(handshake); result != stream_result::ok) {
                co_return std::move(result);
            }
            if(auto result = co_await server_hello_done(*handshake.handshake_hasher); result != stream_result::ok) {
                co_return std::move(result);
            }
            break;
        case static_cast<uint8_t>(HandshakeType::client_key_exchange):
            client_key_exchange(handshake, std::move(record));
            break;
        case static_cast<uint8_t>(HandshakeType::finished):
            client_handshake_finished(handshake, std::move(record));
            if(auto result = co_await server_change_cipher_spec(); result != stream_result::ok) {
                co_return std::move(result);
            }
            if(auto result = co_await server_handshake_finished(handshake); result != stream_result::ok) {
                co_return std::move(result);
            }
            co_return stream_result::ok;
        default:
            throw ssl_error("unsupported handshake record type", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    co_return stream_result::ok;
}


std::optional<tls_record> try_extract_record(ustring& input) {
    if (input.size() < 5) {
        return std::nullopt;
    }
    tls_record out(static_cast<ContentType>(input[0]), input[1], input[2] );

    size_t record_size = try_bigend_read(input,3,2);
    if(input.size() < record_size + 5) {
        return std::nullopt;
    }
    out.m_contents = input.substr(5, record_size);
    input = input.substr(5 + record_size);
    return out;
}

bool check_SNI(ustring servernames) {
    // Server name
    try {
        while(!servernames.empty()) {
            size_t entry_len = try_bigend_read(servernames, 0, 2);
            ustring entry = servernames.substr(2, entry_len);
            
            switch(entry.at(0)) {
                case 0: // DNS hostname
                {
                    size_t name_len = try_bigend_read(entry, 1, 2);
                    const auto subdomain_name = entry.substr(3);
                    
                    if(name_len != subdomain_name.size()) {
                        return false;
                    }
                    auto domain_names = option_singleton().domain_names;
                    auto str_domain_name = to_signed(subdomain_name);
                    for(auto name : domain_names) {
                        if (name == str_domain_name) {
                            return true;
                        }
                    }
                    break;
                }
                default:
                    break;
            }
            servernames = servernames.substr(entry_len + 2);
        }
    } catch(...) { }
    return false;
}

std::array<uint8_t, 32> extract_x25519_key(ustring extension) {
    size_t ext_len = try_bigend_read(extension, 0, 2); // todo, less copying, more indexing
    if(ext_len + 2 != extension.size()) {
        throw ssl_error("malformed TLS version extension", AlertLevel::fatal, AlertDescription::decode_error);
    }
    extension = extension.substr(2);
    while(!extension.empty()) { // todo: check max iterations for any while(true)
        ustring key_type = extension.substr(0, 2);
        size_t len = try_bigend_read(extension, 2, 2);
        ustring key_value = extension.substr(4, len);
        if(key_type == ustring{ 0x00, 0x1d } and key_value.size() == 32) {
            std::array<uint8_t, 32> out;
            std::copy(key_value.begin(), key_value.end(), out.begin());
            return out;
        }
        extension = extension.substr(len + 4);
        // todo: size sanity check
        // todo: extract other keys
    }
    return {};
}

bool is_tls13_supported(ustring extension) {
    size_t versions = extension.at(0);
    if(versions + 1 != extension.size() or versions % 2 != 0) {
        throw ssl_error("malformed TLS version extension", AlertLevel::fatal, AlertDescription::decode_error);
    }
    for(int i = 1; i < extension.size(); i += 2) {
        if(extension[i] == 0x03 and extension[i+1] == 0x04) {
            // tls 1.3 supported // todo: check logic
        }
        return true;
    }
    return false;
}
 
void TLS::client_hello(handshake_material& handshake, tls_record record) {
    if(m_expected_record != HandshakeStage::client_hello) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    auto hello = record.m_contents;
    if(hello.empty()) {
        throw ssl_error("record is just a header", AlertLevel::fatal, AlertDescription::decode_error);
    }
    assert(hello.size() >= 1 and hello[0] == 1);

    size_t len = try_bigend_read(hello,1,3);
    if(len + 4 != hello.size()) {
        throw ssl_error("record length overflows", AlertLevel::fatal, AlertDescription::decode_error);
    }
    // client random
    handshake.m_client_random.resize(32);
    std::copy(&hello.at(6), &hello.at(38), handshake.m_client_random.begin());
    // session ID
    size_t idx = 38;
    size_t session_id_len = try_bigend_read(hello, idx, 1);
    if(session_id_len == 32) {
        client_session_id = std::array<uint8_t, 32>{};
        std::copy(&hello.at(idx+1), &hello.at(idx+33), client_session_id->begin());
    }

    idx += (session_id_len + 1);
    // cipher suites
    size_t ciphers_len = try_bigend_read(hello, idx, 2);
    static_cast<void>(hello.at(idx+ ciphers_len + 2));
    handshake.cipher = cipher_choice(handshake, hello.substr(idx + 2, ciphers_len));
    if(handshake.cipher == static_cast<uint16_t>(cipher_suites::TLS_FALLBACK_SCSV)) {
        throw ssl_error("unnecessary TLS 1.1 fallback", AlertLevel::fatal, AlertDescription::inappropriate_fallback);
    }

    // client version
    if ( hello.at(4) != 3 or hello.at(5) != 3 ) {
        throw ssl_error("unsupported version handshake", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    assert(cipher_context);
    assert(handshake.hash_ctor);
    assert(handshake.handshake_hasher);

    idx += ciphers_len + 2;
    // compression
    ssize_t compression_methods_lengths = try_bigend_read(hello, idx, 1);
    ustring compression_methods = hello.substr(idx + 1, compression_methods_lengths);
    if (compression_methods.find(static_cast<unsigned char>('\0')) == std::string::npos) {
        throw ssl_error("compression not supported", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    idx += (compression_methods_lengths + 1);
    // extensions
    ssize_t extensions_len = try_bigend_read(hello, idx, 2);
    idx += 2;

    while(extensions_len > 0) {
        size_t extension_type = try_bigend_read(hello, idx, 2);
        size_t extension_len = try_bigend_read(hello, idx + 2, 2);
        ustring extension = hello.substr(idx + 4, extension_len);
        extensions_len -= extension_len + 4;
        if(extensions_len < 0) {
            throw ssl_error("record length overflows", AlertLevel::fatal, AlertDescription::decode_error);
        }
        switch(extension_type) {
            case 0x000a:
                break;
            case 0x0000: // SNI
                if(!check_SNI(extension)) {
                    throw ssl_error("unexpected SNI", AlertLevel::fatal, AlertDescription::handshake_failure);
                }
                break;
            case 0x000f: // Heartbeat
                if(extension == ustring {0x00, 0x01, 0x00} or extension == ustring {0x00, 0x01, 0x01}) { // todo: check actual values here
                    can_heartbeat = true;
                } else {
                    throw ssl_error("invalid heartbeat extension", AlertLevel::fatal, AlertDescription::illegal_parameter);
                }
                break;
            case 0x002b: // TLS 1.3
                tls13_available = is_tls13_supported(extension);
                break;
            case 0x0033: // key share
                handshake.client_public_key = extract_x25519_key(extension);
                break;
            default:
                break;
        }
        idx += extension_len + 4;
    }

    handshake.handshake_hasher->update(hello);
    m_expected_record = HandshakeStage::server_hello;
}




symmetric_keys tls13_key_calc(handshake_material& handshake) {
    symmetric_keys keys;
    
    auto shared_secret = fbw::curve25519::multiply(handshake.server_private_key_ephem, handshake.client_public_key);
    auto hash_all_messages = handshake.handshake_hasher->hash();

    auto zero_hash = do_hash(*handshake.hash_ctor, ustring{});

    auto early_secret = hkdf_extract(*handshake.hash_ctor, ustring{}, ustring(32, 0) );
    auto derived_secret = hkdf_expand_label(*handshake.hash_ctor, early_secret, "derived", zero_hash, 48);
    auto handshake_secret = hkdf_extract(*handshake.hash_ctor, derived_secret, shared_secret);

    auto client_secret = hkdf_expand_label(*handshake.hash_ctor, handshake_secret, "c hs traffic", hash_all_messages, 48);
    auto server_secret = hkdf_expand_label(*handshake.hash_ctor, handshake_secret, "s hs traffic", hash_all_messages, 48);

    keys.client_handshake_key = hkdf_expand_label(*handshake.hash_ctor, client_secret, "key", ustring(), 32);
    keys.server_handshake_key = hkdf_expand_label(*handshake.hash_ctor, server_secret, "key", ustring(), 32); // todo: make length depend on cipher

    keys.client_handshake_iv = hkdf_expand_label(*handshake.hash_ctor, client_secret, "iv", ustring(), 12);
    keys.server_handshake_iv = hkdf_expand_label(*handshake.hash_ctor, server_secret, "iv", ustring(), 12);

    keys.client_data_key = hkdf_expand_label(*handshake.hash_ctor, keys.client_handshake_key, "key", ustring(), 32);
    keys.server_data_key = hkdf_expand_label(*handshake.hash_ctor, keys.server_handshake_key, "key", ustring(), 32);
    
    return keys;
}

task<stream_result> TLS::server_hello(handshake_material& handshake) {
    assert(m_expected_record == HandshakeStage::server_hello);

    // record header
    auto hello_record = tls_record(ContentType::Handshake);
    
    // handshake header and server version
    hello_record.m_contents.reserve(49); // fix me
    hello_record.m_contents = {static_cast<uint8_t>(HandshakeType::server_hello), 0x00, 0x00, 0x00, 0x03, 0x03};
    
    // server random
    handshake.m_server_random.resize(32);
    randomgen.randgen(handshake.m_server_random);
    hello_record.m_contents.append(handshake.m_server_random.cbegin(), handshake.m_server_random.cend());

    // session_id
    if(use_tls13 and client_session_id.has_value()) {
        hello_record.m_contents.push_back(32);
        hello_record.m_contents.append(client_session_id->begin(), client_session_id->end()); // session ID
    } else {
        hello_record.m_contents.append({0}); // session ID
    }
    
    ustring ciph;
    ciph.resize(2);
    checked_bigend_write(handshake.cipher, ciph, 0, 2);
    hello_record.m_contents.append(ciph);
    hello_record.m_contents.append({0}); // no compression

    ustring extensions = hello_extensions(handshake); // todo: store each of the extensions sent by the client in a map, and then only return those
    hello_record.m_contents.append(extensions);

    assert(hello_record.m_contents.size() >= 4);
    checked_bigend_write(hello_record.m_contents.size() - 4, hello_record.m_contents, 1, 3);

    assert(handshake.handshake_hasher != nullptr);
    handshake.handshake_hasher->update(hello_record.m_contents);
    
    auto result = co_await write_record(hello_record, option_singleton().handshake_timeout);
    m_expected_record = HandshakeStage::server_certificate;

    // todo: move into separate function
    symmetric_keys keys = tls13_key_calc(handshake);

    // todo: save the keys

    co_return std::move(result);
}

ustring TLS::hello_extensions(handshake_material& handshake) {
     // announces no support for vulnerable handshake renegotiation attacks
    const ustring handshake_reneg = { 0xff, 0x01, 0x00, 0x01, 0x00 };

    // announces application layer will use http/1.1
    ustring alpn_protocol_data { 0x00, 0x10, 0x00, 0x00, 0x00, 0x00 }; 
    auto http11 = to_unsigned("http/1.1");
    auto lenhttp11 = static_cast<uint8_t>(http11.size());
    alpn_protocol_data.push_back(lenhttp11);
    alpn_protocol_data.append(http11);
    checked_bigend_write(alpn_protocol_data.size() - 6, alpn_protocol_data, 4, 2);
    checked_bigend_write(alpn_protocol_data.size() - 4, alpn_protocol_data, 2, 2);

    // announces willingness to accept heartbeat records
    ustring heartbeat = { 0x00, 0x0f, 0x00, 0x01, 0x00 };

    // announces we will use TLS 1.3
    ustring tls13_ext = { 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };


    ustring key_share_ext = { 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20};
    if(use_tls13) {
        // compute x25519 keypair 
        randomgen.randgen(handshake.server_private_key_ephem);
        std::array<uint8_t, 32> pubkey_ephem = curve25519::base_multiply(handshake.server_private_key_ephem);
        key_share_ext.append(pubkey_ephem.begin(), pubkey_ephem.end());
    }

    ustring extensions { 0x00, 0x00 };
    extensions.append(alpn_protocol_data);
    extensions.append(handshake_reneg);

    if(use_tls13) {
        extensions.append(tls13_ext);
        extensions.append(key_share_ext);
    }
    if (can_heartbeat) {
        extensions.append(heartbeat);
    }
    checked_bigend_write(extensions.size() - 2, extensions, 0, 2);

    return extensions;
}

task<stream_result> TLS::server_certificate(hash_base& handshake_hasher) {
    assert(m_expected_record == HandshakeStage::server_certificate);
    tls_record certificate_record(ContentType::Handshake);
    certificate_record.m_contents = {static_cast<uint8_t>(HandshakeType::certificate), 0,0,0, 0,0,0};

    std::vector<ustring> certs;
    try {
        certs = der_cert_from_file(option_singleton().certificate_file);
    } catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
        throw e;
    }
    
    for (const auto& cert : certs) {
        ustring cert_header;
        cert_header.append({0, 0, 0});
        checked_bigend_write(cert.size(), cert_header, 0, 3);
        certificate_record.m_contents.append(cert_header);
        certificate_record.m_contents.append(cert);
    }
    assert(certificate_record.m_contents.size() >= 7);
    checked_bigend_write(certificate_record.m_contents.size() - 4, certificate_record.m_contents, 1, 3);
    checked_bigend_write(certificate_record.m_contents.size() - 7, certificate_record.m_contents, 4, 3);

    handshake_hasher.update(certificate_record.m_contents);
    m_expected_record = HandshakeStage::server_key_exchange;
    co_return co_await write_record(certificate_record, option_singleton().handshake_timeout);
}

task<stream_result> TLS::server_key_exchange(handshake_material& handshake) {
    randomgen.randgen(handshake.server_private_key_ephem);
    std::array<uint8_t, 32> pubkey_ephem = curve25519::base_multiply(handshake.server_private_key_ephem);

    // Record Header
    tls_record record(ContentType::Handshake);

    // Handshake Header
    record.m_contents.reserve(116);
    record.m_contents = { static_cast<uint8_t>(HandshakeType::server_key_exchange), 0x00, 0x00, 0x00 };

    // Curve Info
    std::array<uint8_t,3> curve_info({static_cast<uint8_t>(ECCurveType::named_curve), 0x00, 0x00});
    checked_bigend_write(static_cast<size_t>(NamedCurve::x25519), curve_info, 1, 2);
    
    // Public Key
    ustring signed_empheral_key;
    signed_empheral_key.append(curve_info.cbegin(), curve_info.cend());
    signed_empheral_key.append({static_cast<uint8_t>(pubkey_ephem.size())});
    signed_empheral_key.append(pubkey_ephem.crbegin(), pubkey_ephem.crend());

    assert(handshake.hash_ctor != nullptr);
    auto hashctx = handshake.hash_ctor->clone();
    
    hashctx->update(handshake.m_client_random);
    hashctx->update(handshake.m_server_random);
    hashctx->update(signed_empheral_key);
    
    auto signature_digest_vec = hashctx->hash();
    assert(signature_digest_vec.size() == 32);
    std::array<uint8_t, 32> signature_digest;
    std::copy(signature_digest_vec.cbegin(), signature_digest_vec.cend(), signature_digest.begin());
    
    auto certificate_private = privkey_from_file(option_singleton().key_file);

    // Signature
    std::array<uint8_t, 32> csrn;
    randomgen.randgen(csrn);
    ustring signature = secp256r1::DER_ECDSA(std::move(csrn), std::move(signature_digest), std::move(certificate_private));
    ustring sig_header ({static_cast<uint8_t>(HashAlgorithm::sha256), // Signature Header
        static_cast<uint8_t>(SignatureAlgorithm::ecdsa), 0x00, 0x00});
    
    checked_bigend_write(signature.size(), sig_header, 2, 2);
    
    record.m_contents.append(signed_empheral_key);
    record.m_contents.append(sig_header);
    record.m_contents.append(signature);

    assert(record.m_contents.size() >= 4);
    checked_bigend_write(record.m_contents.size()-4, record.m_contents, 1, 3);
    
    handshake.handshake_hasher->update(record.m_contents);
    m_expected_record = HandshakeStage::server_hello_done;
    co_return co_await write_record(record, option_singleton().handshake_timeout);
}

task<stream_result> TLS::server_hello_done(hash_base& handshake_hasher) {
    assert(m_expected_record == HandshakeStage::server_hello_done);
    tls_record record(ContentType::Handshake);
    record.m_contents = { static_cast<uint8_t>(HandshakeType::server_hello_done), 0x00, 0x00, 0x00 };
    handshake_hasher.update(record.m_contents);
    m_expected_record = HandshakeStage::client_key_exchange;
    co_return co_await write_record(record, option_singleton().handshake_timeout);
}

void TLS::client_key_exchange(handshake_material& handshake, tls_record record) {
    auto key_exchange = record.m_contents;
    if(m_expected_record != HandshakeStage::client_key_exchange) {
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    static_cast<void>(key_exchange.at(0));
    assert(key_exchange[0] == static_cast<uint8_t>(HandshakeType::client_key_exchange));
    
    const size_t len = try_bigend_read(key_exchange, 1, 3);
    const size_t keylen = try_bigend_read(key_exchange, 4, 1);
    if(len + 4 != key_exchange.size() or len != keylen + 1) {
        throw ssl_error("bad key exchange", AlertLevel::fatal, AlertDescription::decode_error);
    }
    
    if(key_exchange.size() < 37) {
        throw ssl_error("bad public key", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    std::reverse_copy(&key_exchange[5], &key_exchange[37], handshake.client_public_key.begin());
    auto premaster_secret = fbw::curve25519::multiply(handshake.server_private_key_ephem, handshake.client_public_key);
    handshake.master_secret = prf(*handshake.hash_ctor, premaster_secret, "master secret", handshake.m_client_random + handshake.m_server_random, 48);

    // AES_256_CBC_SHA256 has the largest amount of key material at 128 bytes
    auto key_material = prf(*handshake.hash_ctor,  handshake.master_secret, "key expansion", handshake.m_server_random + handshake.m_client_random, 128);

    cipher_context->set_key_material(key_material);
    handshake.handshake_hasher->update(key_exchange);
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

void TLS::client_handshake_finished(handshake_material& handshake, tls_record record) {
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
    record.m_contents = {static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)};
    auto res = co_await write_record(record, option_singleton().handshake_timeout);
    m_expected_record = HandshakeStage::server_handshake_finished;
    co_return res;
}

task<stream_result> TLS::server_handshake_finished(const handshake_material& handshake) {
    assert(m_expected_record == HandshakeStage::server_handshake_finished);
    tls_record out(ContentType::Handshake);
    out.m_contents = { static_cast<uint8_t>(HandshakeType::finished), 0x00, 0x00, 0x0c };
    
    assert(handshake.handshake_hasher);
    auto handshake_hash = handshake.handshake_hasher->hash(); // the others?
    assert(handshake_hash.size() == 32);
    
    ustring server_finished = prf(*handshake.hash_ctor, handshake.master_secret, "server finished", handshake_hash, 12);
    
    out.m_contents.append(server_finished);
    if(m_expected_record <= HandshakeStage::server_change_cipher_spec) {
        throw ssl_error("Unwilling to respond on unencrypted channel", AlertLevel::fatal, AlertDescription::insufficient_security);
    }
    
    m_expected_record = HandshakeStage::application_data;
    co_return co_await write_record(out, option_singleton().handshake_timeout);
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

task<stream_result> TLS::client_heartbeat(tls_record record, std::optional<milliseconds> timeout) {
    if(!can_heartbeat) {
        throw ssl_error("bad heartbeat payload length", AlertLevel::fatal, AlertDescription::illegal_parameter);
    }
    auto heartbeat_message = record.m_contents;

    if (heartbeat_message.size() < 1 or heartbeat_message[0] != 0x01 ) {
        throw ssl_error("unexpected heartbeat response", AlertLevel::fatal, AlertDescription::access_denied);
    }

    auto payload_length = try_bigend_read(heartbeat_message, 1, 2);
    if (payload_length >  heartbeat_message.size() - 3) {
        co_await m_client->write(to_unsigned("heartbleed?"), option_singleton().error_timeout);
        throw ssl_error("bad heartbeat payload length", AlertLevel::fatal, AlertDescription::access_denied);
    }

    auto length_and_payload = heartbeat_message.substr(1, payload_length + 2);

    tls_record heartbeat_record( ContentType::Heartbeat);
    heartbeat_record.m_contents = { 0x02 };
    heartbeat_record.m_contents.append( length_and_payload );
    co_return co_await write_record(heartbeat_record, timeout);
}

// once client sends over their supported ciphers
// if client supports ChaCha20 we enforce that
// otherwise if client supports AES-GCM/AES-CBC, we pick whichever their preference is
unsigned short TLS::cipher_choice(handshake_material& handshake, const ustring& s) {
    if(tls13_available and false) {
        for(size_t i = 0; i < s.size(); i += 2) {
            uint16_t x = try_bigend_read(s, i, 2);
            if(x == static_cast<uint16_t>(cipher_suites::TLS_CHACHA20_POLY1305_SHA256)) {
                use_tls13 = true;
                cipher_context = std::make_unique<cha::ChaCha20_Poly1305>();
                handshake.hash_ctor = std::make_unique<sha256>();
                handshake.handshake_hasher = handshake.hash_ctor->clone();
                return x;
            }
        }
    }

    /*
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if(x == static_cast<uint16_t>(cipher_suites::TLS_FALLBACK_SCSV)) {
            return x;
        }
    }
    */
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)) {
            cipher_context = std::make_unique<cha::ChaCha20_Poly1305>();
            handshake.hash_ctor = std::make_unique<sha256>();
            handshake.handshake_hasher = handshake.hash_ctor->clone();
            return x;
        }
    }
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if(x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)) {
            cipher_context = std::make_unique<aes::AES_128_GCM_SHA256>();
            handshake.hash_ctor = std::make_unique<sha256>();
            handshake.handshake_hasher = handshake.hash_ctor->clone();
            return x;
        }
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)) {
            cipher_context = std::make_unique<aes::AES_CBC_SHA>();
            handshake.hash_ctor = std::make_unique<sha256>();
            handshake.handshake_hasher = handshake.hash_ctor->clone();
            return x;
        }

    }
    throw ssl_error("no supported ciphers", AlertLevel::fatal, AlertDescription::handshake_failure );
    return 0;
}

}// namespace fbw



