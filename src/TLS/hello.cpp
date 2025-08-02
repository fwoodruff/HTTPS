//
//  hello.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 18/08/2024.
//

#include "hello.hpp"
#include "TLS_enums.hpp"
#include "TLS_utils.hpp"
#include "../global.hpp"
#include <vector>
#include <span>
#include <memory>
#include <algorithm>
#include <print>
#include "Cryptography/assymetric/secp256r1.hpp"
#include "Cryptography/assymetric/x25519.hpp"
#include "Cryptography/assymetric/x25519mlkem768.hpp"
#include "Cryptography/one_way/keccak.hpp"

namespace fbw {

std::vector<std::string> get_SNI(std::span<const uint8_t> servernames) {
    // Server name
    try {
        std::vector<std::string> out;
        while(!servernames.empty()) {
            auto entry = der_span_read(servernames, 0, 2);
            if(entry.empty()) {
                throw std::out_of_range{"out of range"};
            }
            switch(entry[0]) {
                case 0: // DNS hostname
                {
                    size_t name_len = try_bigend_read(entry, 1, 2);
                    const auto subdomain_name_span = entry.subspan(3);
                    if(name_len != subdomain_name_span.size()) {
                        return {}; // throw something
                    }
                    out.emplace_back(subdomain_name_span.begin(), subdomain_name_span.end());
                    break;
                }
                default:
                    break;
            }
            servernames = servernames.subspan(entry.size() + 2);
        }
        return out;
    } catch(...) { }
    return {};
}

std::vector<NamedGroup> get_supported_groups(std::span<const uint8_t> extension_data) {
    std::vector<NamedGroup> out;
    auto supported_groups_data = extension_data.subspan(2);
    for(int i = 0; i < ssize_t(supported_groups_data.size())-1; i += 2) {
        auto group = try_bigend_read(supported_groups_data, i, 2);
        out.push_back(static_cast<NamedGroup>(group));
    }
    return out;
}

std::vector<SignatureScheme> get_signature_schemes(std::span<const uint8_t> extension_data) {
    std::vector<SignatureScheme> out;
    auto supported_groups_data = extension_data.subspan(2);
    for(int i = 0; i < ssize_t(supported_groups_data.size())-1; i += 2) {
        auto group = try_bigend_read(supported_groups_data, i, 2);
        out.push_back(static_cast<SignatureScheme>(group));
    }
    return out;
}

std::pair<bool, bool> get_server_client_heartbeat(std::span<const uint8_t> extension_data) {
    const std::vector<uint8_t> peer_may_send {0x00, 0x01, 0x00};
    const std::vector<uint8_t> peer_no_send { 0x00, 0x01, 0x02};
    if(extension_data.size() == 3) [[likely]] {
        if(std::equal(extension_data.begin(), extension_data.end(), peer_may_send.begin())) {
            return { true, true };
        }
        if(std::equal(extension_data.begin(), extension_data.end(), peer_no_send.begin())) {
            return { true, false };
        }
    }
    return { false, false};
}

std::vector<uint16_t> get_supported_versions(std::span<const uint8_t> extension_data) {
    std::vector<uint16_t> out;
    size_t versions = extension_data[0];
    if(versions + 1 != extension_data.size() or versions % 2 != 0) {
        return {};
    }
    for(size_t i = 1; i < extension_data.size(); i += 2) {
        uint16_t vers = try_bigend_read(extension_data, i, 2);
        out.push_back(vers);
    }
    return out;
}

std::vector<CertificateCompressionAlgorithm> get_certificate_compression_algos(std::span<const uint8_t> extension_data) {
    std::vector<CertificateCompressionAlgorithm> out;
    auto cert_algos = der_span_read(extension_data, 0, 1);
    while(!cert_algos.empty()) {
        auto algo = static_cast<CertificateCompressionAlgorithm>(try_bigend_read(cert_algos, 0, 2));
        out.push_back(algo);
        cert_algos = cert_algos.subspan(2);
    }
    return out;
}

std::vector<key_share> get_named_group_keys(std::span<const uint8_t> extension_data) {
    size_t ext_len = try_bigend_read(extension_data, 0, 2);
    if(ext_len + 2 != extension_data.size()) {
        throw ssl_error("malformed TLS version extension", AlertLevel::fatal, AlertDescription::decode_error);
    }
    extension_data = extension_data.subspan(2);
    std::vector<key_share> shared_keys;
    while(!extension_data.empty()) {
        auto key_type = extension_data.subspan(0, 2);
        auto group = static_cast<NamedGroup>(try_bigend_read(key_type, 0, 2));
        size_t len = try_bigend_read(extension_data, 2, 2);
        auto key_value = extension_data.subspan(4, len);
        auto typed_key = key_share({group, std::vector<uint8_t>(key_value.begin(), key_value.end())});
        shared_keys.push_back(std::move(typed_key));
        extension_data = extension_data.subspan(len + 4);
    }
    return shared_keys;
}

std::vector<std::string> get_application_layer_protocols(std::span<const uint8_t> extension_data) {
    std::vector<std::string> alpn_types;
    auto alpn_data = der_span_read(extension_data, 0, 2);
    while(!alpn_data.empty()) {
        auto alpn_val = der_span_read(alpn_data, 0, 1);
        alpn_types.emplace_back(alpn_val.begin(), alpn_val.end());
        alpn_data = alpn_data.subspan(alpn_val.size()+1);
    }
    return alpn_types;
}

preshared_key_ext get_preshared_keys(std::span<const uint8_t> extension_data) {
    preshared_key_ext psk_exts {};
    auto psk_ids = der_span_read(extension_data, 0, 2);
    psk_exts.idxbinders_ext = psk_ids.size() + 2;
    extension_data = extension_data.subspan(psk_ids.size() + 2);
    while(!psk_ids.empty()) {
        auto psk = der_span_read(psk_ids, 0, 2);
        pre_shared_key_entry psk_entry {};
        psk_entry.m_key = {psk.begin(), psk.end()};
        psk_entry.m_obfuscated_age = try_bigend_read(psk_ids, psk.size() + 2, 4);
        psk_exts.m_keys.push_back(std::move(psk_entry));
        psk_ids = psk_ids.subspan(psk.size() + 6);
    }
    auto binder_data = der_span_read(extension_data, 0, 2);
    while(!binder_data.empty()) {
        auto binder = der_span_read(binder_data, 0, 1);
        binder_data = binder_data.subspan(binder.size() + 1);
        psk_exts.m_psk_binder_entries.emplace_back(binder.begin(), binder.end());
    }
    return psk_exts;
}

std::vector<PskKeyExchangeMode> get_pskmodes(std::span<const uint8_t> extension_data) {
    auto spn = der_span_read(extension_data, 0, 1);
    std::vector<PskKeyExchangeMode> out;
    for(auto c : spn) {
        out.push_back(static_cast<PskKeyExchangeMode>(c));
    }
    return out;
}

void parse_extension(hello_record_data& record, extension ext) {
    switch(ext.type) {
        case ExtensionType::server_name:
            record.parsed_extensions.insert(ext.type);
            record.server_names = get_SNI(ext.data);
            break;
        case ExtensionType::max_fragment_length:
            record.parsed_extensions.insert(ext.type);
            record.record_size_limit = try_bigend_read(ext.data, 0, 2);
            break;
        case ExtensionType::padding:
            record.parsed_extensions.insert(ext.type);
            record.padding_size = der_span_read(ext.data, 0, 2).size();
            break;
        case ExtensionType::supported_groups:
            record.parsed_extensions.insert(ext.type);
            record.supported_groups = get_supported_groups(ext.data);
            break;
        case ExtensionType::heartbeat:
        {
            record.parsed_extensions.insert(ext.type);
            auto [server_heartbeat, client_heartbeat] = get_server_client_heartbeat(ext.data);
            record.server_heartbeat = server_heartbeat;
            record.client_heartbeat = client_heartbeat;
            break;
        }
        case ExtensionType::application_layer_protocol_negotiation:
            record.parsed_extensions.insert(ext.type);
            record.application_layer_protocols = get_application_layer_protocols(ext.data);
            break;
        case ExtensionType::signed_certificate_timestamp:
            record.parsed_extensions.insert(ext.type);
            break;
        case ExtensionType::pre_shared_key:
            record.parsed_extensions.insert(ext.type);
            record.pre_shared_key = get_preshared_keys(ext.data);
            break;
        case ExtensionType::early_data:
            record.parsed_extensions.insert(ext.type);
            break;
        case ExtensionType::supported_versions:
            record.parsed_extensions.insert(ext.type);
            record.supported_versions = get_supported_versions(ext.data);
            break;
        case ExtensionType::psk_key_exchange_modes:
            record.parsed_extensions.insert(ext.type);
            record.pskmodes = get_pskmodes(ext.data);
            break;
        case ExtensionType::key_share:
            record.parsed_extensions.insert(ext.type);
            record.shared_keys = get_named_group_keys(ext.data);
            break;
        case ExtensionType::compressed_certificate:
            record.parsed_extensions.insert(ext.type);
            record.certificate_compression = get_certificate_compression_algos(ext.data);
            break;
        case ExtensionType::renegotiation_info:
            record.parsed_extensions.insert(ext.type);
            break;
        default:
            break;
    }
}

hello_record_data parse_client_hello(const std::vector<uint8_t>& hello) {

    hello_record_data record;

    if(hello.empty()) {
        throw ssl_error("record is just a header", AlertLevel::fatal, AlertDescription::decode_error);
    }
    assert(hello.size() >= 1 and hello[0] == 1);

    size_t len = try_bigend_read(hello,1,3);
    if(len + 4 != hello.size()) {
        throw ssl_error("record length overflows", AlertLevel::fatal, AlertDescription::decode_error);
    }

    record.legacy_client_version = try_bigend_read(hello, 4, 2);

    // client random
    std::copy(&hello.at(6), &hello.at(38), record.m_client_random.begin());
    
    // session ID
    size_t idx = 38;
    auto session_id_span = der_span_read(hello, idx, 1);
    record.client_session_id.insert(record.client_session_id.end(), session_id_span.begin(), session_id_span.end());
    idx += (session_id_span.size() + 1);

    // cipher suites
    auto cipher_bytes = der_span_read(hello, idx, 2);
    for(size_t i = 0; i < cipher_bytes.size()-1; i+= 2) {
        auto suite_value = try_bigend_read(cipher_bytes, i, 2);
        record.cipher_su.push_back(static_cast<cipher_suites>(suite_value));
    }
    
    // client version
    if ( hello.at(4) != 3 or hello.at(5) != 3 ) {
        throw ssl_error("unsupported version handshake", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    idx += cipher_bytes.size() + 2;
    // compression
    auto compression_methods = der_span_read(hello, idx, 1);
    record.compression_types = std::vector<uint8_t>(compression_methods.begin(), compression_methods.end());
    idx += (compression_methods.size() + 1);

    // extensions
    auto extensions = der_span_read(hello, idx, 2);
    idx += 2;

    while(!extensions.empty()) {
        size_t extension_type = try_bigend_read(extensions, 0, 2);
        auto extension_span = der_span_read(extensions, 2, 2);
        if(extensions.size() < extension_span.size() + 2) {
            throw ssl_error("bad extensions", AlertLevel::fatal, AlertDescription::decode_error);
        }
        extensions = extensions.subspan(extension_span.size() + 4);
        std::vector<uint8_t> ext_data(extension_span.begin(), extension_span.end());
        extension ext = {static_cast<ExtensionType>(extension_type), ext_data};
        parse_extension(record, ext);

        if(ext.type == ExtensionType::pre_shared_key) {
            if(!extensions.empty()) {
                throw ssl_error("preshared key must be last extension", AlertLevel::fatal, AlertDescription::illegal_parameter);
            }
            const uint8_t* dptr = &extension_span.front();
            const uint8_t* dfrom = &hello.front();
            assert(record.pre_shared_key);
            auto diff = dptr - dfrom;
            assert(record.pre_shared_key->idxbinders == 0);
            assert( record.pre_shared_key->idxbinders_ext != 0);
            record.pre_shared_key->idxbinders = record.pre_shared_key->idxbinders_ext + diff;
        }
    }
    return record;
}

void write_alpn_extension(tls_record& record, std::string alpn) {
    record.write2(ExtensionType::application_layer_protocol_negotiation);
    record.start_size_header(2);
    record.start_size_header(2);
    record.start_size_header(1);
    record.write(to_unsigned(alpn));
    record.end_size_header();
    record.end_size_header();
    record.end_size_header();
}

void write_early_data_encrypted_ext(tls_record& record) {
    record.write2(ExtensionType::early_data);
    record.start_size_header(2);
    record.end_size_header();
}

void write_renegotiation_info(tls_record& record) {
    const uint16_t handshake_reneg = 0xff01;
    record.write2(handshake_reneg);
    record.start_size_header(2);
    record.write1(0);
    record.end_size_header();
}

void write_heartbeat(tls_record& record) {
    record.write2(ExtensionType::heartbeat);
    record.start_size_header(2);
    record.write1(0);
    record.end_size_header();
}

void write_key_share(tls_record& record, const key_share& pubkey_ephem) {
    record.write2(ExtensionType::key_share);
    record.start_size_header(2);
    record.write2(pubkey_ephem.key_type);
    record.start_size_header(2);
    record.write(pubkey_ephem.key);
    record.end_size_header();
    record.end_size_header();
}

void write_key_share_request(tls_record& record, NamedGroup chosen_group) {
    record.write2(ExtensionType::key_share);
    record.start_size_header(2);
    record.write2(chosen_group);
    record.end_size_header();
}

void write_supported_versions(tls_record& record, uint16_t version) {
    record.write2(ExtensionType::supported_versions);
    record.start_size_header(2);
    record.write2(version);
    record.end_size_header();
}

void write_cookie(tls_record& record) {
    record.write2(ExtensionType::cookie);
    record.start_size_header(2);
    record.start_size_header(2);
    record.write(to_unsigned("cookie"));
    record.end_size_header();
    record.end_size_header();
}

void write_pre_shared_key_extension(tls_record& record, uint16_t key_id) {
    record.write2(ExtensionType::pre_shared_key);
    record.start_size_header(2);
    record.write2(key_id);
    record.end_size_header();
}

std::vector<uint8_t> get_shared_secret(std::array<uint8_t, 32> server_private_key_ephem, key_share peer_key) {
    assert(!peer_key.key.empty());
    switch(peer_key.key_type) {
        case NamedGroup::x25519:
        {
            assert(peer_key.key.size() == curve25519::PUBKEY_SIZE);
            std::array<uint8_t, curve25519::PUBKEY_SIZE> cli_pub;
            std::copy(peer_key.key.begin(), peer_key.key.end(), cli_pub.begin());
            auto shared_secret = curve25519::multiply(server_private_key_ephem, cli_pub);
            auto shared_secret_str = std::vector<uint8_t>(shared_secret.begin(), shared_secret.end());
            return shared_secret_str;
        }
        case NamedGroup::secp256r1:
        {
            assert(peer_key.key.size() == secp256r1::PUBKEY_SIZE);
            std::array<uint8_t, secp256r1::PUBKEY_SIZE> cli_pub;
            std::copy_n(peer_key.key.begin(), secp256r1::PUBKEY_SIZE, cli_pub.begin());
            auto shared_secret = secp256r1::multiply(server_private_key_ephem, cli_pub);
            auto shared_secret_str = std::vector<uint8_t>(shared_secret.begin(), shared_secret.end());
            return shared_secret_str;
        }
        default:
            assert(false);
            break;
    }
}

std::pair<std::vector<uint8_t>, key_share> process_client_key_share(const key_share& client_keyshare) {
    switch(client_keyshare.key_type) {
        case NamedGroup::x25519:
        {
            std::array<uint8_t, 32> server_privkey;
            randomgen.randgen(server_privkey);
            std::array<uint8_t, 32> pubkey_ephem = curve25519::base_multiply(server_privkey);
            std::vector<uint8_t> server_pub(pubkey_ephem.begin(), pubkey_ephem.end());
            key_share server_key { client_keyshare.key_type, server_pub };
            auto shared_secret = get_shared_secret(server_privkey, client_keyshare);
            return { shared_secret, server_key };
        }
        case NamedGroup::secp256r1:
        {
            std::array<uint8_t, 32> server_privkey;
            randomgen.randgen(server_privkey);
            std::array<uint8_t, 65> pubkey_ephem = secp256r1::get_public_key(server_privkey);
            std::vector<uint8_t> server_pub(pubkey_ephem.begin(), pubkey_ephem.end());
            key_share server_key { client_keyshare.key_type, server_pub };
            auto shared_secret = get_shared_secret(server_privkey, client_keyshare);
            return { shared_secret, server_key };
        }
        case NamedGroup::X25519MLKEM768:
        {
            auto [ shared_secret, server_keyshare ] = xkem::process_client_keyshare(client_keyshare.key);
            if (shared_secret.empty()) {
                throw ssl_error("", AlertLevel::fatal, AlertDescription::illegal_parameter);
            }
            return { shared_secret, { NamedGroup::X25519MLKEM768, server_keyshare } };
        }
        default:
            assert(false);
    }
}

std::vector<uint8_t> make_hello_random(uint16_t version, bool requires_hello_retry) {
    constexpr std::array<uint8_t, 8> tls_11_downgrade_protection_sentinel = { 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00 };
    constexpr std::array<uint8_t, 8> tls_12_downgrade_protection_sentinel = { 0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01 };
    constexpr std::array<uint8_t, 32> tls13_hello_retry_sentinel = { 0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
                                                                     0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
                                                                     0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
                                                                     0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c };
    std::vector<uint8_t> server_random(32, 0);
    do {
        randomgen.randgen(server_random);
        if(std::equal(tls_12_downgrade_protection_sentinel.begin(), tls_12_downgrade_protection_sentinel.begin() + 4, server_random.begin()+24)) {
            continue;
        }
    } while(false);
    assert(server_random != std::vector<uint8_t>(32, 0));
    if(version < TLS12) {
        std::copy(tls_11_downgrade_protection_sentinel.begin(), tls_11_downgrade_protection_sentinel.end(), server_random.begin()+24);
    }
    if(version == TLS12) {
        std::copy(tls_12_downgrade_protection_sentinel.begin(), tls_12_downgrade_protection_sentinel.end(), server_random.begin()+24);
    }
    if(version == TLS13 and requires_hello_retry) {
        std::copy(tls13_hello_retry_sentinel.begin(), tls13_hello_retry_sentinel.end(), server_random.begin());
    }
    return server_random;
}

} // namespace