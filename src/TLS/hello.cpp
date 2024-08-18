

#include "hello.hpp"
#include "TLS_enums.hpp"
#include "../global.hpp"
#include <vector>
#include <span>
#include <memory>

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

std::vector<SignatureScheme> get_supported_groups(std::span<const uint8_t> extension_data) {
    std::vector<SignatureScheme> out;
    auto supported_groups_data = extension_data.subspan(2);
    for(int i = 0; i < ssize_t(supported_groups_data.size())-1; i += 2) {
        auto group = try_bigend_read(supported_groups_data, i, 2);
        out.push_back(static_cast<SignatureScheme>(group));
    }
    return out;
}

std::pair<bool, bool> get_server_client_heartbeat(std::span<const uint8_t> extension_data) {
    const ustring peer_may_send {0x00, 0x01, 0x00};
    const ustring peer_no_send { 0x00, 0x01, 0x02};
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

std::vector<key_share> get_named_groups(std::span<const uint8_t> extension_data) {
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
        auto typed_key = key_share({group, ustring(key_value.begin(), key_value.end())});
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

void parse_extension(hello_record_data& record, extension ext) {
    switch(ext.type) {
        case ExtensionType::server_name:
            record.server_names = get_SNI(ext.data);
            break;
        case ExtensionType::supported_groups:
            record.supported_groups = get_supported_groups(ext.data);
            break;
        case ExtensionType::heartbeat:
        {
            auto [server_heartbeat, client_heartbeat] = get_server_client_heartbeat(ext.data);
            record.server_heartbeat = server_heartbeat;
            record.client_heartbeat = client_heartbeat;
            break;
        }
        case ExtensionType::supported_versions:
            record.supported_versions = get_supported_versions(ext.data);
            break;
        case ExtensionType::key_share:
            record.shared_keys = get_named_groups(ext.data);
            break;
        case ExtensionType::application_layer_protocol_negotiation:
            record.application_layer_protocols = get_application_layer_protocols(ext.data);
        default:
            break;
    }
}

hello_record_data parse_client_hello(const ustring& hello) {

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
    record.client_session_id.append(session_id_span.begin(), session_id_span.end());
    idx += (session_id_span.size() + 1);

    // cipher suites
    auto cipher_bytes = der_span_read(hello, idx, 2);
    for(int i = 0; i < cipher_bytes.size()-1; i+= 2) {
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
        ustring ext_data(extension_span.begin(), extension_span.end());
        extension ext = {static_cast<ExtensionType>(extension_type), ext_data};
        parse_extension(record, ext);
    }
    return record;
}

} // namespace