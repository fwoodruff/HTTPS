//
//  TLS_utils.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 27/07/2024.
//

#include "TLS_utils.hpp"

#include "../global.hpp"
#include "PEMextract.hpp"

namespace fbw {
std::array<uint8_t, 32> extract_x25519_key(std::span<const uint8_t> extension) {
    size_t ext_len = try_bigend_read(extension, 0, 2);
    if(ext_len + 2 != extension.size()) {
        throw ssl_error("malformed TLS version extension", AlertLevel::fatal, AlertDescription::decode_error);
    }
    extension = extension.subspan(2);
    while(!extension.empty()) { // todo: check max iterations for any while(true)
        auto key_type = extension.subspan(0, 2);
        uint16_t group = try_bigend_read(key_type, 0, 2);
        size_t len = try_bigend_read(extension, 2, 2);
        auto key_value = extension.subspan(4, len);
        if(group == static_cast<uint16_t>(NamedGroup::x25519) and key_value.size() == 32) {
            std::array<uint8_t, 32> out;
            std::copy(key_value.begin(), key_value.end(), out.begin());
            return out;
        }
        extension = extension.subspan(len + 4);
        // todo: size sanity check
        // todo: extract other keys
    }
    return {};
}

void certificates_serial(tls_record& record, std::string domain, bool tls_13) {
    record.push_der(3);
    std::vector<ustring> certs;
    try {
        certs = der_cert_for_domain(domain);
    } catch(std::exception& e) {
        std::cerr << e.what() << std::endl;
        throw e;
    }
    for (const auto& cert : certs) {
        record.push_der(3);
        record.write(cert);
        if(tls_13) { // certificate extensions
            record.push_der(2);
            record.pop_der();
        }
        record.pop_der();
    }
    record.pop_der();
}


bool is_tls13_supported(std::span<const uint8_t> extension) {
    if(extension.empty()) {
        throw std::out_of_range{"out of range"};
    }
    size_t versions = extension[0];
    if(versions + 1 != extension.size() or versions % 2 != 0) {
        throw ssl_error("malformed TLS version extension", AlertLevel::fatal, AlertDescription::decode_error);
    }
    for(size_t i = 1; i < extension.size(); i += 2) {
        if(extension[i] == 0x03 and extension[i+1] == 0x04) {
            // tls 1.3 supported // todo: check logic
        }
        return true;
    }
    return false;
}


std::string check_SNI(std::span<const uint8_t> servernames) {
    // Server name
    try {
        while(!servernames.empty()) {
            auto entry = der_span_read(servernames, 0, 2);
            if(entry.empty()) {
                throw std::out_of_range{"out of range"};
            }
            switch(entry[0]) {
                case 0: // DNS hostname
                {
                    size_t name_len = try_bigend_read(entry, 1, 2);
                    const auto subdomain_name = entry.subspan(3);
                    
                    if(name_len != subdomain_name.size()) {
                        return "";
                    }
                    auto domain_names = option_singleton().domain_names;
                    for(auto name : domain_names) {
                        if(name.size() == subdomain_name.size() and std::equal(name.begin(), name.end(), subdomain_name.begin())) {
                            return name;
                        }
                    }
                    break;
                }
                default:
                    break;
            }
            servernames = servernames.subspan(entry.size() + 2);
        }
    } catch(...) { }
    return "";
}

}