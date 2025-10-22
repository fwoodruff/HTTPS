//
//  PEMextract.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 04/12/2021.
//

#include "PEMextract.hpp"
#include "Cryptography/assymetric/secp256r1.hpp"
#include "TLS_enums.hpp"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <array>
#include <cassert>


namespace fbw {
static uint8_t letter_to_num(uint8_t byt) {
    if(byt >='A' and byt <= 'Z') {
        return byt-'A';
    }
    if(byt >='a' and byt <= 'z') {
        return byt-'a' + 26;
    }
    if(byt >='0' and byt <= '9') {
        return byt-'0' + 52;
    }
    if(byt == '+') {
        return 62;
    }
    if(byt == '/') {
        return 63;
    }
    throw ssl_error("unexpected character; could not parse PEM", AlertLevel::fatal, AlertDescription::bad_certificate);
}

static std::vector<uint8_t> decode64(std::string data) {
    std::vector<uint8_t> out;
    uint16_t buffer = 0;
    int j = 0;
    for(size_t i = 0; i < data.size(); i++) {
        if (data[i] == '\n') {
            continue;
        }
        if (data[i] == '=') {
            continue;
        }
        buffer <<= 6;
        buffer |= (uint16_t(letter_to_num(data[i]) & 0x3f));
        j += 6;
        if(j >= 8) {
            j -= 8;
            out.insert(out.end(), {static_cast<uint8_t>(buffer >> j)});
        }
    }
    return out;
}

static std::array<uint8_t,32> deserialise(std::vector<uint8_t> asn1) {
    if (asn1.size() < 68) {
        throw ssl_error("unsupported private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    const std::vector<uint8_t> eckey_id = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
    const std::vector<uint8_t> secp256k1_id = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

    if (!std::equal(eckey_id.begin(), eckey_id.end(), asn1.begin() + 8) ||
        !std::equal(secp256k1_id.begin(), secp256k1_id.end(), asn1.begin() + 17)) {
        throw ssl_error("unsupported certificate private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    std::array<unsigned char, 32> privkey;
    std::copy(&asn1[36], &asn1[36 + 32], privkey.begin());
    return privkey;
}

std::array<uint8_t,32> privkey_for_domain(const std::string& domain) {
    auto privkey_file = project_options.key_folder / domain / project_options.key_file;
    if(!std::filesystem::exists(privkey_file) or domain.empty()) {
        privkey_file = project_options.key_folder / project_options.default_subfolder / project_options.key_file;
    }
    return privkey_from_file(privkey_file);
}

std::array<uint8_t,32> privkey_from_file(const std::filesystem::path& filename) {
    std::ifstream const t(filename);
    if (t.fail()) {
        throw ssl_error("no private key found", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    std::stringstream buffer;
    buffer << t.rdbuf();
    std::string const file = buffer.str();
    std::string const begin = "-----BEGIN PRIVATE KEY-----\n";
    std::string const end = "-----END PRIVATE KEY-----\n";
    size_t start_idx = file.find(begin);
    if(start_idx == std::string::npos) {
        throw ssl_error("unsupported private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    start_idx += begin.size();
    size_t const end_idx = file.find(end);
    if(end_idx == std::string::npos) {
        throw ssl_error("unsupported private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    if (end_idx < start_idx) {
        throw ssl_error("unsupported private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    std::string const data = file.substr(start_idx,end_idx-start_idx);
    std::vector<uint8_t> const DER = decode64(data);
    auto key = deserialise(DER);
    return key;
}

std::vector<std::vector<uint8_t>> der_cert_for_domain(const std::string& domain) {
    auto cert_file = project_options.key_folder / domain / project_options.certificate_file;
    if(!std::filesystem::exists(cert_file) or domain.empty()) {
        cert_file = project_options.key_folder / project_options.default_subfolder / project_options.certificate_file;
    }
    return der_cert_from_file(cert_file);
}

std::vector<std::vector<uint8_t>> der_cert_from_file(const std::filesystem::path& filename) {
    std::ifstream const t(filename);
    std::stringstream buffer;
    buffer << t.rdbuf();
    std::string const file = buffer.str();
    
    size_t end_idx = 0;
    std::vector<std::vector<uint8_t>> output;
    while(true) {
        const std::string begin = "-----BEGIN CERTIFICATE-----\n";
        const std::string end = "-----END CERTIFICATE-----\n";
        size_t start_idx = file.find(begin, end_idx);
        if(start_idx == std::string::npos) {
            if(end_idx == 0) {
                throw ssl_error("bad certificate", AlertLevel::fatal, AlertDescription::bad_certificate);
            }                 break;
           
        }
        start_idx += begin.size();
        end_idx = file.find(end, end_idx);
        if(end_idx == std::string::npos) {
            throw ssl_error("bad certificate", AlertLevel::fatal, AlertDescription::bad_certificate);
        }
        if (end_idx < start_idx) {
            throw ssl_error("bad certificate", AlertLevel::fatal, AlertDescription::bad_certificate);
        }
        std::string const data = file.substr(start_idx, end_idx - start_idx);
        end_idx += end.size();
        const std::vector<uint8_t> DER = decode64(data);
        output.push_back(DER);
    }
    return output;
}
} // namespace fbw
