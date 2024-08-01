//
//  PEMextract.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 04/12/2021.
//

#include "PEMextract.hpp"
#include "Cryptography/assymetric/secp256r1.hpp"
#include "TLS_enums.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <array>
#include <cassert>


namespace fbw {
uint8_t letter_to_num(uint8_t byt) {
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

ustring decode64(std::string data) {
    ustring out;
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
            out.append({static_cast<uint8_t>(buffer >> j)});
        }
    }
    return out;
}

std::array<uint8_t,32> deserialise(ustring asn1) {
    if (asn1.size() < 68) {
        throw ssl_error("unsupported private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    const ustring eckey_id = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
    const ustring secp256k1_id = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};

    if (eckey_id != asn1.substr(8, 9) or secp256k1_id != asn1.substr(17, 10)) {
        throw ssl_error("unsupported certificate private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }

    std::array<unsigned char, 32> privkey;
    std::copy(&asn1[36], &asn1[36 + 32], privkey.begin());
    return privkey;
}

std::array<uint8_t,32> privkey_for_domain(std::string domain) {
    auto privkey_file = option_singleton().key_folder / domain / option_singleton().key_file;
    if(!std::filesystem::exists(privkey_file) or domain == "") {
        privkey_file = option_singleton().key_folder / option_singleton().default_subfolder / option_singleton().key_file;
    }
    return privkey_from_file(privkey_file);
}

std::array<uint8_t,32> privkey_from_file(std::filesystem::path filename) {
    std::ifstream t(filename);
    if (t.fail()) {
        throw ssl_error("no private key found", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    std::stringstream buffer;
    buffer << t.rdbuf();
    std::string file = buffer.str();
    std::string begin = "-----BEGIN PRIVATE KEY-----\n";
    std::string end = "-----END PRIVATE KEY-----\n";
    size_t start_idx = file.find(begin);
    if(start_idx == std::string::npos) {
        throw ssl_error("unsupported private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    start_idx += begin.size();
    size_t end_idx = file.find(end);
    if(end_idx == std::string::npos) {
        throw ssl_error("unsupported private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    if (end_idx < start_idx) {
        throw ssl_error("unsupported private key format", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    std::string data = file.substr(start_idx,end_idx-start_idx);
    ustring DER = decode64(data);
    auto key = deserialise(DER);
    return key;
}

std::vector<ustring> der_cert_for_domain(std::string domain) {
    auto cert_file = option_singleton().key_folder / domain / option_singleton().certificate_file;
    if(!std::filesystem::exists(cert_file) or domain == "") {
        cert_file = option_singleton().key_folder / option_singleton().default_subfolder / option_singleton().certificate_file;
    }
    return der_cert_from_file(cert_file);
}

std::vector<ustring> der_cert_from_file(std::filesystem::path filename) {
    std::ifstream t(filename);
    std::stringstream buffer;
    buffer << t.rdbuf();
    std::string file = buffer.str();
    
    size_t end_idx = 0;
    std::vector<ustring> output;
    while(true) {
        const std::string begin = "-----BEGIN CERTIFICATE-----\n";
        const std::string end = "-----END CERTIFICATE-----\n";
        size_t start_idx = file.find(begin, end_idx);
        if(start_idx == std::string::npos) {
            if(end_idx == 0) {
                throw ssl_error("bad certificate", AlertLevel::fatal, AlertDescription::bad_certificate);
            } else {
                break;
            }
        }
        start_idx += begin.size();
        end_idx = file.find(end, end_idx);
        if(end_idx == std::string::npos) {
            throw ssl_error("bad certificate", AlertLevel::fatal, AlertDescription::bad_certificate);
        }
        if (end_idx < start_idx) {
            throw ssl_error("bad certificate", AlertLevel::fatal, AlertDescription::bad_certificate);
        }
        std::string data = file.substr(start_idx, end_idx - start_idx);
        end_idx += end.size();
        const ustring DER = decode64(data);
        output.push_back(DER);
    }
    return output;
}
} // namespace fbw
