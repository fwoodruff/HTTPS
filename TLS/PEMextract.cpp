//
//  PEMextract.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 04/12/2021.
//

#include "PEMextract.hpp"
#include "secp256r1.hpp"
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
    assert(false);
}

uint8_t num_to_letter(uint8_t bits) {
    assert(bits < 64 and bits >=0);
    if (bits <= 25) {
        return bits + 'A';
    }
    if(bits>=26 and bits <= 51) {
        return bits + 'a' - 26;
    }
    if(bits >=52 and bits <= 61) {
        return bits + '0' - 52;
    }
    if(bits == 62) {
        return '+';
    }
    if(bits == 63) {
        return '/';
    }
    
    assert(false);
}


ustring encode64(ustring data) {
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
        buffer <<= 8;
        buffer |= data[i];
        j += 8;
        while(j >= 6) {
            j -= 6;
            out.append({num_to_letter((buffer>>j) & 0x3f)});
        }
    }
    return out;
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
    assert(asn1.size() >= 68);
    // currently this ignores everything and assumes the file is secp256r1
    std::array<unsigned char, 32> privkey;
    std::copy(&asn1[36], &asn1[36 + 32], privkey.begin());
    return privkey;
}


std::array<uint8_t,32> privkey_from_file(std::string filename) {
    std::ifstream t(filename);
    std::stringstream buffer;
    buffer << t.rdbuf();
    std::string file = buffer.str();
    std::string begin = "-----BEGIN PRIVATE KEY-----\n";
    std::string end = "-----END PRIVATE KEY-----\n";
    size_t start_idx = file.find(begin);
    assert(start_idx != std::string::npos);
    start_idx += begin.size();
    size_t end_idx = file.find(end);
    assert(end_idx != std::string::npos);
    std::string data = file.substr(start_idx,end_idx-start_idx);
    ustring DER = decode64(data);
    auto key = deserialise(DER);
    return key;
}

std::vector<ustring> der_cert_from_file(std::string filename) {
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
        end_idx = file.find(end,end_idx);
        if(end_idx == std::string::npos) {
            throw ssl_error("bad certificate", AlertLevel::fatal, AlertDescription::bad_certificate);
        }
        std::string data = file.substr(start_idx,end_idx-start_idx);
        end_idx+=end.size();
        const ustring DER = decode64(data);
        output.push_back(DER);
        
    }
    return output;
}
} // namespace fbw
