//
//  cipher_base.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef cipher_base_hpp
#define cipher_base_hpp

#include "../../../global.hpp"
#include "../../TLS_utils.hpp"
#include "../key_derivation.hpp"
#include "../../Cryptography/one_way/keccak.hpp"

#include <cstdio>

namespace fbw {

tls_record wrap13(tls_record record) {
    if(record.get_type() == ContentType::ChangeCipherSpec) {
        return record;
    }
    record.m_contents.push_back(static_cast<uint8_t>(record.get_type()));
    // RFC 8446 5.4
    // Enforce client support for wrapped record padding but leave content padding to the application layer
    record.m_contents.push_back(0);
    record.m_type = ContentType::Application;
    return record;
}

tls_record unwrap13(tls_record record) {
    assert(record.m_contents.size() > 1);
    while(record.m_contents.size() > 1 and record.m_contents.back() == 0) {
        record.m_contents.pop_back();
    }
    record.m_type = static_cast<ContentType>(record.m_contents.back());
    record.m_contents.pop_back();
    return record;
}

ustring make_additional_13(const ustring& message, size_t tag_size) {
    ustring additional_data { 0x17, 0x03, 0x03, 0, 0};
    auto size = message.size();
    size += tag_size;
    checked_bigend_write(size, additional_data, 3, 2);
    return additional_data;
}

} // namespace fbw


#endif // cipher_base_hpp
