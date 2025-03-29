//
//  block_chain.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 12/12/2021.
//

#include "block_chain.hpp"
#include "../one_way/sha1.hpp"
#include "../one_way/hmac.hpp"
#include "AES.hpp"
#include "../../../global.hpp"
#include "../one_way/keccak.hpp"
#include "../../TLS_enums.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>

namespace fbw::aes {

AES_CBC_SHA::AES_CBC_SHA() : server_write_round_keys({}),
                                            client_write_round_keys({}),
                                            server_MAC_key({}),
                                            client_MAC_key({}),
                                            seqno_server(0),
                                            seqno_client(0) { }


void AES_CBC_SHA::set_key_material_12(ustring expanded_master)  {
    assert(expanded_master.size() >= 104);

    auto client_write_key = std::vector<uint8_t>(16,0);
    auto server_write_key = std::vector<uint8_t>(16,0);
    
    auto it = expanded_master.begin();

    std::copy_n(it, client_MAC_key.size(), client_MAC_key.begin());
    it += client_MAC_key.size();
    std::copy_n(it, server_MAC_key.size(), server_MAC_key.begin());
    it += server_MAC_key.size();
    std::copy_n(it, client_write_key.size(), client_write_key.begin());
    it += client_write_key.size();
    std::copy_n(it, server_write_key.size(), server_write_key.begin());
    it += server_write_key.size();
    
    client_write_round_keys = aes_key_schedule(client_write_key);
    server_write_round_keys = aes_key_schedule(server_write_key);
}


ustring pad_message(ustring message) {
    const auto blocksize = 16;
    const auto padmax = 256;
    
    assert(padmax > blocksize and padmax % blocksize == 0);
    
    // randomises the padding length
    const auto min_padded_message_size = ((message.size() / blocksize)+1)* blocksize;
    const auto max_padded_message_size = ((message.size() / padmax)+1)* padmax;
    auto randval = randomgen.randgen64();
    const auto padded_message_size = min_padded_message_size +
                (randval*blocksize) % (blocksize+max_padded_message_size-min_padded_message_size);

    const auto padding_checked = padded_message_size - message.size();
    
    assert(padded_message_size > message.size());
    assert(padding_checked < padmax);
    const uint8_t padding = padding_checked;
    message.append(padding, padding-1);
    assert(message.size() % blocksize == 0);
    return message;
}


tls_record AES_CBC_SHA::protect(tls_record record) noexcept {
    auto ctx = hmac(sha1(), server_MAC_key );
    std::array<uint8_t,13> sequence {};
    checked_bigend_write(seqno_server, sequence, 0, 8);
    seqno_server++;
    sequence[8] = static_cast<uint8_t>(record.get_type());
    sequence[9] = record.get_major_version();
    sequence[10] = record.get_minor_version();
    checked_bigend_write(record.m_contents.size(), sequence, 11, 2);
    ctx.update(sequence);
    ctx.update(record.m_contents);
    auto machash = std::move(ctx).hash();
    record.m_contents.append(machash);
    std::array<uint8_t, 16> record_IV {};
    randomgen.randgen(record_IV);
    record.m_contents = pad_message(std::move(record.m_contents));
    ustring out;
    out.append(record_IV.cbegin(),record_IV.cend());
    auto in_block = record_IV;
    for(size_t i = 0; i < record.m_contents.size(); i += 16) {
        std::transform(in_block.cbegin(), in_block.cend(), &record.m_contents[i], in_block.begin(), std::bit_xor<uint8_t>());
        auto out_block = aes_encrypt(in_block, server_write_round_keys);
        out.append(out_block.cbegin(),out_block.cend());
        in_block = out_block;
    }
    record.m_contents = std::move(out);
    return record;
}

tls_record AES_CBC_SHA::deprotect(tls_record record) {

    if(record.m_contents.size() % 16 != 0 or record.m_contents.size() < 32) {
        throw ssl_error("bad encrypted record length", AlertLevel::fatal, AlertDescription::decrypt_error);
    }

    ustring plaintext;
    std::array<uint8_t, 16> record_IV {};
    constexpr auto blocksize = record_IV.size();
    
    assert(record.m_contents.size() >= 16);
    std::copy(&*record.m_contents.begin(),&record.m_contents[blocksize], record_IV.begin() );

    
    auto xor_block = record_IV;
    
    for(size_t i = blocksize; i < record.m_contents.size(); i += blocksize) {
        std::array<uint8_t,blocksize> in_block {};
        std::copy(&record.m_contents[i], &record.m_contents[i+blocksize], in_block.begin());

        auto plainxor = aes_decrypt(in_block, client_write_round_keys);

        std::transform(plainxor.cbegin(), plainxor.cend(), xor_block.cbegin(), plainxor.begin(), std::bit_xor<uint8_t>());
        xor_block = in_block;

        plaintext.append(plainxor.cbegin(),plainxor.cend());
    }
    
    
    bool pad_oracle_attack = false;
    
    assert(plaintext.size() >= 1);
    size_t siz = plaintext[plaintext.size()-1];
    if(siz+1+client_MAC_key.size() > plaintext.size()) {
        pad_oracle_attack = true;
    }
    for(size_t i = 0; i < siz+1; i++) {
        assert(plaintext.size() >= 1+i);
        if(plaintext[plaintext.size()-1-i] != siz) {
            pad_oracle_attack = true;
        }
    }
    
    if(pad_oracle_attack) {
        siz = 0;
    }
    
    assert(plaintext.size() >= siz + 1);
    plaintext.resize(plaintext.size()-siz-1);
    std::array<uint8_t, 20> mac_calc {};
    std::copy(plaintext.crbegin(), plaintext.crbegin() + 20, mac_calc.rbegin());
    
    assert(plaintext.size() >= mac_calc.size());
    plaintext.resize(plaintext.size() - mac_calc.size());

    auto ctx = hmac(sha1(), client_MAC_key);
    std::array<uint8_t,13> mac_hash_header {};
    checked_bigend_write(seqno_client, mac_hash_header, 0, 8);
    mac_hash_header[8] = static_cast<uint8_t>(record.get_type());
    mac_hash_header[9] = record.get_major_version();
    mac_hash_header[10] = record.get_minor_version();

    seqno_client++;
    checked_bigend_write(plaintext.size(), mac_hash_header, 11, 2);

    ctx.update(mac_hash_header);
    ctx.update(plaintext);
    auto machash = std::move(ctx).hash();
    

    if(!std::equal(mac_calc.cbegin(), mac_calc.cend(), machash.cbegin())) {
        throw ssl_error("bad client MAC", AlertLevel::fatal, AlertDescription::bad_record_mac);
    }
    if(pad_oracle_attack) {
        throw ssl_error("bad client padding", AlertLevel::fatal, AlertDescription::decrypt_error);
    }
    
    record.m_contents = std::move(plaintext);

    if(record.m_contents.size() > TLS_RECORD_SIZE + DECRYPTED_TLS_RECORD_GIVE) {
        throw ssl_error("decrypted record too large", AlertLevel::fatal, AlertDescription::record_overflow);
    }
    return record;
}

} // namespace fbw::aes
