//
//  secure_hash.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//


#ifndef hmac_hpp
#define hmac_hpp

#include <array>
#include <algorithm>
#include <vector>
#include <string>

#include "hash_base.hpp"
#include "../../../global.hpp"

namespace fbw {

class hmac : public hash_base {
    std::unique_ptr<const hash_base> m_factory;
    std::unique_ptr<hash_base> m_hasher;
    std::vector<uint8_t> KeyPrime;

    hmac(const hash_base& hasher, const uint8_t* key, size_t key_len);
public:
    template<typename T> hmac(const hash_base& hasher, const T& key);
    [[nodiscard]] std::unique_ptr<hash_base> clone() const override;
    hmac& update_impl(const uint8_t* key, size_t key_len) noexcept override;
    [[nodiscard]] std::vector<uint8_t> hash() const override;
    using hash_base::hash;
    [[nodiscard]] size_t get_block_size() const noexcept override;
    [[nodiscard]] size_t get_hash_size() const noexcept override;

    hmac(const hmac &);
    hmac& operator=(const hmac &);
    ~hmac() noexcept override = default;
};

template<typename T>
hmac::hmac(const hash_base& hasher, const T& key) :
    hmac(std::move(hasher), key.data(), key.size())
{}


template<typename T, typename U>
std::vector<uint8_t> do_hmac(const hash_base& hash_ctor, const T& key, const U& data) {
    auto mac = hmac(hash_ctor, key);
    mac.update(data);
    return mac.hash();
}

} // namespace fbw

#endif   // hmac_hpp
