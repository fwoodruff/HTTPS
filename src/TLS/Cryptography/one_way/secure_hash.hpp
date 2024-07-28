//
//  secure_hash.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//


#ifndef secure_hash_hpp
#define secure_hash_hpp

#include <array>
#include <algorithm>
#include <vector>
#include <string>

#include "hash_base.hpp"
#include "../../../global.hpp"

namespace fbw {

class sha256 final : public hash_base {
public:
    static constexpr int64_t block_size = 64;
    static constexpr int64_t hash_size = 32;
    sha256() noexcept;
    
    std::unique_ptr<hash_base> clone() const override;
    sha256& update_impl(const uint8_t* begin, size_t size) noexcept override;
    
    ustring hash() && override; // todo: rvalue ref is a bit clumsy, generating a hash shouldn't mangle the context
    [[nodiscard]] size_t get_block_size() const noexcept override;
    [[nodiscard]] size_t get_hash_size() const noexcept override;
private:
    size_t datalen;
    uint64_t bitlen;
    std::array<uint8_t,block_size> m_data;
    std::array<uint32_t,8> state;
    bool done;
};

class sha384 final : public hash_base {
public:
    static constexpr int64_t block_size = 128;
    static constexpr int64_t hash_size = 48;
    sha384() noexcept;
    
    std::unique_ptr<hash_base> clone() const override;
    sha384& update_impl(const uint8_t* begin, size_t size) noexcept override;
    
    ustring hash() && override;
    [[nodiscard]] size_t get_block_size() const noexcept override;
    [[nodiscard]] size_t get_hash_size() const noexcept override;
private:
    size_t datalen = 0;
    uint64_t bitlen = 0;
    std::array<uint8_t,block_size> m_data;
    std::array<uint64_t,8> state;
    bool done = false;
};

class sha1 final : public hash_base {
public:
    static constexpr int64_t block_size = 64;
    static constexpr int64_t hash_size = 20;
    sha1();
    
    std::unique_ptr<hash_base> clone() const override;
    sha1& update_impl(const uint8_t* begin, size_t size) noexcept override;
    
    ustring hash() && override;
    [[nodiscard]] size_t get_block_size() const noexcept override;
    [[nodiscard]] size_t get_hash_size() const noexcept override;

private:
    size_t datalen = 0;
    std::array<uint32_t,5> m_state;
    std::array<uint8_t,block_size> m_data;
    bool done;
    
};


class hmac : public hash_base {
    std::unique_ptr<const hash_base> m_factory;
    std::unique_ptr<hash_base> m_hasher;
    std::vector<uint8_t> KeyPrime;

    hmac(const hash_base& hasher, const uint8_t* key, size_t key_len); // todo: pass hash_base by const ref not unique_ptr
public:
    template<typename T> hmac(const hash_base& hasher, const T& key);
    std::unique_ptr<hash_base> clone() const override;
    hmac& update_impl(const uint8_t* key, size_t key_len) noexcept override;
    [[nodiscard]] ustring hash() && override;
    using hash_base::hash;
    [[nodiscard]] size_t get_block_size() const noexcept override;
    [[nodiscard]] size_t get_hash_size() const noexcept override;

    hmac(const hmac &);
    hmac& operator=(const hmac &);
    ~hmac() noexcept = default;
};

template<typename T>
hmac::hmac(const hash_base& hasher, const T& key) :
    hmac(std::move(hasher), key.data(), key.size())
{}


template<typename T> 
ustring do_hash(const hash_base& hash_ctor, const T& data) {
    auto ctx = hash_ctor.clone();
    ctx->update(data);
    return ctx->hash();
}

template<typename T, typename U>
ustring do_hmac(const hash_base& hash_ctor, const T& key, const U& data) {
    auto mac = hmac(hash_ctor, key);
    mac.update(data);
    return mac.hash();
}

} // namespace fbw

#endif   // secure_hash_hpp
