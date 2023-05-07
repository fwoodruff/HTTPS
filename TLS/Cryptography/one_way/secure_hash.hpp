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
#include "global.hpp"

namespace fbw {

class sha256 final : public hash_base {
public:
    static constexpr int64_t block_size = 64;
    sha256() noexcept;
    
    std::unique_ptr<hash_base> clone() const override;
    sha256& update_impl(const uint8_t* begin, size_t size) noexcept override;
    
    ustring hash() && override;
    [[nodiscard]] size_t get_block_size() const noexcept override;
private:
    size_t datalen;
    uint64_t bitlen;
    std::array<uint8_t,block_size> m_data;
    std::array<uint32_t,8> state;
    bool done;
};

class sha384 final : public hash_base {
public:
    static constexpr int64_t block_size = 64;
    sha384() noexcept;
    
    std::unique_ptr<hash_base> clone() const override;
    sha256& update_impl(const uint8_t* begin, size_t size) noexcept override;
    
    ustring hash() && override;
    [[nodiscard]] size_t get_block_size() const noexcept override;
private:
    size_t datalen;
    uint64_t bitlen;
    std::array<uint8_t,block_size> data;
    std::array<uint64_t,8> state;
    bool done;
};

class sha1 final : public hash_base {
public:
    static constexpr int64_t block_size = 64;
    sha1();
    
    std::unique_ptr<hash_base> clone() const override;
    sha1& update_impl(const uint8_t* begin, size_t size) noexcept override;
    
    ustring hash() && override;
    [[nodiscard]] size_t get_block_size() const noexcept override;

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

    hmac(std::unique_ptr<hash_base> hasher, const uint8_t* key, size_t key_len);
public:
    template<typename T> hmac(std::unique_ptr<hash_base> hasher, const T& key);
    std::unique_ptr<hash_base> clone() const override;
    hmac& update_impl(const uint8_t* key, size_t key_len) noexcept override;
    [[nodiscard]] ustring hash() && override;
    using hash_base::hash;
    [[nodiscard]] size_t get_block_size() const noexcept override;

    hmac(const hmac &);
    hmac& operator=(const hmac &);
    ~hmac() noexcept = default;
};

template<typename T>
hmac::hmac(std::unique_ptr<hash_base> hasher, const T& key) :
    hmac(std::move(hasher), key.data(), key.size())
{}

} // namespace fbw

#endif   // secure_hash_hpp
