//
//  secure_hash.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//


#ifndef sha2_hpp
#define sha2_hpp

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
    
    ustring hash() const override;
    [[nodiscard]] size_t get_block_size() const noexcept override;
    [[nodiscard]] size_t get_hash_size() const noexcept override;
private:
    size_t datalen = 0;
    uint64_t bitlen = 0;
    std::array<uint8_t,block_size> m_data {};
    std::array<uint32_t,8> state {};
};

class sha384 final : public hash_base {
public:
    static constexpr int64_t block_size = 128;
    static constexpr int64_t hash_size = 48;
    sha384() noexcept;
    
    std::unique_ptr<hash_base> clone() const override;
    sha384& update_impl(const uint8_t* begin, size_t size) noexcept override;
    
    ustring hash() const override;
    [[nodiscard]] size_t get_block_size() const noexcept override;
    [[nodiscard]] size_t get_hash_size() const noexcept override;
private:
    size_t datalen = 0;
    uint64_t bitlen = 0;
    std::array<uint8_t, block_size> m_data {};
    std::array<uint64_t, 8> state {};
};

} // namespace fbw

#endif   // secure_hash_hpp
