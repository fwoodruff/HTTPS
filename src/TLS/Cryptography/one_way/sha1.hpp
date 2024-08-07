//
//  secure_hash.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//


#ifndef sha1_hpp
#define sha1_hpp

#include <array>
#include <algorithm>
#include <vector>
#include <string>

#include "hash_base.hpp"
#include "../../../global.hpp"

namespace fbw {


class sha1 final : public hash_base {
public:
    static constexpr int64_t block_size = 64;
    static constexpr int64_t hash_size = 20;
    sha1();
    
    std::unique_ptr<hash_base> clone() const override;
    sha1& update_impl(const uint8_t* begin, size_t size) noexcept override;
    
    ustring hash() const override;
    [[nodiscard]] size_t get_block_size() const noexcept override;
    [[nodiscard]] size_t get_hash_size() const noexcept override;

private:
    size_t datalen = 0;
    std::array<uint32_t,5> m_state {};
    std::array<uint8_t,block_size> m_data {};    
};


} // namespace fbw

#endif   // sha1_hpp
