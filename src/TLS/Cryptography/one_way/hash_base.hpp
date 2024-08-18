//
//  hash_base.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef hash_base_hpp
#define hash_base_hpp

#include <stdio.h>
#include "../../../global.hpp"
#include <memory>
#include <string>


namespace fbw {

class hmac;


class hash_base {
    virtual hash_base& update_impl(const uint8_t* data, size_t size) noexcept = 0;
public:
    friend hmac;
    virtual ~hash_base() noexcept = default;
    virtual std::unique_ptr<hash_base> clone() const = 0;
    
    template<typename T>
    hash_base& update(const T & data) {
        return update_impl(data.data(), data.size());
    }
     
    [[nodiscard]] virtual ustring hash() const = 0;

    [[nodiscard]] virtual size_t get_block_size() const noexcept = 0;
    [[nodiscard]] virtual size_t get_hash_size() const noexcept = 0;
};

template<typename T> 
ustring do_hash(const hash_base& hash_ctor, const T& data) {
    auto ctx = hash_ctor.clone();
    ctx->update(data);
    return ctx->hash();
}


} // namespace fbw

#endif // hash_base_hpp
