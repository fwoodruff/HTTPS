//
//  keccak.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 16/07/2021.
//
#ifndef keccak_hpp
#define keccak_hpp

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace fbw {

class keccak_sponge {
    size_t capacity;
    size_t rate;
    std::array<uint8_t,200> state;
    size_t rate_in_bytes;
    size_t idx;
    bool absorb_phase = true;
    uint8_t padding_byte;
public:
    keccak_sponge(size_t capacity = 512, uint8_t domain_separator = 0x1F) noexcept;
    template <typename T> void absorb(const T* input, size_t num_bytes) noexcept;
    template <typename T> void squeeze(T* output, size_t num_bytes) noexcept;
    void reset() noexcept;
};

class cprng : keccak_sponge {
    std::once_flag init;
public:
    void randgen(uint8_t* output, size_t num_bytes);
    [[nodiscard]] uint64_t randgen64();

    template<typename T>
    void randgen(T& output) {
        randgen(output.data(), output.size());
    }
};

extern thread_local cprng randomgen;

} // namespace fbw

#endif // keccak_hpp
