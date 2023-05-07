//
//  keccak.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 16/07/2021.
//

#include "keccak.hpp"
#include "global.hpp"

#include <cstdio>
#include <array>
#include <cassert>
#include <climits>
#include <random>
#include <cstring>

namespace fbw {
static_assert(CHAR_BIT == 8, "CHAR_BIT != 8");

thread_local cprng randomgen;

void keccak_F1600_state_permute(std::array<uint8_t,200>& state) noexcept;
int LFSR86540(uint8_t& LFSR) noexcept;
uint64_t ROL64(uint64_t a, uint64_t offset) noexcept ;
uint64_t read_lane(const std::array<uint8_t, 200>& state, int x, int y) noexcept;
void write_lane(std::array<uint8_t, 200>& state,  int x, int y, uint64_t val) noexcept;
void xor_lane(std::array<uint8_t, 200>& state,  int x, int y, uint64_t val) noexcept;


keccak_sponge::keccak_sponge(size_t capacity_) noexcept {
    capacity = capacity_;
    rate = 1600 - capacity;
    assert(rate % 8 == 0 and capacity < 1600);
    state = {0};
    rate_in_bytes = rate/8;
    block_size = 0;
    absorb_phase = true;
    idx = 0;
}

void keccak_sponge::reset() noexcept {
    absorb_phase = true;
    block_size = 0;
    state = {0};
}

void keccak_sponge::absorb(const uint8_t* const input, size_t inputByteLen) noexcept {
    assert(absorb_phase);
    if(!inputByteLen) return;
    while(inputByteLen > 0) {
        if(idx==rate_in_bytes) {
            keccak_F1600_state_permute(state);
            idx = 0;
        }
        assert(idx < 200);
        state[idx++] ^= input[--inputByteLen];
    }
}

void keccak_sponge::absorb(const char* const input, size_t inputByteLen) noexcept {
    assert(absorb_phase);
    if(!inputByteLen) return;
    while(inputByteLen > 0) {
        if(idx==rate_in_bytes) {
            keccak_F1600_state_permute(state);
            idx = 0;
        }
        state[idx++] ^= static_cast<uint8_t>(input[--inputByteLen]);
    }
}



void keccak_sponge::squeeze(uint8_t* const output, size_t outputByteLen) noexcept {
    if(absorb_phase) {
        assert(idx < 200);
        state[idx] ^= 0x1F;
        state[rate_in_bytes-1] ^= 0x80;
        keccak_F1600_state_permute(state);
        absorb_phase = false;
        idx = 0;
    }
    while(outputByteLen > 0) {
        if(idx==rate_in_bytes) {
            keccak_F1600_state_permute(state);
            idx = 0;
        }
        output[--outputByteLen] = state[idx++];
    }
}

void keccak_sponge::squeeze(char* const output, size_t outputByteLen) noexcept {
    if(absorb_phase) {
        assert(idx < 200);
        state[idx] ^= 0x1F;
        state[rate_in_bytes-1] ^= 0x80;
        keccak_F1600_state_permute(state);
        absorb_phase = false;
        idx = 0;
    }
    while(outputByteLen > 0) {
        if(idx==rate_in_bytes) {
            keccak_F1600_state_permute(state);
            idx = 0;
        }
        output[--outputByteLen] = static_cast<char>(state[idx++]);
    }
}


uint64_t ROL64(uint64_t a, uint64_t offset) noexcept {
    assert(offset<64);
    return (a<<offset)^(a>>(64-offset));
}

uint64_t read_lane(const std::array<uint8_t, 200>& state, int x, int y) noexcept {
    uint64_t out = 0;
    size_t addr = 8*(x + 5*y);
    for(int i=7; i>=0; --i) {
        out <<= 8;
        assert(addr+i < 200);
        out |= state[addr + i];
    }
    return out;
}

void write_lane(std::array<uint8_t, 200>& state,  int x, int y, uint64_t val) noexcept {
    const size_t addr = 8*(x + 5*y);
    uint64_t mask = 0xffULL;
    for(int i=0; i<8; i++) {
        assert(addr+i < 200);
        state[addr+i] = (val & mask) >> (8*i);
        mask <<= 8;
    }
}

void xor_lane(std::array<uint8_t, 200>& state,  int x, int y, uint64_t val) noexcept {
    const size_t addr = 8*(x + 5*y);
    uint64_t mask = 0xffULL;
    for(int i=0; i<8; i++) {
        assert(addr+i < 200);
        state[addr+i] ^= (val & mask) >> (8*i);
        mask <<= 8;
    }
}

void keccak_F1600_state_permute(std::array<uint8_t,200>& state) noexcept {
    uint8_t LFSRstate { 0x01 };
    for(int round=0; round<24; round++) {
        uint64_t C[5] {}, D =0;
        for(int i=0; i<5; i++) {
            C[i] = 0;
            for(int j=0; j<5; j++) {
                C[i] ^= read_lane(state, i, j);
            }
        }
        for(int i=0; i<5; i++) {
            D = C[(i+4)%5] ^ ROL64(C[(i+1)%5], 1);
            for (int j=0; j<5; j++)
                xor_lane(state, i, j, D);
        }
           
        unsigned int x = 1;
        unsigned int y = 0;
        uint64_t current = read_lane(state, x, y);
        for(int t=0; t<24; t++) {
            unsigned int r = ((t+1)*(t+2)/2)%64;
            unsigned int Y = (2*x+3*y)%5; x = y; y = Y;
            uint64_t temp = read_lane(state, x, y);
            write_lane(state, x, y, ROL64(current, r));
            current = temp;
        }
        uint64_t temp[5] {};
        for(int j=0; j<5; j++) {
            for(int i=0; i<5; i++)
                temp[i] = read_lane(state, i, j);
            for(int i=0; i<5; i++)
                write_lane(state, i, j, temp[i] ^((~temp[(i+1)%5]) & temp[(i+2)%5]));
        }
        for(int j=0; j<7; j++) {
            unsigned int bitPosition = (1<<j)-1;
            if (LFSR86540(LFSRstate))
                xor_lane(state,0, 0, 1ULL<<bitPosition);
        }
        
    }
}

int LFSR86540(uint8_t& LFSR) noexcept {
    int result = (LFSR & 0x01) != 0;
    LFSR = (LFSR & 0x80) ? LFSR << 1 : (LFSR << 1) ^ 0x71;
    return result;
}




void cprng::randgen(uint8_t*  output, size_t N) {
    if(!init) {
        std::random_device rd;
        unsigned char bucket[4];
        for(int i = 0; i < 50; i ++) {
            unsigned int val = rd();
            std::memcpy(bucket, &val, 4);
            absorb(bucket, 4);
        }
        init = true;
    }
    squeeze(output, N);
};

uint64_t cprng::randgen64() {
    uint8_t randbuff[8] {};
    uint64_t randval;
    randomgen.randgen(randbuff, 8);
    memcpy(&randval, randbuff, 8);
    return randval;
}

} // namespace fbw
