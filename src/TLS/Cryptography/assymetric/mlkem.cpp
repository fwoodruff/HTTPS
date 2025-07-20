//
//  mlkem.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 20/07/2025.
//

#include "mlkem.hpp"

#include <array>
#include <cassert>

namespace fbw::mlkem {

std::array<uint8_t, serial_byte_len> byte_encode(cyclotomic_poly F_poly) {
    std::array<uint8_t, serial_byte_len> b_bytes_out;
    int j = 0;
    for(int i = 0; i < n_len; i +=2) {
        auto a0 = F_poly[i] & 0x0fff;
        auto a1 = F_poly[i+1] & 0x0fff;
        b_bytes_out[j] = a0 & 0xff;
        b_bytes_out[j+1] = ((a0 >> 8) & 0x0f) | ((a1 & 0x0f) << 4);
        b_bytes_out[j+2] = ((a1 >> 4) & 0xff);
        j+=3;
    }
    return b_bytes_out;
}

cyclotomic_poly byte_decode(std::span<uint8_t> serial_F_poly, uint32_t d) {
    cyclotomic_poly F_poly;
    const int m = (d < 12) ? (1 << d) : q_modulo;
    for (int i = 0; i < n_len; i++) {
        uint32_t val = 0;
        for (int j = 0; j < d; j++) {
            int bit_pos = i * d + j;
            int byte_idx = bit_pos / 8;
            int bit_offset = bit_pos % 8;

            uint8_t bit = (serial_F_poly[byte_idx] >> bit_offset) & 1;
            val |= (bit << j);
        }
        F_poly[i] = val % m;
    }
    return F_poly;
}

cyclotomic_poly sample_NTT(std::span<const uint8_t, 32> seed_idx, uint8_t ii, uint8_t jj) {
    ::fbw::keccak_sponge ctx;
    cyclotomic_poly out;
    ctx.absorb(seed_idx.data(), seed_idx.size());
    ctx.absorb(&ii, 1);
    ctx.absorb(&jj, 1);
    int j = 0;
    while(j < n_len) {
        std::array<uint8_t, 3> C;
        ctx.squeeze(C.data(), C.size());
        auto d1 = int(C[0]) | (int(C[1] & 0x0f) << 8);
        auto d2 = (C[1] >> 4) | (int(C[2]) << 4);
        if(d1 < q_modulo) {
            out[j] = d1;
            j++;
        }
        if(d2 < q_modulo and j < 256) {
            out[j] = d2;
            j++;
        }
    }
    return out;
}

cyclotomic_poly sample_poly_CBD(uint8_t k, std::span<const uint8_t> b_array) {
    cyclotomic_poly out;
    assert(b_array.size() == k * 64);
    auto eta = b_array.size() / 64;
    for(int i = 0; i < n_len; i++) {
        int x = 0;
        int y = 0;
        for(int j = 0; j < eta; j++) {
            auto bit_idx_x = 2 * i * eta + j;
            auto bit_idx_y = bit_idx_x + eta;
            auto byte_idx_x = bit_idx_x / 8;
            auto offset_x = bit_idx_x & 0x7;
            auto byte_idx_y = bit_idx_y / 8;
            auto offset_y = bit_idx_y & 0x7;

            if((b_array[byte_idx_x] >> offset_x) & 1) {
                x++;
            }
            if((b_array[byte_idx_y] >> offset_y) & 1) {
                y++;
            }
        }
        out[i] = (q_modulo + x - y) % q_modulo;
    }
    return out;
}

int modexp(int base, int exp, int mod) {
    int result = 1;
    base %= mod;
    while(exp > 0) {
        if(exp & 1) {
            result = (1ll * base * result) % mod;
        }
        base = (1ll * base * result);
        exp >>= 1;
    }
    return result;
}

int bit_rev_7(int i) {
    return ((i >> 0) & 1) << 6 |
           ((i >> 1) & 1) << 5 |
           ((i >> 2) & 1) << 4 |
           ((i >> 3) & 1) << 3 |
           ((i >> 4) & 1) << 2 |
           ((i >> 5) & 1) << 1 |
           ((i >> 6) & 1) << 0;
}

int zeta_exp_bit_rev_7(int i) {
    auto rev = bit_rev_7(i);
    return modexp(zeta_q, rev, q_modulo);
}

cyclotomic_poly NTT(cyclotomic_poly f) {
    int i = 0;
    for(int len = 128; len >= 2; len >>= 1) {
        for(int start = 0; start < 256; start += (2 * len)) {
            auto zeta = zeta_exp_bit_rev_7(i);
            i++;
            for(auto j = start; j < start + len; j++) {
                auto t = zeta * f[j + len];
                f[j + len] = f[j] - t;
                f[j] += t;
            }
        }
    }
    return f;
}

cyclotomic_poly invNTT(cyclotomic_poly f) {
    int i = 127;
    for(int len = 2; len <= 128; len <<= 1) {
        for(int start = 0; start < n_len; start += 2 * len) {
            auto zeta = zeta_exp_bit_rev_7(i);
            i--;
            for(auto j = start; j < start + len; j++) {
                auto t = f[j];
                f[j] = t + f[j + len];
                f[j + len] = zeta * (f[j + len] - t);
            }
        }
    }
    for(int i = 0; i < n_len; i++) {
        f[i] *= 3303;
        f[i] %= q_modulo;
    }
    return f;
}

cyclotomic_poly multiply_NTT(cyclotomic_poly f_hat, cyclotomic_poly g_hat) {
    cyclotomic_poly h_hat;
    for(int i = 0; i < 128; i ++) { 
        auto revs = 2*bit_rev_7(i)+1;
        auto root = modexp(zeta_q, revs, q_modulo);
        auto [ c0, c1 ] = base_case_multiply(f_hat[2*i], f_hat[2*i + 1], g_hat[2*i], g_hat[2*i + 1], root);
        h_hat[2 * i] = c0;
        h_hat[2 * i + 1] = c1;
    }
    return h_hat;
}

cyclotomic_poly add_NTT(cyclotomic_poly f_hat, cyclotomic_poly g_hat) {
    cyclotomic_poly res;
    for(int i = 0; i < n_len; i++) {
        res[i] = f_hat[i] + g_hat[i];
    }
    return res;
}

std::pair<int, int> base_case_multiply(int64_t a0, int64_t a1, int64_t b0, int64_t b1, int64_t gamma) {
    auto c0 = (a0 * b0 + a1 * b1 * gamma) % q_modulo;
    auto c1 =(a0 * b1 + a1 * b0) % q_modulo;
    return {c0 , c1};
}

void prepare_matrix_A(uint8_t k, std::span<const uint8_t, 32> rho, std::span<cyclotomic_poly> A_buffer) {
    assert(A_buffer.size() >= k * k);
    for(uint8_t i = 0; i < k; i++) {
        for(uint8_t j = 0; j < k; j++) {
            A_buffer[i * k + j] = sample_NTT(rho, i, j);
        }
    }
}

void mmul_with_error(uint8_t k, std::span<cyclotomic_poly> A_matrix, std::span<cyclotomic_poly> s_polys, std::span<cyclotomic_poly> e_polys, std::span<cyclotomic_poly> t_polys) {
    for (int i = 0; i < k; i++) {
        cyclotomic_poly acc {};
        for (int j = 0; j < k; j++) {
            auto product = multiply_NTT(A_matrix[i*k+j], s_polys[j]);
            acc = add_NTT(acc, product);
        }
        t_polys[i] = add_NTT(acc, e_polys[i]);
    }
}

void k_pke_key_gen(uint8_t k, std::array<uint8_t, 32> d, std::span<uint8_t> ek_PKE, std::span<uint8_t> dk_PKE, std::span<cyclotomic_poly> Ase_buffer, std::span<uint8_t> eta_buffer ) {
    assert(ek_PKE.size() >= serial_byte_len + seed_len);
    assert(dk_PKE.size() >= serial_byte_len);
    assert(Ase_buffer.size() >= k * (k+3));
    assert(eta_buffer.size() >= k * seed_len);
    
    keccak_sponge bobleponge;
    bobleponge.absorb(d.data(), d.size());
    bobleponge.absorb(&k, 1);
    std::array<uint8_t, 32> rho;
    std::array<uint8_t, 32> sigma;
    auto A_buffer = Ase_buffer.subspan(0, k*k);
    auto s_polys = Ase_buffer.subspan(k*k, k);
    auto e_polys = Ase_buffer.subspan(k*(k+1), k);
    auto t_buffer = Ase_buffer.subspan(k*(k+2), k);
    bobleponge.squeeze(rho.data(), rho.size());
    bobleponge.squeeze(sigma.data(), sigma.size());

    prepare_matrix_A(k, rho, A_buffer);
    uint8_t N = 0;
    sample_vector_poly_CBD(k, sigma, N, s_polys, eta_buffer);
    sample_vector_poly_CBD(k, sigma, N, e_polys, eta_buffer);
    for(int i = 0; i < k; i++) {
        s_polys[i] = NTT(s_polys[i]);
        e_polys[i] = NTT(e_polys[i]);
    }
    mmul_with_error(k, A_buffer, s_polys, e_polys, t_buffer);
    for(int i = 0; i < k; i++) {
        auto ek_bytes = byte_encode(t_buffer[i]);
        auto dk_bytes = byte_encode(s_polys[i]);
        std::copy(ek_bytes.begin(), ek_bytes.end(), ek_PKE.begin() + (serial_byte_len * i));
        std::copy(dk_bytes.begin(), dk_bytes.end(), dk_PKE.begin() + (serial_byte_len * i));
    }
    std::copy(rho.begin(), rho.begin() + 32, ek_PKE.begin() + (serial_byte_len * k));
    return;
}

cyclotomic_poly sample_poly_CBD_seed(uint8_t k, std::span<uint8_t> seed, uint8_t& N, std::span<uint8_t> eta_buffer) {
    keccak_sponge prf;
    prf.absorb(seed.data(), seed.size());
    prf.absorb(&N, 1);
    N++;
    prf.squeeze(eta_buffer.data(), eta_buffer.size());
    return sample_poly_CBD(k, eta_buffer);
}

void sample_vector_poly_CBD(uint8_t k, std::span<uint8_t> iv, uint8_t& number_once_counter, std::span<cyclotomic_poly> s_out, std::span<uint8_t> eta_buffer) {
    for(int i = 0; i < k; i++) {
        s_out[i] = sample_poly_CBD_seed(k, iv, number_once_counter, eta_buffer);
    }
}

int decompress_d(uint32_t y, uint32_t d) {
    assert(d <= 12);
    assert(y < (1u << d));
    return (q_modulo * y + (1 << (d - 1))) >> d;
}

uint32_t compress_d(uint32_t x, uint32_t d) {
    uint32_t scale = 1u << d;
    return (static_cast<uint64_t>(x) * scale + q_modulo / 2) / q_modulo;
}

cyclotomic_poly decompress_poly(cyclotomic_poly poly, uint32_t d) {
    cyclotomic_poly out;
    for(int i = 0; i < n_len; i++) {
        out[i] = decompress_d(poly[i], d);
    }
    return out;
}

cyclotomic_poly compress_poly(cyclotomic_poly poly, uint32_t d) {
    cyclotomic_poly out;
    for(int i = 0; i < n_len; i++) {
        out[i] = compress_d(poly[i], d);
    }
    return out;
}

void k_pke_encrypt(uint8_t k, std::span<uint8_t> ek_PKE, std::array<uint8_t, 32> message, std::array<uint8_t, 32> randomness, std::span<uint8_t> ciphertext, std::span<cyclotomic_poly> Aty_buffer, std::span<uint8_t> eta_buffer, std::span<uint8_t> c_out) {
    assert(ek_PKE.size() >= k * serial_byte_len);
    assert(Aty_buffer.size() > k*(k+4));
    auto A_matrix = Aty_buffer.subspan(0, k*k);
    auto t_buffer = Aty_buffer.subspan(k*k, k);
    auto y_buffer = Aty_buffer.subspan(k*(k+1), k);
    auto e_buffer = Aty_buffer.subspan(k*(k+2), k);
    auto u_polys = Aty_buffer.subspan(k*(k+3), k);

    for(int i = 0; i < k; i++) {
        std::span<uint8_t, serial_byte_len> subsp (ek_PKE.data() + serial_byte_len * i, serial_byte_len * (i+1));
        A_matrix[i] = byte_decode(subsp, 12);
    }
    auto rho = std::span<const uint8_t, 32>(ek_PKE.subspan(serial_byte_len * k, 32));
    prepare_matrix_A(k, rho, A_matrix);

    uint8_t N = 0;
    sample_vector_poly_CBD(k, randomness, N, y_buffer, eta_buffer);
    sample_vector_poly_CBD(k, randomness, N, e_buffer, eta_buffer);
    
    auto e2 = sample_poly_CBD_seed(k, randomness, N, eta_buffer);

    for(int i = 0; i < k; i++) {
        y_buffer[i] = NTT(y_buffer[i]);
    }

    for (int i = 0; i < k; i++) {
        cyclotomic_poly acc {};
        for (int j = 0; j < k; j++) {
            auto product = multiply_NTT(A_matrix[j*k+i], y_buffer[j]);
            invNTT(product);
            acc = add_NTT(acc, product);
        }
        u_polys[i] = add_NTT(acc, e_buffer[i]);
    }
    cyclotomic_poly mu = byte_decode(message, 1);
    mu = decompress_poly(mu, 1);

    cyclotomic_poly v{};
    for(int i = 0; i < k; i++) {
        auto product = multiply_NTT(t_buffer[i], y_buffer[i]);
        v = add_NTT(v, product);
    }
    v = invNTT(v);
    v = add_NTT(v, e2);
    v = add_NTT(v, mu);

    for(int i = 0; i < k; i++) {
        auto c1 = byte_encode(compress_poly(u_polys[i], 12));
        std::copy(c1.begin(), c1.end(), c_out.begin() + (i * c1.size()));
    }
    auto c2 = byte_encode(compress_poly(v, 12));
    std::copy(c2.begin(), c2.end(), c_out.begin() + (k * c2.size()));
}

}
