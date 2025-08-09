//
//  mlkem.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 20/07/2025.
//

#include "mlkem.hpp"

#include <array>
#include <cassert>
#include <algorithm>
#include <print>

namespace fbw::mlkem {

void byte_encode(uint8_t d, cyclotomic_polynomial F_poly, std::span<uint8_t> b_out) {
    assert(b_out.size() == size_t(n_len * d + 7)/8);
    std::fill(b_out.begin(), b_out.end(), 0);
    for(int i = 0; i < n_len; i ++ ) {
        int a = F_poly[i];
        assert(a >= 0);
        assert(a < (1<<d));
        assert(a < q_modulo);
        for(int j = 0; j < d; j++) {
            auto bit_idx = i * d + j;
            auto byte_idx = bit_idx / 8;
            b_out[byte_idx] |= (a & 1) << (bit_idx % 8);
            a >>= 1;
        }
    }
}

cyclotomic_polynomial byte_decode(std::span<uint8_t> serial_F_poly, uint32_t d) {
    assert(serial_F_poly.size() == (n_len * d + 7)/8);
    cyclotomic_polynomial F_poly;
    const int m = (d < 12) ? (1 << d) : q_modulo;
    
    for (int i = 0; i < n_len; i++) {
        uint32_t val = 0;
        for (unsigned j = 0; j < d; j++) {
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

cyclotomic_polynomial sample_NTT(std::span<const uint8_t, entropy_length> seed_idx, uint8_t ii, uint8_t jj) {
    fbw::keccak_sponge ctx(256, 0x1F);
    cyclotomic_polynomial out;
    ctx.absorb(seed_idx.data(), seed_idx.size());
    ctx.absorb(&jj, 1);
    ctx.absorb(&ii, 1);
    int j = 0;
    while(j < n_len) {
        // hot loop
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

cyclotomic_polynomial sample_poly_CBD(uint8_t eta, std::span<const uint8_t> eta_buffer) {
    assert(eta_buffer.size() == eta * n_len / 4);
    cyclotomic_polynomial out;
    assert(eta_buffer.size() == eta * entropy_length * 2);
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

            auto xbit = (eta_buffer[byte_idx_x] >> offset_x) & 1;
            x += xbit;
            auto ybit = (eta_buffer[byte_idx_y] >> offset_y) & 1;
            y += ybit;
        }
        out[i] = (q_modulo + x - y) % q_modulo;
    }
    return out;
}

constexpr int modexp(int base, int exp, int mod) {
    int result = 1;
    base %= mod;
    while(exp > 0) {
        if(exp & 1) {
            result = (1ll * base * result) % mod;
        }
        base = (1ll * base * base) % mod;
        exp >>= 1;
    }
    return result;
}

constexpr int bit_rev_7(int i) {
    return ((i >> 0) & 1) << 6 |
           ((i >> 1) & 1) << 5 |
           ((i >> 2) & 1) << 4 |
           ((i >> 3) & 1) << 3 |
           ((i >> 4) & 1) << 2 |
           ((i >> 5) & 1) << 1 |
           ((i >> 6) & 1) << 0;
}

constexpr int zeta_exp_bit_rev_7(int i) {
    auto rev = bit_rev_7(i);
    return modexp(zeta_q, rev, q_modulo);
}

constexpr auto zeta_exp_bit_rev_7_arr = []{
    std::array<int, 128> out;
    for(unsigned i = 0; i < out.size(); i++) {
        out[i] = zeta_exp_bit_rev_7(i);
    }
    return out;
}();

cyclotomic_polynomial NTT(cyclotomic_polynomial f) {
    int i = 1;
    for(int len = 128; len >= 2; len >>= 1) {
        for(int start = 0; start < 256; start += (2 * len)) {
            assert(i < 128);
            auto zeta = zeta_exp_bit_rev_7_arr[i];
            i++;
            for(auto j = start; j < start + len; j++) {
                auto t = (zeta * f[j + len]) % q_modulo;
                f[j + len] = (f[j] + q_modulo - t) % q_modulo;
                f[j] = (f[j] + t) % q_modulo;
            }
        }
    }
    return f;
}

cyclotomic_polynomial neg(cyclotomic_polynomial f) {
    for(size_t i = 0; i < f.size(); i ++) {
        f[i] = (q_modulo-f[i]) % q_modulo;
    }
    return f;
}

cyclotomic_polynomial invNTT(cyclotomic_polynomial f) {
    int i = 127;
    for(int len = 2; len <= 128; len <<= 1) {
        for(int start = 0; start < n_len; start += 2 * len) {
            auto zeta = zeta_exp_bit_rev_7(i);
            i--;
            for(auto j = start; j < start + len; j++) {
                auto t = f[j];
                f[j] = (t + f[j + len]) % q_modulo;
                auto diff = (f[j + len] + q_modulo - t) % q_modulo;
                f[j + len] = (zeta * diff) % q_modulo;
            }
        }
    }
    for(int i = 0; i < n_len; i++) {
        f[i] *=  inv128_q;
        f[i] %= q_modulo;
    }
    return f;
}

cyclotomic_polynomial multiply_NTT(cyclotomic_polynomial f_hat, cyclotomic_polynomial g_hat) {
    cyclotomic_polynomial h_hat;
    for(int i = 0; i < 128; i ++) { 
        auto revs = 2*bit_rev_7(i)+1;
        auto root = modexp(zeta_q, revs, q_modulo);
        auto [ c0, c1 ] = base_case_multiply(f_hat[2*i], f_hat[2*i + 1], g_hat[2*i], g_hat[2*i + 1], root);
        h_hat[2 * i] = c0;
        h_hat[2 * i + 1] = c1;
    }
    return h_hat;
}

cyclotomic_polynomial add_poly(cyclotomic_polynomial f_hat, cyclotomic_polynomial g_hat) {
    cyclotomic_polynomial res;
    for(int i = 0; i < n_len; i++) {
        assert(f_hat[i] >= 0);
        assert(g_hat[i] >= 0);
        res[i] = (f_hat[i] + g_hat[i]) % q_modulo;
    }
    return res;
}

std::pair<int, int> base_case_multiply(int64_t a0, int64_t a1, int64_t b0, int64_t b1, int64_t gamma) {
    auto c0 = (a0 * b0 + a1 * b1 * gamma) % q_modulo;
    auto c1 =(a0 * b1 + a1 * b0) % q_modulo;
    return {c0 , c1};
}

void prepare_matrix_A(uint8_t k, std::span<const uint8_t, entropy_length> rho, std::span<cyclotomic_polynomial> A_buffer) {
    assert(A_buffer.size() == k * k);
    for(uint8_t i = 0; i < k; i++) {
        for(uint8_t j = 0; j < k; j++) {
            A_buffer[i * k + j] = sample_NTT(rho, i, j);
        }
    }
}

void mmul_with_error(uint8_t k, std::span<cyclotomic_polynomial> A_matrix, std::span<cyclotomic_polynomial> s_polys, std::span<cyclotomic_polynomial> e_polys, std::span<cyclotomic_polynomial> t_polys) {
    for (int i = 0; i < k; i++) {
        cyclotomic_polynomial acc {};
        for (int j = 0; j < k; j++) {
            auto product = multiply_NTT(A_matrix[i*k+j], s_polys[j]);
            acc = add_poly(acc, product);
        }
        t_polys[i] = add_poly(acc, e_polys[i]);
    }
}

void k_pke_key_gen(kyber_parameters params, std::array<uint8_t, entropy_length> d, std::span<uint8_t> ek_PKE, std::span<uint8_t> dk_PKE, std::span<cyclotomic_polynomial> Ase_buffer, std::span<uint8_t> eta_buffer ) {
    assert(ek_PKE.size() == size_t(serial_byte_len * params.k + entropy_length));
    assert(dk_PKE.size() == size_t(serial_byte_len * params.k));
    assert(Ase_buffer.size() == size_t(params.k * (params.k+4)));
    assert(eta_buffer.size() == size_t(params.eta_1 * entropy_length * 2));
    
    keccak_sponge bobleponge(1024, 0x06);
    bobleponge.absorb(d.data(), d.size());
    bobleponge.absorb(&params.k, 1);
    std::array<uint8_t, entropy_length> rho;
    std::array<uint8_t, entropy_length> sigma;
    auto A_buffer = Ase_buffer.subspan(0, params.k*params.k);
    auto s_polys = Ase_buffer.subspan(params.k* params.k, params.k);
    auto e_polys = Ase_buffer.subspan(params.k*(params.k+1), params.k);
    auto t_buffer = Ase_buffer.subspan(params.k*(params.k+2), params.k);
    bobleponge.squeeze(rho.data(), rho.size());
    bobleponge.squeeze(sigma.data(), sigma.size());

    prepare_matrix_A(params.k, rho, A_buffer);
    uint8_t N = 0;
    sample_vector_poly_CBD(params.k, params.eta_1, sigma, N, s_polys, eta_buffer);
    sample_vector_poly_CBD(params.k, params.eta_1, sigma, N, e_polys, eta_buffer);
    for(int i = 0; i < params.k; i++) {
        s_polys[i] = NTT(s_polys[i]);
        e_polys[i] = NTT(e_polys[i]);
    }
    mmul_with_error(params.k, A_buffer, s_polys, e_polys, t_buffer);
    for(int i = 0; i < params.k; i++) {
        auto ek_span = ek_PKE.subspan(serial_byte_len * i, serial_byte_len);
        auto dk_span = dk_PKE.subspan(serial_byte_len * i, serial_byte_len);
        byte_encode(12, t_buffer[i], ek_span);
        byte_encode(12, s_polys[i], dk_span);
    }
    std::copy(rho.begin(), rho.end(), ek_PKE.begin() + (serial_byte_len * params.k));
    return;
}

cyclotomic_polynomial sample_poly_CBD_seed(uint8_t eta, std::span<uint8_t> seed, uint8_t& N, std::span<uint8_t> eta_buffer) {
    keccak_sponge prf(512, 0x1F);
    prf.absorb(seed.data(), seed.size());
    prf.absorb(&N, 1);
    N++;
    prf.squeeze(eta_buffer.data(), eta_buffer.size());
    return sample_poly_CBD(eta, eta_buffer);
}

void sample_vector_poly_CBD(uint8_t k, uint8_t eta, std::span<uint8_t> iv, uint8_t& number_once_counter, std::span<cyclotomic_polynomial> s_out, std::span<uint8_t> eta_buffer) {
    for(int i = 0; i < k; i++) {
        s_out[i] = sample_poly_CBD_seed(eta, iv, number_once_counter, eta_buffer);
    }
}

int decompress_d(int32_t y, uint32_t d) {
    assert(d <= 12);
    assert(y < int32_t(1u << d));
    return (q_modulo * y + (1 << (d - 1))) >> d;
}

uint32_t compress_d(int32_t x, uint32_t d) {
    uint32_t scale = (1u << d);
    int32_t t = x % int32_t(q_modulo);
    int32_t w = (t + q_modulo) % q_modulo;
    auto out =  (w * scale + q_modulo / 2) / q_modulo;
    return out % scale;
}

cyclotomic_polynomial decompress_poly(cyclotomic_polynomial poly, uint32_t d) {
    cyclotomic_polynomial out;
    for(int i = 0; i < n_len; i++) {
        out[i] = decompress_d(poly[i], d);
    }
    return out;
}

cyclotomic_polynomial compress_poly(cyclotomic_polynomial poly, uint32_t d) {
    cyclotomic_polynomial out;
    for(int i = 0; i < n_len; i++) {
        out[i] = compress_d(poly[i], d);
    }
    return out;
}

void k_pke_encrypt(kyber_parameters params, std::span<uint8_t> ek_PKE, std::array<uint8_t, entropy_length> message, std::array<uint8_t, entropy_length> randomness, std::span<cyclotomic_polynomial> Aty_buffer, std::span<uint8_t> eta_buffer, std::span<uint8_t> c_out) {
    assert(ek_PKE.size() == size_t(params.k * serial_byte_len + entropy_length));
    assert(Aty_buffer.size() == size_t(params.k*(params.k+4)));
    assert(c_out.size() == size_t(entropy_length * (params.d_u * params.k + params.d_v)));
    assert(eta_buffer.size() == entropy_length * 2 * std::max(params.eta_1, params.eta_2));
    auto A_matrix = Aty_buffer.subspan(0, params.k*params.k);
    auto t_buffer = Aty_buffer.subspan(params.k*params.k, params.k);
    auto y_span = Aty_buffer.subspan(params.k*(params.k+1), params.k);
    auto e_span = Aty_buffer.subspan(params.k*(params.k+2), params.k);
    auto u_polys = Aty_buffer.subspan(params.k*(params.k+3), params.k);
    auto eta_1_buffer = eta_buffer.subspan(0, entropy_length * 2 * params.eta_1);
    auto eta_2_buffer = eta_buffer.subspan(0, entropy_length * 2 * params.eta_2); // reused

    for(int i = 0; i < params.k; i++) {
        std::span<uint8_t, serial_byte_len> subsp (ek_PKE.data() + serial_byte_len * i, serial_byte_len);
        t_buffer[i] = byte_decode(subsp, 12);
    }
    auto rho = std::span<const uint8_t, entropy_length>(ek_PKE.subspan(serial_byte_len * params.k, entropy_length));
    prepare_matrix_A(params.k, rho, A_matrix);

    uint8_t N = 0;
    sample_vector_poly_CBD(params.k, params.eta_1, randomness, N, y_span, eta_1_buffer);
    sample_vector_poly_CBD(params.k, params.eta_2, randomness, N, e_span, eta_2_buffer);
    
    auto e2 = sample_poly_CBD_seed(params.eta_2, randomness, N, eta_2_buffer);

    for(int i = 0; i < params.k; i++) {
        y_span[i] = NTT(y_span[i]);
    }

    for (int i = 0; i < params.k; i++) {
        cyclotomic_polynomial acc {};
        for (int j = 0; j < params.k; j++) {
            auto product = multiply_NTT(A_matrix[j*params.k+i], y_span[j]);
            acc = add_poly(acc, product);
        }
        acc = invNTT(acc);
        u_polys[i] = add_poly(acc, e_span[i]);
    }
    auto mu = decompress_poly(byte_decode(message, 1), 1);

    cyclotomic_polynomial v{};
    for(int i = 0; i < params.k; i++) {
        auto product = multiply_NTT(t_buffer[i], y_span[i]);
        v = add_poly(v, product);
    }
    v = invNTT(v);
    v = add_poly(v, e2);
    v = add_poly(v, mu);

    for(int i = 0; i < params.k; i++) {
        byte_encode(params.d_u, compress_poly(u_polys[i], params.d_u), c_out.subspan(i * entropy_length * params.d_u, entropy_length * params.d_u));
    }
    byte_encode(params.d_v, compress_poly(v, params.d_v), c_out.subspan(entropy_length * params.k * params.d_u));
}

std::array<uint8_t, entropy_length> k_pke_decrypt(kyber_parameters params, std::span<uint8_t> dk_PKE, std::span<uint8_t> ciphertext, std::span<cyclotomic_polynomial> us_buffer) {
    std::array<uint8_t, entropy_length> message;
    auto c1_len = entropy_length * params.d_u * params.k;
    auto c1 = ciphertext.subspan(0, c1_len);
    auto c2 = ciphertext.subspan(c1_len);

    auto u_prime = us_buffer.subspan(0, params.k);
    auto s_hat = us_buffer.subspan(params.k, params.k);

    for(int i = 0; i < params.k; i++) {
       u_prime[i] = decompress_poly(byte_decode(c1.subspan(i * entropy_length * params.d_u, entropy_length * params.d_u), params.d_u), params.d_u);
    }
    auto v_prime = decompress_poly(byte_decode(c2, params.d_v), params.d_v);
    for(int i = 0; i < params.k; i++) {
       s_hat[i] = byte_decode(dk_PKE.subspan(i* serial_byte_len, serial_byte_len), 12);
    }
    cyclotomic_polynomial acc {};
    for(int i = 0; i < params.k; i++) {
        acc = add_poly(acc, multiply_NTT(s_hat[i], NTT(u_prime[i])));
    }
    auto w = add_poly(v_prime, neg(invNTT(acc)));
    byte_encode(1, compress_poly(w, 1), message);
    return message;
}

void ml_kem_key_gen_internal(kyber_parameters params, std::array<uint8_t, entropy_length> d, std::array<uint8_t, entropy_length> z, std::span<uint8_t> ek, std::span<uint8_t> dk, std::span<cyclotomic_polynomial> Ase_buffer, std::span<uint8_t> eta_buffer) {
    auto k_bytelen = serial_byte_len * params.k;
    assert(ek.size() == size_t(k_bytelen + entropy_length));
    assert(dk.size() == size_t(k_bytelen * 2 + 3 * entropy_length));
    auto dk_pke = dk.subspan(0, k_bytelen);
    k_pke_key_gen(params, d, ek, dk_pke, Ase_buffer, eta_buffer);
    std::copy(ek.begin(), ek.end(), dk.begin() + k_bytelen);

    keccak_sponge H(512, 0x06);
    H.absorb(ek.data(), ek.size());
    H.squeeze(dk.data() + k_bytelen + ek.size(), entropy_length);
    std::copy(z.begin(), z.end(), dk.begin() + k_bytelen + ek.size() + entropy_length);
}

void ml_kem_encaps_internal(kyber_parameters params, std::span<uint8_t> ek, std::array<uint8_t, entropy_length> message, std::array<uint8_t, entropy_length>& shared_key, std::span<uint8_t> cipher_text, std::span<cyclotomic_polynomial> Aty_buffer, std::span<uint8_t> eta_buffer ) {
    keccak_sponge hash_key(512, 0x06);
    keccak_sponge sponge(1024, 0x06);
    sponge.absorb(message.data(), message.size());
    hash_key.absorb(ek.data(), ek.size());
    std::array<uint8_t, entropy_length> tmp;
    hash_key.squeeze(tmp.data(), tmp.size());
    sponge.absorb(tmp.data(), tmp.size());
    sponge.squeeze(shared_key.data(), shared_key.size());
    std::array<uint8_t, entropy_length> rand;
    sponge.squeeze(rand.data(), rand.size());
    k_pke_encrypt(params, ek, message, rand, Aty_buffer, eta_buffer, cipher_text);
}

shared_secret ml_kem_decaps_internal(kyber_parameters params, std::span<uint8_t> dk, std::span<uint8_t> ciphertext, std::span<cyclotomic_polynomial> Aty_buffer, std::span<uint8_t> cipher_eta_buffer) {
    auto klen = serial_byte_len * params.k;
    assert(dk.size() == size_t(2 * klen + 3 * entropy_length));
    auto c_size = entropy_length * (params.d_u * params.k + params.d_v);
    auto dk_pke = dk.subspan(0, klen);
    auto ek_pke = dk.subspan(klen, klen + entropy_length);
    auto h = dk.subspan(klen * 2 + entropy_length, entropy_length);
    auto z = dk.subspan(klen * 2 + 2* entropy_length, entropy_length);
    auto us_buffer = Aty_buffer.subspan(0, params.k * 2);
    auto m_prime = k_pke_decrypt(params, dk_pke, ciphertext, us_buffer);

    auto c_prime = cipher_eta_buffer.subspan(0, c_size);
    auto max_eta = entropy_length * 2 * std::max(params.eta_1, params.eta_2);
    auto eta_buffer = cipher_eta_buffer.subspan(c_size, max_eta);
    assert(cipher_eta_buffer.size() == size_t(max_eta + c_size));
    keccak_sponge sponge(1024, 0x06);
    sponge.absorb(m_prime.data(), m_prime.size());
    sponge.absorb(h.data(), h.size());
    std::array<uint8_t, entropy_length> k_prime;
    std::array<uint8_t, entropy_length> r_prime;
    sponge.squeeze(k_prime.data(), k_prime.size());
    sponge.squeeze(r_prime.data(), r_prime.size());
    std::array<uint8_t, entropy_length> k_bar;
    keccak_sponge J(512, 0x1F);
    J.absorb(z.data(), z.size());
    J.absorb(ciphertext.data(), ciphertext.size());
    J.squeeze(k_bar.data(), k_bar.size());

    k_pke_encrypt(params, ek_pke, m_prime, r_prime, Aty_buffer, eta_buffer, c_prime);
    
    uint8_t diff = 0;
    for(size_t i = 0; i < ciphertext.size(); i++) {
        diff |= ciphertext[i] ^ c_prime[i];
    }
    uint8_t mask_prime = (diff == 0);
    uint8_t mask_bar = (diff != 0);
    mask_prime *= 0xff;
    mask_bar *= 0xff;
    for(int i = 0; i < entropy_length; i++) {
        k_prime[i] = (k_prime[i] & mask_prime) | (k_bar[i] & mask_bar);
    }
    return k_prime;
}

bool encaps_input_sanitise(kyber_parameters params, std::span<const uint8_t> ek) {
    const size_t t_len = serial_byte_len * params.k;
    const size_t expected = t_len + entropy_length;
    if (ek.size() != expected) {
        return false; 
    }
    for (size_t i = 0; i < t_len; i += 3) {
        uint16_t b0 = ek[i + 0];
        uint16_t b1 = ek[i + 1];
        uint16_t b2 = ek[i + 2];
        uint16_t a0 = b0 | ((b1 & 0x0Fu) << 8);
        uint16_t a1 = (b1 >> 4) | (b2 << 4);
        if(a0 >= q_modulo || a1 >= q_modulo) {
            // public value checks need not be constant time
            return false;
        }
    }
    return true;
}

}