//
//  mlkem.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 20/07/2025.
//

#ifndef mlkem_hpp
#define mlkem_hpp

#include <array>
#include <span>
#include <utility>
#include "../one_way/keccak.hpp"
#include <print>

namespace fbw::mlkem {

constexpr int32_t q_modulo = 3329;
constexpr int32_t d_bitlen = 12;
constexpr int32_t n_len = 256;
constexpr int32_t zeta_q = 17;
constexpr int32_t entropy_length = 32;
constexpr int32_t serial_byte_len = ((n_len * d_bitlen + 7)/8);

constexpr int32_t inv128_q = 3303;

struct kyber_parameters {
    uint8_t k;
    uint8_t eta_1;
    uint8_t eta_2;
    uint8_t d_u;
    uint8_t d_v;
};

constexpr kyber_parameters params512 {
    .k = 2,
    .eta_1 = 3,
    .eta_2 = 2,
    .d_u = 10,
    .d_v = 4
};

constexpr kyber_parameters params768 {
    .k = 3,
    .eta_1 = 2,
    .eta_2 = 2,
    .d_u = 10,
    .d_v = 4
};

constexpr kyber_parameters params1024 {
    .k = 4,
    .eta_1 = 2,
    .eta_2 = 2,
    .d_u = 11,
    .d_v = 5
};

template<kyber_parameters Params>
constexpr int32_t dk_size = (serial_byte_len * Params.k*2) + (3*entropy_length);

template<kyber_parameters Params>
constexpr int32_t ciphertext_size = (n_len / 8) * (Params.d_u * Params.k + Params.d_v);

template<kyber_parameters Params>
constexpr int32_t ek_size = (serial_byte_len * Params.k) + entropy_length;

template<kyber_parameters Params>
using private_decapsulation = std::array<uint8_t, dk_size<Params>>;

template<kyber_parameters Params>
using public_encapsulation = std::array<uint8_t, ek_size<Params>>;

template<kyber_parameters Params>
using ciphertext = std::array<uint8_t, ciphertext_size<Params>>;

using shared_secret = std::array<uint8_t, entropy_length>;
using cyclotomic_polynomial = std::array<int32_t, n_len>;

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf

// Encodes an array of d-bit integers into a byte array for 1 <= d <= 12.
void byte_encode(uint8_t d_bits, cyclotomic_polynomial F_poly, std::span<uint8_t> b_out);

// Decodes a byte array into an array of d-bit integers for 1 <= d <= 12.
cyclotomic_polynomial byte_decode(std::span<uint8_t> serial_F_poly, uint32_t d_bits);

// Takes a 32-byte seed and two indices as input and outputs a pseudorandom element if T_q.
cyclotomic_polynomial sample_NTT(std::span<const uint8_t, entropy_length> seed_idx, uint8_t i_idx, uint8_t j_idx);

// Takes a seed as input and outputs a pseudorandom sample from the distribution D_eta(R_q).
cyclotomic_polynomial sample_poly_CBD(uint8_t k_param, std::span<const uint8_t> b_array);

// Computes the NTT representation f_hat of a given polynomial f in R_q.
cyclotomic_polynomial NTT(cyclotomic_polynomial f_poly);

// Computes the polynomial f in R_q that corresponds to a given NTT representation f_hat in T_q.
cyclotomic_polynomial invNTT(cyclotomic_polynomial f_hat);

// Computes the product (in the ring T_q) of two NTT representations.
cyclotomic_polynomial multiply_NTT(cyclotomic_polynomial f_hat, cyclotomic_polynomial g_hat);

// Computes the product of two degree-one polynomials with respect to a quadratic modulus.
std::pair<int, int> base_case_multiply(int64_t a_poly0, int64_t a_poly1, int64_t b_poly0, int64_t b_poly1, int64_t gamma);

// Uses randomness to generate an encryption key and a corresponding decryption key.
void k_pke_key_gen(kyber_parameters params, std::array<uint8_t, entropy_length> d_rand, std::span<uint8_t> ek_PKE, std::span<uint8_t> dk_PKE, std::span<cyclotomic_polynomial> Ase_buffer, std::span<uint8_t> eta_buffer );

void sample_vector_poly_CBD(uint8_t k_param, uint8_t eta, std::span<uint8_t> init_vec, uint8_t& number_once_counter, std::span<cyclotomic_polynomial> s_out, std::span<uint8_t> eta_buffer) ;

// Uses the encryption key to encrypt a plaintext message using the randomness.
void k_pke_encrypt(kyber_parameters params, std::span<uint8_t> ek_PKE, std::array<uint8_t, entropy_length> message, std::array<uint8_t, entropy_length> randomness, std::span<cyclotomic_polynomial> Aty_buffer, std::span<uint8_t> eta_buffer, std::span<uint8_t> c_out);

// Uses the decryption key to decrypt a ciphertext.
std::array<uint8_t, entropy_length> k_pke_decrypt(kyber_parameters params, std::span<uint8_t> dk_PKE, std::span<uint8_t> ciphertext, std::span<cyclotomic_polynomial> us_buffer);

// Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
void ml_kem_key_gen_internal(kyber_parameters params, std::array<uint8_t, entropy_length> d_rand, std::array<uint8_t, entropy_length> z, std::span<uint8_t> ek, std::span<uint8_t> dk, std::span<cyclotomic_polynomial> Ase_buffer, std::span<uint8_t> eta_buffer);

void ml_kem_encaps_internal(kyber_parameters params, std::span<uint8_t> ek, std::array<uint8_t, entropy_length> message, std::array<uint8_t, entropy_length>& shared_key, std::span<uint8_t> cipher_text, std::span<cyclotomic_polynomial> Aty_buffer, std::span<uint8_t> eta_buffer );

shared_secret ml_kem_decaps_internal(kyber_parameters params, std::span<uint8_t> dk, std::span<uint8_t> ciphertext, std::span<cyclotomic_polynomial> Aty_buffer, std::span<uint8_t> cipher_eta_buffer);

bool encaps_input_sanitise(kyber_parameters params, std::span<const uint8_t> ek);

template<kyber_parameters Params>
std::pair<public_encapsulation<Params>, private_decapsulation<Params>> generate_key_pair() {
    std::array<uint8_t, entropy_length> d_rand;
    std::array<uint8_t, entropy_length> z_rand;
    randomgen.randgen(d_rand);
    randomgen.randgen(z_rand);
    public_encapsulation<Params> encapsulation_key; // public
    private_decapsulation<Params> decapsulation_key; // private
    constexpr auto k_buffer_size = static_cast<const size_t>(Params.k * (Params.k+4));
    std::array<cyclotomic_polynomial, k_buffer_size> Ase_buffer;
    constexpr auto A_buffer_size = static_cast<size_t>(2 * entropy_length * Params.eta_1);
    std::array<uint8_t, A_buffer_size> eta_buffer;
    ml_kem_key_gen_internal(Params, d_rand, z_rand, encapsulation_key, decapsulation_key, Ase_buffer, eta_buffer);
    return { encapsulation_key, decapsulation_key};
}

template<kyber_parameters Params>
std::tuple<shared_secret, ciphertext<Params>, bool> encapsulate_secret(public_encapsulation<Params> encapsulation_key) {
    std::array<uint8_t, entropy_length> message;
    randomgen.randgen(message);
    shared_secret shared_key;
    ciphertext<Params> ciphertext;
    constexpr auto k_buffer_size = static_cast<size_t>(Params.k*(Params.k+4));
    std::array<cyclotomic_polynomial, k_buffer_size> Ase_buffer;
    constexpr auto max_eta = 2 * entropy_length * std::max(Params.eta_1, Params.eta_2);
    std::array<uint8_t, max_eta> eta_buffer;
    if(!encaps_input_sanitise(Params, encapsulation_key)) {
        return { {}, {}, false };
    }
    ml_kem_encaps_internal(Params, encapsulation_key, message, shared_key, ciphertext, Ase_buffer, eta_buffer);
    return {shared_key, ciphertext, true};
}

template<kyber_parameters Params>
shared_secret decapsulate_secret(private_decapsulation<Params> decapsulation_key, ciphertext<Params> ciphertext) {
    shared_secret secret_key;
    constexpr auto k_buffer_size = static_cast<size_t>(Params.k*(Params.k+4));
    std::array<cyclotomic_polynomial, k_buffer_size> Ase_buffer;

    constexpr auto max_eta = entropy_length * 2 * std::max(Params.eta_1, Params.eta_2);
    constexpr auto c_size =  entropy_length * (Params.d_u * Params.k + Params.d_v);
    std::array<uint8_t, max_eta + c_size > eta_buffer;
    return ml_kem_decaps_internal(Params, decapsulation_key, ciphertext, Ase_buffer, eta_buffer);
    return secret_key;
}

}

#endif