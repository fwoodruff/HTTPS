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
#include "../one_way/keccak.hpp"

namespace fbw::mlkem {

constexpr int32_t q_modulo = 3299;
constexpr int32_t d_bitlen = 12;
constexpr int32_t n_len = 256;
constexpr int32_t zeta_q = 17;
constexpr int32_t seed_len = 32;
constexpr int32_t serial_byte_len = (n_len * d_bitlen/8);

using cyclotomic_poly = std::array<int32_t, 256>;

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf

// Encodes an array of d-bit integers into a byte array for 1 <= d <= 12
std::array<uint8_t, serial_byte_len> byte_encode(cyclotomic_poly F_poly);

// Decodes a byte array into an array of d-bit integers for 1 <= d <= 12
cyclotomic_poly byte_decode(std::span<uint8_t> serial_F_poly, uint32_t d);

// Takes a 32-byte seed and two indices as input and outputs a pseudorandom element if T_q
cyclotomic_poly sample_NTT(std::span<const uint8_t, 32> seed_idx, uint8_t ii, uint8_t jj);

// Takes a seed as input and outputs a pseudorandom sample from the distribution D_eta(R_q)
cyclotomic_poly sample_poly_CBD(uint8_t k, std::span<const uint8_t> b_array);

// Computes the NTT representation f_hat of a given polynomial f in R_q
cyclotomic_poly NTT(cyclotomic_poly f);

// Computes the polynomial f in R_q that corresponds to a given NTT representation f_hat in T_q
cyclotomic_poly invNTT(cyclotomic_poly f_hat);

// Computes the product (in the ring T_q) of two NTT representations
cyclotomic_poly multiply_NTT(cyclotomic_poly f_hat, cyclotomic_poly g_hat);

// Computes the product of two degree-one polynomials with respect to a quadratic modulus
std::pair<int, int> base_case_multiply(int64_t a0, int64_t a1, int64_t b0, int64_t b1, int64_t gamma);

// Uses randomness to generate an encryption key and a corresponding decryption key
void k_pke_key_gen(uint8_t k, std::array<uint8_t, 32> d, std::span<uint8_t> ek_PKE, std::span<uint8_t> dk_PKE, std::span<cyclotomic_poly> Ase_buffer, std::span<uint8_t> eta_buffer ) ;

void sample_vector_poly_CBD(uint8_t k, std::span<uint8_t> iv, uint8_t& number_once_counter, std::span<cyclotomic_poly> s_out, std::span<uint8_t> eta_buffer);

// Uses the encryption key to encrypt a plaintext message using the randomness
void k_pke_encrypt(uint8_t k, std::span<uint8_t> ek_PKE, std::array<uint8_t, 32> message, std::array<uint8_t, 32> randomness, std::span<uint8_t> ciphertext, std::span<cyclotomic_poly> Aty_buffer, std::span<uint8_t> eta_buffer, std::span<uint8_t> c_out);

}

#endif