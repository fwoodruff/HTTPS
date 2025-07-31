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

namespace fbw::mlkem {

constexpr int32_t q_modulo = 3299;
constexpr int32_t d_bitlen = 12;
constexpr int32_t n_len = 256;
constexpr int32_t zeta_q = 17;
constexpr int32_t seed_len = 32;
constexpr int32_t serial_byte_len = (n_len * d_bitlen/8);

constexpr int32_t dk512size = serial_byte_len * 2 + seed_len;
constexpr int32_t dk768size = serial_byte_len * 3 + seed_len;
constexpr int32_t dk1024size = serial_byte_len * 4 + seed_len;

constexpr int32_t ciphertext512size = 768;
constexpr int32_t ciphertext768size = 1088;
constexpr int32_t ciphertext1024size = 1568; // todo: calculate don't hardcode

constexpr int32_t ek512size = serial_byte_len * 4 + seed_len * 3;
constexpr int32_t ek768size = serial_byte_len * 6 + seed_len * 3;
constexpr int32_t ek1024size = serial_byte_len * 8 + seed_len * 3;

using ml_kem_512_pub = std::array<uint8_t, dk512size>;
using ml_kem_768_pub = std::array<uint8_t, dk768size>;
using ml_kem_1024_pub = std::array<uint8_t, dk1024size>;

using ml_kem_512_priv = std::array<uint8_t, ek512size>;
using ml_kem_768_priv = std::array<uint8_t, ek768size>;
using ml_kem_1024_priv = std::array<uint8_t, ek1024size>;

struct kyber_params {
    constexpr static uint8_t eta_2 = 2;
    uint8_t k;
    uint8_t eta_1;
    uint8_t d_u;
    uint8_t d_v;
};

using cyclotomic_poly = std::array<int32_t, 256>;

// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf

// Encodes an array of d-bit integers into a byte array for 1 <= d <= 12.
void byte_encode(uint8_t d, cyclotomic_poly F_poly, std::span<uint8_t> b_out);

// Decodes a byte array into an array of d-bit integers for 1 <= d <= 12.
cyclotomic_poly byte_decode(std::span<uint8_t> serial_F_poly, uint32_t d);

// Takes a 32-byte seed and two indices as input and outputs a pseudorandom element if T_q.
cyclotomic_poly sample_NTT(std::span<const uint8_t, 32> seed_idx, uint8_t ii, uint8_t jj);

// Takes a seed as input and outputs a pseudorandom sample from the distribution D_eta(R_q).
cyclotomic_poly sample_poly_CBD(uint8_t k, std::span<const uint8_t> b_array);

// Computes the NTT representation f_hat of a given polynomial f in R_q.
cyclotomic_poly NTT(cyclotomic_poly f);

// Computes the polynomial f in R_q that corresponds to a given NTT representation f_hat in T_q.
cyclotomic_poly invNTT(cyclotomic_poly f_hat);

// Computes the product (in the ring T_q) of two NTT representations.
cyclotomic_poly multiply_NTT(cyclotomic_poly f_hat, cyclotomic_poly g_hat);

// Computes the product of two degree-one polynomials with respect to a quadratic modulus.
std::pair<int, int> base_case_multiply(int64_t a0, int64_t a1, int64_t b0, int64_t b1, int64_t gamma);

// Uses randomness to generate an encryption key and a corresponding decryption key.
void k_pke_key_gen(kyber_params params, std::array<uint8_t, seed_len> d, std::span<uint8_t> ek_PKE, std::span<uint8_t> dk_PKE, std::span<cyclotomic_poly> Ase_buffer, std::span<uint8_t> eta_buffer );

void sample_vector_poly_CBD(uint8_t k, uint8_t eta, std::span<uint8_t> iv, uint8_t& number_once_counter, std::span<cyclotomic_poly> s_out, std::span<uint8_t> eta_buffer) ;

// Uses the encryption key to encrypt a plaintext message using the randomness.
void k_pke_encrypt(kyber_params params, std::span<uint8_t> ek_PKE, std::array<uint8_t, seed_len> message, std::array<uint8_t, seed_len> randomness, std::span<cyclotomic_poly> Aty_buffer, std::span<uint8_t> eta_buffer, std::span<uint8_t> c_out);

// Uses the decryption key to decrypt a ciphertext.
std::array<uint8_t, 32> k_pke_decrypt(kyber_params params, std::span<uint8_t> dk_PKE, std::span<uint8_t> ciphertext, std::span<cyclotomic_poly> us_buffer);

// Uses randomness to generate an encapsulation key and a corresponding decapsulation key.
void ml_kem_key_gen_internal(kyber_params params, std::array<uint8_t, seed_len> d, std::array<uint32_t, seed_len> z, std::span<uint8_t> ek, std::span<uint8_t> dk, std::span<cyclotomic_poly> Ase_buffer, std::span<uint8_t> eta_buffer);

void ml_kem_encaps_internal(kyber_params params, std::span<uint8_t> ek, std::array<uint8_t, seed_len> message, std::array<uint8_t, seed_len>& shared_key, std::span<uint8_t> cipher_text, std::span<cyclotomic_poly> Aty_buffer, std::span<uint8_t> eta_buffer );

std::array<uint8_t, seed_len> ml_kem_decaps_internal(kyber_params params, std::span<uint8_t> dk, std::span<uint8_t> ciphertext, std::array<uint8_t, seed_len> secret_key, std::span<cyclotomic_poly> Aty_buffer, std::span<uint8_t> cipher_eta_buffer);

std::pair<ml_kem_512_pub, ml_kem_512_priv> ml_key_key_gen_512();
std::pair<ml_kem_768_pub, ml_kem_768_priv> ml_key_key_gen_768();
std::pair<ml_kem_1024_pub, ml_kem_1024_priv> ml_key_key_gen_1024();

std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 768>> ml_kem_encaps_512(ml_kem_512_pub key);
std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 1088>> ml_kem_encaps_768(ml_kem_768_pub key);
std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 1568>> ml_kem_encaps_1024(ml_kem_1024_pub key);

std::array<uint8_t, 32> ml_kem_decaps_512(ml_kem_512_priv key);
std::array<uint8_t, 32> ml_kem_decaps_768(ml_kem_512_priv key);
std::array<uint8_t, 32> ml_kem_decaps_1024(ml_kem_512_priv key);

}

#endif