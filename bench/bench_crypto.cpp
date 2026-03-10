//
//  bench_crypto.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 28/02/2026.
//

#include "../src/TLS/Cryptography/cipher/chacha20poly1305.hpp"
#include "../src/TLS/Cryptography/cipher/galois_counter.hpp"
#include "../src/TLS/Cryptography/one_way/keccak.hpp"

#include <chrono>
#include <cstdio>
#include <vector>

using namespace fbw::cha;
using namespace fbw::aes;
using namespace std::chrono;

static ChaCha20_Poly1305_ctx make_chacha_ctx() {
    ChaCha20_Poly1305_ctx ctx;
    fbw::randomgen.randgen(ctx.server_write_key);
    fbw::randomgen.randgen(ctx.server_implicit_write_IV);
    ctx.client_write_key = ctx.server_write_key;
    ctx.client_implicit_write_IV = ctx.server_implicit_write_IV;
    return ctx;
}

static AES_128_GCM_SHA256_tls13 make_gcm_ctx() {
    AES_128_GCM_SHA256_tls13 ctx;
    std::vector<uint8_t> key(16);
    fbw::randomgen.randgen(key);
    ctx.set_server_traffic_key(key);
    ctx.set_client_traffic_key(key);
    return ctx;
}

void smoke_test_chacha() {
    auto ctx = make_chacha_ctx();
    std::vector<uint8_t> plaintext(1024);
    fbw::randomgen.randgen(plaintext);
    std::vector<uint8_t> aad = { 0x17, 0x03, 0x03, 0x00, 0x00 };
    auto buf = plaintext;
    auto ciphertext = ctx.encrypt(buf, aad);
    ctx.seqno_client = 0;
    if(ctx.decrypt(ciphertext, aad) != plaintext) {
        throw std::runtime_error("round trip failed");
    }
}

void smoke_test_gcm() {
    auto ctx = make_gcm_ctx();
    std::vector<uint8_t> plaintext(1024);
    fbw::randomgen.randgen(plaintext);
    fbw::tls_record rec(fbw::ContentType::Application);
    rec.m_contents = plaintext;
    auto encrypted = ctx.protect(rec);
    if (ctx.deprotect(encrypted).m_contents != plaintext) {
        throw std::runtime_error("AES-GCM round trip failed");
    }
}

int bench() {
    smoke_test_chacha();
    smoke_test_gcm();

    const std::array<size_t, 7> sizes = { 64, 64, 256, 1024, 4096, 8192, 16384 };
    std::printf("ChaCha20-Poly1305\n");
    std::printf("%-12s  %14s  %14s\n", "payload (B)", "enc (MB/s)", "dec (MB/s)");

    for(size_t sz : sizes) {
        auto aad       = std::vector<uint8_t>{ 0x17, 0x03, 0x03, 0x00, 0x00 };
        std::vector<uint8_t> plaintext(sz);
        fbw::randomgen.randgen(plaintext);
        int iters      = std::clamp(int(25e6 / sz), 50, 50000);
        
        // seed
        auto ctx = make_chacha_ctx();
        std::vector<std::vector<uint8_t>> pool(iters);
        for(int i = 0; i < iters; i++) {
            pool[i] = ctx.encrypt(plaintext, aad);
        }

        // bench
        auto t0 = high_resolution_clock::now();
        for(int i = 0; i < iters; i++) {
            (void)ctx.encrypt(plaintext, aad);
        }
        auto t1 = high_resolution_clock::now();
        for(int i = 0; i < iters; i++) { 
            (void)ctx.decrypt(pool[i], aad); 
        }
        auto t2 = high_resolution_clock::now();

        // report
        double enc_MBps = sz * iters / duration<double>(t1 - t0).count() / 1e6;
        double dec_MBps = sz * iters / duration<double>(t2 - t1).count() / 1e6;

        std::printf("%-12zu  %14.1f  %14.1f\n", sz, enc_MBps, dec_MBps);
    }

    std::printf("\nAES-128-GCM\n");
    std::printf("%-12s  %14s  %14s\n", "payload (B)", "enc (MB/s)", "dec (MB/s)");

    for (size_t sz : sizes) {
        std::vector<uint8_t> plaintext(sz);
        fbw::randomgen.randgen(plaintext);
        int iters = std::clamp(int(25e6 / sz), 50, 50000);

        auto ctx = make_gcm_ctx();
        std::vector<fbw::tls_record> pool(iters);
        for (int i = 0; i < iters; i++) {
            fbw::tls_record rec(fbw::ContentType::Application);
            rec.m_contents = plaintext;
            pool[i] = ctx.protect(rec);
        }

        auto t0 = high_resolution_clock::now();
        for (int i = 0; i < iters; i++) {
            fbw::tls_record rec(fbw::ContentType::Application);
            rec.m_contents = plaintext;
            (void)ctx.protect(rec);
        }
        auto t1 = high_resolution_clock::now();
        for (int i = 0; i < iters; i++) {
            (void)ctx.deprotect(pool[i]);
        }
        auto t2 = high_resolution_clock::now();

        double enc_MBps = sz * iters / duration<double>(t1 - t0).count() / 1e6;
        double dec_MBps = sz * iters / duration<double>(t2 - t1).count() / 1e6;
        std::printf("%-12zu  %14.1f  %14.1f\n", sz, enc_MBps, dec_MBps);
    }
    return 0;
}

int main() {
    try {
        bench();
    } catch(const std::runtime_error& e) {
        std::fprintf(stderr, "bench failed: %s\n", e.what());
        return 1;
    }
}
