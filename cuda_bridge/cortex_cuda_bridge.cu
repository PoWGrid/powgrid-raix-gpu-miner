#include "cortex_cuda_bridge.h"
#include <cuda_runtime.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "k256.cuh"
#include "k512.cuh"
#include "aes256.cuh"

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_512(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP1_512(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG0_512(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SIG1_512(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

__device__ void sha512_transform(uint64_t state[8], const uint8_t data[128]) {
    uint64_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint64_t)data[i * 8 + 0] << 56) |
               ((uint64_t)data[i * 8 + 1] << 48) |
               ((uint64_t)data[i * 8 + 2] << 40) |
               ((uint64_t)data[i * 8 + 3] << 32) |
               ((uint64_t)data[i * 8 + 4] << 24) |
               ((uint64_t)data[i * 8 + 5] << 16) |
               ((uint64_t)data[i * 8 + 6] << 8)  |
               ((uint64_t)data[i * 8 + 7]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SIG1_512(w[i - 2]) + w[i - 7] + SIG0_512(w[i - 15]) + w[i - 16];
    }
    uint64_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint64_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 80; i++) {
        uint64_t t1 = h + EP1_512(e) + CH64(e, f, g) + K512[i] + w[i];
        uint64_t t2 = EP0_512(a) + MAJ64(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void cuda_sha512(const uint8_t* data, int len, uint8_t digest[64]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    uint8_t block[128];
    int offset = 0;
    while (offset + 128 <= len) {
        sha512_transform(state, data + offset);
        offset += 128;
    }
    int rem = len - offset;
    for (int i = 0; i < rem; i++) block[i] = data[offset + i];
    block[rem] = 0x80;
    rem++;
    if (rem > 112) {
        for (int i = rem; i < 128; i++) block[i] = 0;
        sha512_transform(state, block);
        rem = 0;
    }
    for (int i = rem; i < 120; i++) block[i] = 0;
    uint64_t bits = (uint64_t)len * 8ULL;
    block[120] = (uint8_t)(bits >> 56);
    block[121] = (uint8_t)(bits >> 48);
    block[122] = (uint8_t)(bits >> 40);
    block[123] = (uint8_t)(bits >> 32);
    block[124] = (uint8_t)(bits >> 24);
    block[125] = (uint8_t)(bits >> 16);
    block[126] = (uint8_t)(bits >> 8);
    block[127] = (uint8_t)(bits);
    sha512_transform(state, block);
    for (int i = 0; i < 8; i++) {
        digest[i * 8 + 0] = (uint8_t)(state[i] >> 56);
        digest[i * 8 + 1] = (uint8_t)(state[i] >> 48);
        digest[i * 8 + 2] = (uint8_t)(state[i] >> 40);
        digest[i * 8 + 3] = (uint8_t)(state[i] >> 32);
        digest[i * 8 + 4] = (uint8_t)(state[i] >> 24);
        digest[i * 8 + 5] = (uint8_t)(state[i] >> 16);
        digest[i * 8 + 6] = (uint8_t)(state[i] >> 8);
        digest[i * 8 + 7] = (uint8_t)(state[i]);
    }
}

__device__ void cuda_sha512_64bytes(const uint8_t key_in[64], uint8_t digest[64]) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
        0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    uint8_t block[128];
    for (int i = 0; i < 64; i++) block[i] = key_in[i];
    block[64] = 0x80;
    for (int i = 65; i < 120; i++) block[i] = 0;
    block[120] = 0; block[121] = 0; block[122] = 0; block[123] = 0;
    block[124] = 0; block[125] = 0; block[126] = 2; block[127] = 0;
    sha512_transform(state, block);
    for (int i = 0; i < 8; i++) {
        digest[i * 8 + 0] = (uint8_t)(state[i] >> 56);
        digest[i * 8 + 1] = (uint8_t)(state[i] >> 48);
        digest[i * 8 + 2] = (uint8_t)(state[i] >> 40);
        digest[i * 8 + 3] = (uint8_t)(state[i] >> 32);
        digest[i * 8 + 4] = (uint8_t)(state[i] >> 24);
        digest[i * 8 + 5] = (uint8_t)(state[i] >> 16);
        digest[i * 8 + 6] = (uint8_t)(state[i] >> 8);
        digest[i * 8 + 7] = (uint8_t)(state[i]);
    }
}

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH32(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ32(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_256(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1_256(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0_256(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1_256(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

__device__ void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4 + 0] << 24) |
               ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8)  |
               ((uint32_t)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1_256(w[i - 2]) + w[i - 7] + SIG0_256(w[i - 15]) + w[i - 16];
    }
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1_256(e) + CH32(e, f, g) + K256[i] + w[i];
        uint32_t t2 = EP0_256(a) + MAJ32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

__device__ void cuda_sha256_64bytes(const uint8_t data[64], uint8_t digest[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    sha256_transform(state, data);
    uint8_t block[64];
    block[0] = 0x80;
    for (int i = 1; i < 56; i++) block[i] = 0;
    block[56] = 0; block[57] = 0; block[58] = 0; block[59] = 0;
    block[60] = 0; block[61] = 0; block[62] = 2; block[63] = 0;
    sha256_transform(state, block);
    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

__device__ void cuda_sha256_sponge(const uint8_t h1[32], const int64_t* scratchpad, uint8_t digest[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint8_t block[64];

    // Block 0: h1[0..31] + scratchpad[0..3]
    for (int i = 0; i < 32; i++) block[i] = h1[i];
    for (int i = 0; i < 4; i++) {
        uint64_t val = (uint64_t)scratchpad[i];
        for (int b = 0; b < 8; b++) block[32 + i * 8 + b] = (uint8_t)(val >> (b * 8));
    }
    sha256_transform(state, block);

    // Blocks 1..7: scratchpad[4 + (blk-1)*8 .. 4 + (blk-1)*8 + 7]
    for (int blk = 1; blk <= 7; blk++) {
        int baseIdx = 4 + (blk - 1) * 8;
        for (int i = 0; i < 8; i++) {
            uint64_t val = (uint64_t)scratchpad[baseIdx + i];
            for (int b = 0; b < 8; b++) block[i * 8 + b] = (uint8_t)(val >> (b * 8));
        }
        sha256_transform(state, block);
    }

    // Block 8: scratchpad[60..63] + padding + 4352 bits
    for (int i = 0; i < 4; i++) {
        uint64_t val = (uint64_t)scratchpad[60 + i];
        for (int b = 0; b < 8; b++) block[i * 8 + b] = (uint8_t)(val >> (b * 8));
    }
    block[32] = 0x80;
    for (int i = 33; i < 56; i++) block[i] = 0;
    uint64_t bits = 544ULL * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (uint8_t)(bits >> ((7 - i) * 8));
    sha256_transform(state, block);

    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

__device__ void cuda_sha256(const uint8_t* data, int len, uint8_t digest[32]) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    uint8_t block[64];
    int offset = 0;
    while (offset + 64 <= len) {
        sha256_transform(state, data + offset);
        offset += 64;
    }
    int rem = len - offset;
    for (int i = 0; i < rem; i++) block[i] = data[offset + i];
    block[rem] = 0x80;
    if (rem < 56) {
        for (int i = rem + 1; i < 56; i++) block[i] = 0;
    } else {
        for (int i = rem + 1; i < 64; i++) block[i] = 0;
        sha256_transform(state, block);
        for (int i = 0; i < 56; i++) block[i] = 0;
    }
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) block[56 + i] = (uint8_t)(bits >> ((7 - i) * 8));
    sha256_transform(state, block);

    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uint8_t)(state[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(state[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(state[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(state[i]);
    }
}

__device__ __forceinline__ uint32_t cuda_bswap32(uint32_t x) {
    return __byte_perm(x, 0, 0x0123);
}

__device__ __forceinline__ int64_t v2_get_word(
    uint32_t idx,
    const uint32_t rk[15][4],
    const int64_t spongeHead[64],
    const uint32_t writeCacheAddr[48],
    const int64_t writeCacheVal[48],
    uint32_t writeCacheCount
) {
    if (idx < 64) return spongeHead[idx];

    for (uint32_t c = 0; c < writeCacheCount; c++) {
        if (writeCacheAddr[c] == idx) return writeCacheVal[c];
    }

    uint32_t blockIdx = idx >> 1;
    uint32_t in_blk[4] = { 0, 0, 0, blockIdx };
    uint32_t ct[4];
    aes256_encrypt_block(rk, in_blk, ct);

    if ((idx & 1) == 0) {
        uint32_t lo = cuda_bswap32(ct[0]);
        uint32_t hi = cuda_bswap32(ct[1]);
        return (int64_t)(((uint64_t)hi << 32) | (uint64_t)lo);
    } else {
        uint32_t lo = cuda_bswap32(ct[2]);
        uint32_t hi = cuda_bswap32(ct[3]);
        return (int64_t)(((uint64_t)hi << 32) | (uint64_t)lo);
    }
}

__device__ __forceinline__ void v2_set_word(
    uint32_t idx,
    int64_t val,
    int64_t spongeHead[64],
    uint32_t writeCacheAddr[48],
    int64_t writeCacheVal[48],
    uint32_t* writeCacheCount
) {
    if (idx < 64) {
        spongeHead[idx] = val;
        return;
    }
    for (uint32_t c = 0; c < *writeCacheCount; c++) {
        if (writeCacheAddr[c] == idx) {
            writeCacheVal[c] = val;
            return;
        }
    }
    if (*writeCacheCount < 48) {
        writeCacheAddr[*writeCacheCount] = idx;
        writeCacheVal[*writeCacheCount] = val;
        (*writeCacheCount)++;
    }
}

__device__ int u64_to_str(uint64_t val, char* out) {
    if (val == 0) {
        out[0] = '0';
        return 1;
    }
    char temp[32];
    int len = 0;
    while (val > 0) {
        temp[len++] = '0' + (val % 10);
        val /= 10;
    }
    for (int i = 0; i < len; i++) {
        out[i] = temp[len - 1 - i];
    }
    return len;
}

#define MAX_SOLUTIONS 32

__global__ void cortex_mine_kernel(
    const char* d_prefix, int prefix_len,
    const char* d_suffix, int suffix_len,
    const char* d_seed, int seed_len,
    int target_diff,
    uint64_t target_u64,
    uint64_t base_nonce,
    int nonces_per_thread,
    int64_t* d_scratchpads,
    int* d_found_count,
    uint64_t* d_found_nonces
) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    int total_threads = gridDim.x * blockDim.x;

    for (int iter_nonce = 0; iter_nonce < nonces_per_thread; iter_nonce++) {
        uint64_t nonce = base_nonce + (uint64_t)iter_nonce * (uint64_t)total_threads + (uint64_t)tid;

        char header[512];
        for (int i = 0; i < prefix_len; i++) header[i] = d_prefix[i];
        int nonce_len = u64_to_str(nonce, header + prefix_len);
        int cur_len = prefix_len + nonce_len;
        for (int i = 0; i < suffix_len; i++) header[cur_len + i] = d_suffix[i];
        int header_len = cur_len + suffix_len;

        // 1. key = sha512(header + ":" + seed)
        header[header_len] = ':';
        for (int i = 0; i < seed_len; i++) header[header_len + 1 + i] = d_seed[i];
        int hs_len = header_len + 1 + seed_len;

        uint8_t key[64];
        cuda_sha512((const uint8_t*)header, hs_len, key);
        header[header_len] = 0;

        // Scratchpad initialization (Coalesced)
        for (int i = 0; i < 4096; i += 8) {
            #pragma unroll
            for (int j = 0; j < 8; j++) {
                uint64_t val = ((uint64_t)key[j * 8 + 0]) |
                               (((uint64_t)key[j * 8 + 1]) << 8) |
                               (((uint64_t)key[j * 8 + 2]) << 16) |
                               (((uint64_t)key[j * 8 + 3]) << 24) |
                               (((uint64_t)key[j * 8 + 4]) << 32) |
                               (((uint64_t)key[j * 8 + 5]) << 40) |
                               (((uint64_t)key[j * 8 + 6]) << 48) |
                               (((uint64_t)key[j * 8 + 7]) << 56);
                d_scratchpads[(size_t)(i + j) * total_threads + tid] = (int64_t)val;
            }
            if (i % 64 == 0) {
                uint8_t next_key[64];
                cuda_sha512_64bytes(key, next_key);
                #pragma unroll
                for (int k = 0; k < 64; k++) key[k] = next_key[k];
            }
        }

        // 2. initialDigest = sha512(seed + ":" + header)
        char s_h[512];
        for (int i = 0; i < seed_len; i++) s_h[i] = d_seed[i];
        s_h[seed_len] = ':';
        for (int i = 0; i < header_len; i++) s_h[seed_len + 1 + i] = header[i];
        int sh_len = seed_len + 1 + header_len;

        uint8_t initialDigest[64];
        cuda_sha512((const uint8_t*)s_h, sh_len, initialDigest);

        int64_t r[8];
        double f[4];
        for (int i = 0; i < 8; i++) {
            uint64_t val = ((uint64_t)initialDigest[i * 8 + 0]) |
                           (((uint64_t)initialDigest[i * 8 + 1]) << 8) |
                           (((uint64_t)initialDigest[i * 8 + 2]) << 16) |
                           (((uint64_t)initialDigest[i * 8 + 3]) << 24) |
                           (((uint64_t)initialDigest[i * 8 + 4]) << 32) |
                           (((uint64_t)initialDigest[i * 8 + 5]) << 40) |
                           (((uint64_t)initialDigest[i * 8 + 6]) << 48) |
                           (((uint64_t)initialDigest[i * 8 + 7]) << 56);
            r[i] = (int64_t)val;
        }
        for (int i = 0; i < 4; i++) {
            f[i] = (double)(r[i] % 1000000) / 1000.0;
        }

        // 3. VM Execution
        const int mask = 4095;
        for (int iter = 0; iter < 64; iter++) {
            int opCode = (initialDigest[iter % 64] ^ (uint8_t)d_seed[iter % seed_len]) % 10;
            int srcIdx = (iter + 1) % 8;
            int dstIdx = iter % 8;
            uint32_t u32 = (uint32_t)r[dstIdx];
            int memIdx = (int)(u32 & mask);

            switch (opCode) {
                case 0: r[dstIdx] = r[dstIdx] + d_scratchpads[(size_t)memIdx * total_threads + tid]; break;
                case 1: r[dstIdx] = r[dstIdx] - r[srcIdx]; break;
                case 2: r[dstIdx] = r[dstIdx] * (r[srcIdx] | 1ULL); break;
                case 3: r[dstIdx] = r[dstIdx] ^ r[srcIdx]; break;
                case 4: {
                    int shift = (int)(r[srcIdx] & 63);
                    int64_t sr = r[dstIdx];
                    int64_t right = (shift == 0) ? (sr < 0 ? -1 : 0) : (sr >> (64 - shift));
                    uint64_t ur = ((uint64_t)sr << shift) | (uint64_t)right;
                    r[dstIdx] = (int64_t)ur;
                    break;
                }
                case 5: d_scratchpads[(size_t)memIdx * total_threads + tid] = r[dstIdx] ^ (int64_t)iter; break;
                case 6: {
                    f[dstIdx % 4] = f[dstIdx % 4] + f[srcIdx % 4];
                    int64_t v = (int64_t)floor(abs(f[dstIdx % 4]));
                    r[dstIdx] = r[dstIdx] ^ v;
                    break;
                }
                case 7: {
                    f[dstIdx % 4] = f[dstIdx % 4] * 1.00001;
                    int64_t v = (int64_t)floor(abs(f[dstIdx % 4]));
                    r[dstIdx] = r[dstIdx] ^ v;
                    break;
                }
                case 8: {
                    int nextMem = (memIdx + 64) & mask;
                    int64_t temp = d_scratchpads[(size_t)memIdx * total_threads + tid];
                    d_scratchpads[(size_t)memIdx * total_threads + tid] = d_scratchpads[(size_t)nextMem * total_threads + tid];
                    d_scratchpads[(size_t)nextMem * total_threads + tid] = temp;
                    break;
                }
                case 9: r[dstIdx] = -r[dstIdx]; break;
            }
        }

        // 4. Final Sponge Digest
        uint8_t finalBuf[64];
        for (int i = 0; i < 8; i++) {
            uint64_t val = (uint64_t)r[i];
            finalBuf[i * 8 + 0] = (uint8_t)(val);
            finalBuf[i * 8 + 1] = (uint8_t)(val >> 8);
            finalBuf[i * 8 + 2] = (uint8_t)(val >> 16);
            finalBuf[i * 8 + 3] = (uint8_t)(val >> 24);
            finalBuf[i * 8 + 4] = (uint8_t)(val >> 32);
            finalBuf[i * 8 + 5] = (uint8_t)(val >> 40);
            finalBuf[i * 8 + 6] = (uint8_t)(val >> 48);
            finalBuf[i * 8 + 7] = (uint8_t)(val >> 56);
        }

        uint8_t h1[32];
        cuda_sha256_64bytes(finalBuf, h1);

        int64_t sp_head[64];
        for (int i = 0; i < 64; i++) {
            sp_head[i] = d_scratchpads[(size_t)i * total_threads + tid];
        }

        uint8_t h2[32];
        cuda_sha256_sponge(h1, sp_head, h2);

        // Check difficulty
        bool match = false;
        if (target_u64 > 0) {
            uint64_t h2_u64 = ((uint64_t)h2[0] << 56) | ((uint64_t)h2[1] << 48) |
                              ((uint64_t)h2[2] << 40) | ((uint64_t)h2[3] << 32) |
                              ((uint64_t)h2[4] << 24) | ((uint64_t)h2[5] << 16) |
                              ((uint64_t)h2[6] << 8)  | ((uint64_t)h2[7]);
            match = (h2_u64 <= target_u64);
        } else {
            match = true;
            for (int k = 0; k < target_diff; k++) {
                uint8_t nibble = (k % 2 == 0) ? (h2[k / 2] >> 4) : (h2[k / 2] & 0x0F);
                if (nibble != 0) { match = false; break; }
            }
        }

        if (match) {
            int slot = atomicAdd(d_found_count, 1);
            if (slot < MAX_SOLUTIONS) {
                d_found_nonces[slot] = nonce;
            }
        }
    }
}

__global__ void cortex_mine_v2_kernel(
    const char* d_prefix, int prefix_len,
    const char* d_suffix, int suffix_len,
    const char* d_seed, int seed_len,
    int target_diff,
    uint64_t target_u64,
    uint64_t base_nonce,
    int nonces_per_thread,
    int* d_found_count,
    uint64_t* d_found_nonces
) {
    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    uint64_t thread_base = base_nonce + (uint64_t)tid * (uint64_t)nonces_per_thread;

    for (int n = 0; n < nonces_per_thread; n++) {
        if (*d_found_count > 0) return;

        uint64_t nonce = thread_base + (uint64_t)n;

        char header[384];
        for (int i = 0; i < prefix_len; i++) header[i] = d_prefix[i];
        int nonce_len = u64_to_str(nonce, header + prefix_len);
        int cur_len = prefix_len + nonce_len;
        for (int i = 0; i < suffix_len; i++) header[cur_len + i] = d_suffix[i];
        int header_len = cur_len + suffix_len;

        // 1. seed_key = sha256(header + ":" + seed)
        uint8_t hs_buf[384];
        for (int i = 0; i < header_len; i++) hs_buf[i] = (uint8_t)header[i];
        hs_buf[header_len] = ':';
        for (int i = 0; i < seed_len; i++) hs_buf[header_len + 1 + i] = (uint8_t)d_seed[i];
        int hs_len = header_len + 1 + seed_len;

        uint8_t seed_key[32];
        cuda_sha256(hs_buf, hs_len, seed_key);

        // 2. initial_digest = sha512(seed + ":" + header)
        uint8_t sh_buf[384];
        for (int i = 0; i < seed_len; i++) sh_buf[i] = (uint8_t)d_seed[i];
        sh_buf[seed_len] = ':';
        for (int i = 0; i < header_len; i++) sh_buf[seed_len + 1 + i] = (uint8_t)header[i];
        int sh_len = seed_len + 1 + header_len;

        uint8_t initial_digest[64];
        cuda_sha512(sh_buf, sh_len, initial_digest);

        // 3. Initialize registers
        int64_t r[8];
        for (int i = 0; i < 8; i++) {
            uint64_t val = 0;
            for (int b = 0; b < 8; b++) {
                val |= ((uint64_t)initial_digest[i * 8 + b]) << (b * 8);
            }
            r[i] = (int64_t)val;
        }

        double f[4];
        for (int i = 0; i < 4; i++) {
            f[i] = (double)(r[i] % 1000000) / 1000.0;
        }

        // Expand AES-256 round keys
        uint32_t rk[15][4];
        aes256_key_expansion(seed_key, rk);

        // Generate first 64 words (512 bytes) of keystream
        int64_t spongeHead[64];
        for (int blk = 0; blk < 32; blk++) {
            uint32_t in_blk[4] = { 0, 0, 0, (uint32_t)blk };
            uint32_t ct[4];
            aes256_encrypt_block(rk, in_blk, ct);

            uint32_t lo0 = cuda_bswap32(ct[0]);
            uint32_t hi0 = cuda_bswap32(ct[1]);
            spongeHead[blk * 2] = (int64_t)(((uint64_t)hi0 << 32) | (uint64_t)lo0);

            uint32_t lo1 = cuda_bswap32(ct[2]);
            uint32_t hi1 = cuda_bswap32(ct[3]);
            spongeHead[blk * 2 + 1] = (int64_t)(((uint64_t)hi1 << 32) | (uint64_t)lo1);
        }

        // Sparse Write Cache
        uint32_t writeCacheAddr[48];
        int64_t writeCacheVal[48];
        uint32_t writeCacheCount = 0;

        #define getWordV2(idx) v2_get_word((idx), rk, spongeHead, writeCacheAddr, writeCacheVal, writeCacheCount)
        #define setWordV2(idx, val) v2_set_word((idx), (val), spongeHead, writeCacheAddr, writeCacheVal, &writeCacheCount)

        // 128-cycle RandomX VM loop
        const uint32_t mask = 262143;
        for (int iter = 0; iter < 128; iter++) {
            uint8_t opCode = (initial_digest[iter % 64] ^ (uint8_t)d_seed[iter % seed_len]) % 10;
            int src = (iter + 1) & 7;
            int dst = iter & 7;
            uint32_t memIdx = ((uint32_t)r[dst]) & mask;

            switch (opCode) {
                case 0: r[dst] = r[dst] + getWordV2(memIdx); break;
                case 1: r[dst] = r[dst] - r[src]; break;
                case 2: r[dst] = r[dst] * (r[src] | 1ULL); break;
                case 3: r[dst] ^= r[src]; break;
                case 4: {
                    uint32_t shift = (uint32_t)r[src] & 63;
                    int64_t sr = r[dst];
                    int64_t right = (shift == 0) ? ((sr < 0) ? -1LL : 0LL) : (sr >> (64 - shift));
                    r[dst] = (int64_t)(((uint64_t)sr << shift) | (uint64_t)right);
                    break;
                }
                case 5: setWordV2(memIdx, r[dst] ^ (int64_t)iter); break;
                case 6: {
                    f[dst % 4] += f[src % 4];
                    r[dst] ^= (int64_t)floor(fabs(f[dst % 4]));
                    break;
                }
                case 7: {
                    f[dst % 4] *= 1.00001;
                    r[dst] ^= (int64_t)floor(fabs(f[dst % 4]));
                    break;
                }
                case 8: {
                    uint32_t nextMem = (memIdx + 64) & mask;
                    int64_t tmp = getWordV2(memIdx);
                    int64_t tmp2 = getWordV2(nextMem);
                    setWordV2(memIdx, tmp2);
                    setWordV2(nextMem, tmp);
                    break;
                }
                case 9: r[dst] = -r[dst]; break;
            }
        }
        #undef getWordV2
        #undef setWordV2

        // Step 4 Final Sponge Digest
        uint8_t finalBuf[64];
        for (int i = 0; i < 8; i++) {
            uint64_t val = (uint64_t)r[i];
            for (int b = 0; b < 8; b++) {
                finalBuf[i * 8 + b] = (uint8_t)(val >> (b * 8));
            }
        }

        uint8_t h1[32];
        cuda_sha256_64bytes(finalBuf, h1);

        uint8_t h2[32];
        cuda_sha256_sponge(h1, spongeHead, h2);

        // Check target difficulty
        bool match = false;
        if (target_u64 > 0) {
            uint64_t h2_u64 = ((uint64_t)h2[0] << 56) | ((uint64_t)h2[1] << 48) |
                              ((uint64_t)h2[2] << 40) | ((uint64_t)h2[3] << 32) |
                              ((uint64_t)h2[4] << 24) | ((uint64_t)h2[5] << 16) |
                              ((uint64_t)h2[6] << 8)  | ((uint64_t)h2[7]);
            match = (h2_u64 <= target_u64);
        } else {
            match = true;
            for (int k = 0; k < target_diff; k++) {
                uint8_t nibble = (k % 2 == 0) ? (h2[k / 2] >> 4) : (h2[k / 2] & 0x0F);
                if (nibble != 0) { match = false; break; }
            }
        }

        if (match) {
            int slot = atomicAdd(d_found_count, 1);
            if (slot < MAX_SOLUTIONS) {
                d_found_nonces[slot] = nonce;
            }
        }
    }
}

__global__ void cortex_mine_v22_kernel(
    const char* d_prefix, int prefix_len,
    const char* d_suffix, int suffix_len,
    const char* d_seed, int seed_len,
    int target_diff,
    uint64_t target_u64,
    uint64_t base_nonce,
    int nonces_per_thread,
    int64_t* d_scratchpads_v22,
    int total_v22_threads,
    int* d_found_count,
    uint64_t* d_found_nonces
) {
    __shared__ uint32_t s_TE0[256];
    __shared__ uint8_t s_SBOX[256];
    if (threadIdx.x < 256) {
        s_TE0[threadIdx.x] = AES_TE0[threadIdx.x];
        s_SBOX[threadIdx.x] = AES_SBOX[threadIdx.x];
    }
    __syncthreads();

    int tid = blockIdx.x * blockDim.x + threadIdx.x;
    if (tid >= total_v22_threads) return;

    uint64_t thread_base = base_nonce + (uint64_t)tid * (uint64_t)nonces_per_thread;

    for (int n = 0; n < nonces_per_thread; n++) {
        if (*d_found_count > 0) return;

        uint64_t nonce = thread_base + (uint64_t)n;

        char header[384];
        for (int i = 0; i < prefix_len; i++) header[i] = d_prefix[i];
        int nonce_len = u64_to_str(nonce, header + prefix_len);
        int cur_len = prefix_len + nonce_len;
        for (int i = 0; i < suffix_len; i++) header[cur_len + i] = d_suffix[i];
        int header_len = cur_len + suffix_len;

        // 1. seed_key = sha256(header + ":" + seed)
        uint8_t hs_buf[384];
        for (int i = 0; i < header_len; i++) hs_buf[i] = (uint8_t)header[i];
        hs_buf[header_len] = ':';
        for (int i = 0; i < seed_len; i++) hs_buf[header_len + 1 + i] = (uint8_t)d_seed[i];
        int hs_len = header_len + 1 + seed_len;

        uint8_t seed_key[32];
        cuda_sha256(hs_buf, hs_len, seed_key);

        // 2. iv = sha256(seed + ":" + header + ":v2.2-iv")[0..16]
        uint8_t iv_buf[384];
        for (int i = 0; i < seed_len; i++) iv_buf[i] = (uint8_t)d_seed[i];
        iv_buf[seed_len] = ':';
        for (int i = 0; i < header_len; i++) iv_buf[seed_len + 1 + i] = (uint8_t)header[i];
        int iv_pre_len = seed_len + 1 + header_len;
        const char* iv_suffix = ":v2.2-iv";
        for (int i = 0; i < 8; i++) iv_buf[iv_pre_len + i] = (uint8_t)iv_suffix[i];
        int iv_len = iv_pre_len + 8;

        uint8_t iv_full[32];
        cuda_sha256(iv_buf, iv_len, iv_full);

        // 3. initial_digest = sha512(seed + ":" + header)
        uint8_t sh_buf[384];
        for (int i = 0; i < seed_len; i++) sh_buf[i] = (uint8_t)d_seed[i];
        sh_buf[seed_len] = ':';
        for (int i = 0; i < header_len; i++) sh_buf[seed_len + 1 + i] = (uint8_t)header[i];
        int sh_len = seed_len + 1 + header_len;

        uint8_t initial_digest[64];
        cuda_sha512(sh_buf, sh_len, initial_digest);

        // 4. Initialize registers
        int64_t r[8];
        for (int i = 0; i < 8; i++) {
            uint64_t val = 0;
            for (int b = 0; b < 8; b++) {
                val |= ((uint64_t)initial_digest[i * 8 + b]) << (b * 8);
            }
            r[i] = (int64_t)val;
        }

        double f[4];
        for (int i = 0; i < 4; i++) {
            f[i] = (double)(r[i] % 1000000) / 1000.0;
        }

        // Expand AES-256 round keys
        uint32_t rk[15][4];
        aes256_key_expansion(seed_key, rk);

        // Sequential AES-256-CBC fill of 131,072 blocks with on-the-fly 64-word fold accumulation
        uint32_t block[4];
        block[0] = ((uint32_t)iv_full[0] << 24) | ((uint32_t)iv_full[1] << 16) | ((uint32_t)iv_full[2] << 8) | ((uint32_t)iv_full[3]);
        block[1] = ((uint32_t)iv_full[4] << 24) | ((uint32_t)iv_full[5] << 16) | ((uint32_t)iv_full[6] << 8) | ((uint32_t)iv_full[7]);
        block[2] = ((uint32_t)iv_full[8] << 24) | ((uint32_t)iv_full[9] << 16) | ((uint32_t)iv_full[10] << 8) | ((uint32_t)iv_full[11]);
        block[3] = ((uint32_t)iv_full[12] << 24) | ((uint32_t)iv_full[13] << 16) | ((uint32_t)iv_full[14] << 8) | ((uint32_t)iv_full[15]);

        int64_t fold64[64];
        #pragma unroll
        for (int j = 0; j < 64; j++) fold64[j] = 0;

        for (int b = 0; b < 131072; b++) {
            aes256_encrypt_block_smem(rk, block, block, s_TE0, s_SBOX);

            uint32_t lo0 = cuda_bswap32(block[0]);
            uint32_t hi0 = cuda_bswap32(block[1]);
            int64_t w0 = (int64_t)(((uint64_t)hi0 << 32) | (uint64_t)lo0);

            uint32_t lo1 = cuda_bswap32(block[2]);
            uint32_t hi1 = cuda_bswap32(block[3]);
            int64_t w1 = (int64_t)(((uint64_t)hi1 << 32) | (uint64_t)lo1);

            int word_idx0 = b * 2;
            int word_idx1 = word_idx0 + 1;
            d_scratchpads_v22[(size_t)word_idx0 * (size_t)total_v22_threads + (size_t)tid] = w0;
            d_scratchpads_v22[(size_t)word_idx1 * (size_t)total_v22_threads + (size_t)tid] = w1;

            fold64[word_idx0 & 63] ^= w0;
            fold64[word_idx1 & 63] ^= w1;
        }

        // 128-cycle RandomX VM loop
        const uint32_t mask = 262143;
        for (int iter = 0; iter < 128; iter++) {
            uint8_t opCode = (initial_digest[iter % 64] ^ (uint8_t)d_seed[iter % seed_len]) % 10;
            int src = (iter + 1) & 7;
            int dst = iter & 7;
            uint32_t memIdx = ((uint32_t)r[dst]) & mask;

            switch (opCode) {
                case 0: {
                    int64_t m = d_scratchpads_v22[(size_t)memIdx * (size_t)total_v22_threads + (size_t)tid];
                    r[dst] = r[dst] + m;
                    break;
                }
                case 1: r[dst] = r[dst] - r[src]; break;
                case 2: r[dst] = r[dst] * (r[src] | 1ULL); break;
                case 3: r[dst] ^= r[src]; break;
                case 4: {
                    uint32_t shift = (uint32_t)r[src] & 63;
                    int64_t sr = r[dst];
                    int64_t right = (shift == 0) ? ((sr < 0) ? -1LL : 0LL) : (sr >> (64 - shift));
                    r[dst] = (int64_t)(((uint64_t)sr << shift) | (uint64_t)right);
                    break;
                }
                case 5: {
                    size_t offset = (size_t)memIdx * (size_t)total_v22_threads + (size_t)tid;
                    int64_t old_val = d_scratchpads_v22[offset];
                    int64_t new_val = r[dst] ^ (int64_t)iter;
                    d_scratchpads_v22[offset] = new_val;
                    fold64[memIdx & 63] ^= (old_val ^ new_val);
                    break;
                }
                case 6: {
                    f[dst % 4] += f[src % 4];
                    r[dst] ^= (int64_t)floor(fabs(f[dst % 4]));
                    break;
                }
                case 7: {
                    f[dst % 4] *= 1.00001;
                    r[dst] ^= (int64_t)floor(fabs(f[dst % 4]));
                    break;
                }
                case 8: {
                    uint32_t nextMem = (memIdx + 64) & mask;
                    size_t off1 = (size_t)memIdx * (size_t)total_v22_threads + (size_t)tid;
                    size_t off2 = (size_t)nextMem * (size_t)total_v22_threads + (size_t)tid;
                    int64_t tmp1 = d_scratchpads_v22[off1];
                    int64_t tmp2 = d_scratchpads_v22[off2];
                    d_scratchpads_v22[off1] = tmp2;
                    d_scratchpads_v22[off2] = tmp1;
                    break;
                }
                case 9: r[dst] = -r[dst]; break;
            }
        }

        // Step 4 Final Sponge Digest
        uint8_t finalBuf[64];
        for (int i = 0; i < 8; i++) {
            uint64_t val = (uint64_t)r[i];
            for (int b = 0; b < 8; b++) {
                finalBuf[i * 8 + b] = (uint8_t)(val >> (b * 8));
            }
        }

        uint8_t h1[32];
        cuda_sha256_64bytes(finalBuf, h1);

        uint8_t h2[32];
        cuda_sha256_sponge(h1, fold64, h2);

        // Check target difficulty
        bool match = false;
        if (target_u64 > 0) {
            uint64_t h2_u64 = ((uint64_t)h2[0] << 56) | ((uint64_t)h2[1] << 48) |
                              ((uint64_t)h2[2] << 40) | ((uint64_t)h2[3] << 32) |
                              ((uint64_t)h2[4] << 24) | ((uint64_t)h2[5] << 16) |
                              ((uint64_t)h2[6] << 8)  | ((uint64_t)h2[7]);
            match = (h2_u64 <= target_u64);
        } else {
            match = true;
            for (int k = 0; k < target_diff; k++) {
                uint8_t nibble = (k % 2 == 0) ? (h2[k / 2] >> 4) : (h2[k / 2] & 0x0F);
                if (nibble != 0) { match = false; break; }
            }
        }

        if (match) {
            int slot = atomicAdd(d_found_count, 1);
            if (slot < MAX_SOLUTIONS) {
                d_found_nonces[slot] = nonce;
            }
        }
    }
}

// Single-hash test kernel
__global__ void cortex_test_kernel(
    const char* d_header, int header_len,
    const char* d_seed, int seed_len,
    int64_t* d_scratchpads,
    uint8_t* d_out_hash
) {
    char header[512];
    for (int i = 0; i < header_len; i++) header[i] = d_header[i];
    header[header_len] = ':';
    for (int i = 0; i < seed_len; i++) header[header_len + 1 + i] = d_seed[i];
    int hs_len = header_len + 1 + seed_len;

    uint8_t key[64];
    cuda_sha512((const uint8_t*)header, hs_len, key);

    for (int i = 0; i < 4096; i += 8) {
        for (int j = 0; j < 8; j++) {
            uint64_t val = ((uint64_t)key[j * 8 + 0]) |
                           (((uint64_t)key[j * 8 + 1]) << 8) |
                           (((uint64_t)key[j * 8 + 2]) << 16) |
                           (((uint64_t)key[j * 8 + 3]) << 24) |
                           (((uint64_t)key[j * 8 + 4]) << 32) |
                           (((uint64_t)key[j * 8 + 5]) << 40) |
                           (((uint64_t)key[j * 8 + 6]) << 48) |
                           (((uint64_t)key[j * 8 + 7]) << 56);
            d_scratchpads[i + j] = (int64_t)val;
        }
        if (i % 64 == 0) {
            uint8_t next_key[64];
            cuda_sha512_64bytes(key, next_key);
            for (int k = 0; k < 64; k++) key[k] = next_key[k];
        }
    }

    char s_h[512];
    for (int i = 0; i < seed_len; i++) s_h[i] = d_seed[i];
    s_h[seed_len] = ':';
    for (int i = 0; i < header_len; i++) s_h[seed_len + 1 + i] = d_header[i];
    int sh_len = seed_len + 1 + header_len;

    uint8_t initialDigest[64];
    cuda_sha512((const uint8_t*)s_h, sh_len, initialDigest);

    int64_t r[8];
    double f[4];
    for (int i = 0; i < 8; i++) {
        uint64_t val = ((uint64_t)initialDigest[i * 8 + 0]) |
                       (((uint64_t)initialDigest[i * 8 + 1]) << 8) |
                       (((uint64_t)initialDigest[i * 8 + 2]) << 16) |
                       (((uint64_t)initialDigest[i * 8 + 3]) << 24) |
                       (((uint64_t)initialDigest[i * 8 + 4]) << 32) |
                       (((uint64_t)initialDigest[i * 8 + 5]) << 40) |
                       (((uint64_t)initialDigest[i * 8 + 6]) << 48) |
                       (((uint64_t)initialDigest[i * 8 + 7]) << 56);
        r[i] = (int64_t)val;
    }
    for (int i = 0; i < 4; i++) {
        f[i] = (double)(r[i] % 1000000) / 1000.0;
    }

    const int mask = 4095;
    for (int iter = 0; iter < 64; iter++) {
        int opCode = (initialDigest[iter % 64] ^ (uint8_t)d_seed[iter % seed_len]) % 10;
        int srcIdx = (iter + 1) % 8;
        int dstIdx = iter % 8;
        uint32_t u32 = (uint32_t)r[dstIdx];
        int memIdx = (int)(u32 & mask);

        switch (opCode) {
            case 0: r[dstIdx] = r[dstIdx] + d_scratchpads[memIdx]; break;
            case 1: r[dstIdx] = r[dstIdx] - r[srcIdx]; break;
            case 2: r[dstIdx] = r[dstIdx] * (r[srcIdx] | 1ULL); break;
            case 3: r[dstIdx] = r[dstIdx] ^ r[srcIdx]; break;
            case 4: {
                int shift = (int)(r[srcIdx] & 63);
                int64_t sr = r[dstIdx];
                int64_t right = (shift == 0) ? (sr < 0 ? -1 : 0) : (sr >> (64 - shift));
                uint64_t ur = ((uint64_t)sr << shift) | (uint64_t)right;
                r[dstIdx] = (int64_t)ur;
                break;
            }
            case 5: d_scratchpads[memIdx] = r[dstIdx] ^ (int64_t)iter; break;
            case 6: {
                f[dstIdx % 4] = f[dstIdx % 4] + f[srcIdx % 4];
                int64_t v = (int64_t)floor(abs(f[dstIdx % 4]));
                r[dstIdx] = r[dstIdx] ^ v;
                break;
            }
            case 7: {
                f[dstIdx % 4] = f[dstIdx % 4] * 1.00001;
                int64_t v = (int64_t)floor(abs(f[dstIdx % 4]));
                r[dstIdx] = r[dstIdx] ^ v;
                break;
            }
            case 8: {
                int nextMem = (memIdx + 64) & mask;
                int64_t temp = d_scratchpads[memIdx];
                d_scratchpads[memIdx] = d_scratchpads[nextMem];
                d_scratchpads[nextMem] = temp;
                break;
            }
            case 9: r[dstIdx] = -r[dstIdx]; break;
        }
    }

    uint8_t finalBuf[64];
    for (int i = 0; i < 8; i++) {
        uint64_t val = (uint64_t)r[i];
        finalBuf[i * 8 + 0] = (uint8_t)(val);
        finalBuf[i * 8 + 1] = (uint8_t)(val >> 8);
        finalBuf[i * 8 + 2] = (uint8_t)(val >> 16);
        finalBuf[i * 8 + 3] = (uint8_t)(val >> 24);
        finalBuf[i * 8 + 4] = (uint8_t)(val >> 32);
        finalBuf[i * 8 + 5] = (uint8_t)(val >> 40);
        finalBuf[i * 8 + 6] = (uint8_t)(val >> 48);
        finalBuf[i * 8 + 7] = (uint8_t)(val >> 56);
    }

    uint8_t h1[32];
    cuda_sha256_64bytes(finalBuf, h1);

    int64_t sp_head[64];
    for (int i = 0; i < 64; i++) sp_head[i] = d_scratchpads[i];

    uint8_t h2[32];
    cuda_sha256_sponge(h1, sp_head, h2);

    for (int i = 0; i < 32; i++) d_out_hash[i] = h2[i];
}

__global__ void cortex_test_v2_kernel(
    const char* d_header, int header_len,
    const char* d_seed, int seed_len,
    uint8_t* d_out_hash
) {
    // 1. seed_key = sha256(header + ":" + seed)
    uint8_t hs_buf[384];
    for (int i = 0; i < header_len; i++) hs_buf[i] = (uint8_t)d_header[i];
    hs_buf[header_len] = ':';
    for (int i = 0; i < seed_len; i++) hs_buf[header_len + 1 + i] = (uint8_t)d_seed[i];
    int hs_len = header_len + 1 + seed_len;

    uint8_t seed_key[32];
    cuda_sha256(hs_buf, hs_len, seed_key);

    // 2. initial_digest = sha512(seed + ":" + header)
    uint8_t sh_buf[384];
    for (int i = 0; i < seed_len; i++) sh_buf[i] = (uint8_t)d_seed[i];
    sh_buf[seed_len] = ':';
    for (int i = 0; i < header_len; i++) sh_buf[seed_len + 1 + i] = (uint8_t)d_header[i];
    int sh_len = seed_len + 1 + header_len;

    uint8_t initial_digest[64];
    cuda_sha512(sh_buf, sh_len, initial_digest);

    // 3. Initialize registers
    int64_t r[8];
    for (int i = 0; i < 8; i++) {
        uint64_t val = 0;
        for (int b = 0; b < 8; b++) {
            val |= ((uint64_t)initial_digest[i * 8 + b]) << (b * 8);
        }
        r[i] = (int64_t)val;
    }

    double f[4];
    for (int i = 0; i < 4; i++) {
        f[i] = (double)(r[i] % 1000000) / 1000.0;
    }

    // Expand AES-256 round keys
    uint32_t rk[15][4];
    aes256_key_expansion(seed_key, rk);

    // Generate first 64 words (512 bytes) of keystream
    int64_t spongeHead[64];
    for (int blk = 0; blk < 32; blk++) {
        uint32_t in_blk[4] = { 0, 0, 0, (uint32_t)blk };
        uint32_t ct[4];
        aes256_encrypt_block(rk, in_blk, ct);

        uint32_t lo0 = cuda_bswap32(ct[0]);
        uint32_t hi0 = cuda_bswap32(ct[1]);
        spongeHead[blk * 2] = (int64_t)(((uint64_t)hi0 << 32) | (uint64_t)lo0);

        uint32_t lo1 = cuda_bswap32(ct[2]);
        uint32_t hi1 = cuda_bswap32(ct[3]);
        spongeHead[blk * 2 + 1] = (int64_t)(((uint64_t)hi1 << 32) | (uint64_t)lo1);
    }

    // Sparse Write Cache
    uint32_t writeCacheAddr[48];
    int64_t writeCacheVal[48];
    uint32_t writeCacheCount = 0;

    #define getWordV2(idx) v2_get_word((idx), rk, spongeHead, writeCacheAddr, writeCacheVal, writeCacheCount)
    #define setWordV2(idx, val) v2_set_word((idx), (val), spongeHead, writeCacheAddr, writeCacheVal, &writeCacheCount)

    // 128-cycle RandomX VM loop
    const uint32_t mask = 262143;
    for (int iter = 0; iter < 128; iter++) {
        uint8_t opCode = (initial_digest[iter % 64] ^ (uint8_t)d_seed[iter % seed_len]) % 10;
        int src = (iter + 1) & 7;
        int dst = iter & 7;
        uint32_t memIdx = ((uint32_t)r[dst]) & mask;

        switch (opCode) {
            case 0: r[dst] = r[dst] + getWordV2(memIdx); break;
            case 1: r[dst] = r[dst] - r[src]; break;
            case 2: r[dst] = r[dst] * (r[src] | 1ULL); break;
            case 3: r[dst] ^= r[src]; break;
            case 4: {
                uint32_t shift = (uint32_t)r[src] & 63;
                int64_t sr = r[dst];
                int64_t right = (shift == 0) ? ((sr < 0) ? -1LL : 0LL) : (sr >> (64 - shift));
                r[dst] = (int64_t)(((uint64_t)sr << shift) | (uint64_t)right);
                break;
            }
            case 5: setWordV2(memIdx, r[dst] ^ (int64_t)iter); break;
            case 6: {
                f[dst % 4] += f[src % 4];
                r[dst] ^= (int64_t)floor(fabs(f[dst % 4]));
                break;
            }
            case 7: {
                f[dst % 4] *= 1.00001;
                r[dst] ^= (int64_t)floor(fabs(f[dst % 4]));
                break;
            }
            case 8: {
                uint32_t nextMem = (memIdx + 64) & mask;
                int64_t tmp = getWordV2(memIdx);
                int64_t tmp2 = getWordV2(nextMem);
                setWordV2(memIdx, tmp2);
                setWordV2(nextMem, tmp);
                break;
            }
            case 9: r[dst] = -r[dst]; break;
        }
    }
    #undef getWordV2
    #undef setWordV2

    // Step 4 Final Sponge Digest
    uint8_t finalBuf[64];
    for (int i = 0; i < 8; i++) {
        uint64_t val = (uint64_t)r[i];
        for (int b = 0; b < 8; b++) {
            finalBuf[i * 8 + b] = (uint8_t)(val >> (b * 8));
        }
    }

    uint8_t h1[32];
    cuda_sha256_64bytes(finalBuf, h1);

    cuda_sha256_sponge(h1, spongeHead, d_out_hash);
}

__global__ void cortex_test_v22_kernel(
    const char* d_header, int header_len,
    const char* d_seed, int seed_len,
    int64_t* d_scratchpad_v22,
    uint8_t* d_out_hash
) {
    __shared__ uint32_t s_TE0[256];
    __shared__ uint8_t s_SBOX[256];
    if (threadIdx.x == 0) {
        for (int i = 0; i < 256; i++) {
            s_TE0[i] = AES_TE0[i];
            s_SBOX[i] = AES_SBOX[i];
        }
    }
    __syncthreads();

    // 1. seed_key = sha256(header + ":" + seed)
    uint8_t hs_buf[384];
    for (int i = 0; i < header_len; i++) hs_buf[i] = (uint8_t)d_header[i];
    hs_buf[header_len] = ':';
    for (int i = 0; i < seed_len; i++) hs_buf[header_len + 1 + i] = (uint8_t)d_seed[i];
    int hs_len = header_len + 1 + seed_len;

    uint8_t seed_key[32];
    cuda_sha256(hs_buf, hs_len, seed_key);

    // 2. iv = sha256(seed + ":" + header + ":v2.2-iv")[0..16]
    uint8_t iv_buf[384];
    for (int i = 0; i < seed_len; i++) iv_buf[i] = (uint8_t)d_seed[i];
    iv_buf[seed_len] = ':';
    for (int i = 0; i < header_len; i++) iv_buf[seed_len + 1 + i] = (uint8_t)d_header[i];
    int iv_pre_len = seed_len + 1 + header_len;
    const char* iv_suffix = ":v2.2-iv";
    for (int i = 0; i < 8; i++) iv_buf[iv_pre_len + i] = (uint8_t)iv_suffix[i];
    int iv_len = iv_pre_len + 8;

    uint8_t iv_full[32];
    cuda_sha256(iv_buf, iv_len, iv_full);

    // 3. initial_digest = sha512(seed + ":" + header)
    uint8_t sh_buf[384];
    for (int i = 0; i < seed_len; i++) sh_buf[i] = (uint8_t)d_seed[i];
    sh_buf[seed_len] = ':';
    for (int i = 0; i < header_len; i++) sh_buf[seed_len + 1 + i] = (uint8_t)d_header[i];
    int sh_len = seed_len + 1 + header_len;

    uint8_t initial_digest[64];
    cuda_sha512(sh_buf, sh_len, initial_digest);

    // 4. Initialize registers
    int64_t r[8];
    for (int i = 0; i < 8; i++) {
        uint64_t val = 0;
        for (int b = 0; b < 8; b++) {
            val |= ((uint64_t)initial_digest[i * 8 + b]) << (b * 8);
        }
        r[i] = (int64_t)val;
    }

    double f[4];
    for (int i = 0; i < 4; i++) {
        f[i] = (double)(r[i] % 1000000) / 1000.0;
    }

    // Expand AES-256 round keys
    uint32_t rk[15][4];
    aes256_key_expansion(seed_key, rk);

    uint32_t block[4];
    block[0] = ((uint32_t)iv_full[0] << 24) | ((uint32_t)iv_full[1] << 16) | ((uint32_t)iv_full[2] << 8) | ((uint32_t)iv_full[3]);
    block[1] = ((uint32_t)iv_full[4] << 24) | ((uint32_t)iv_full[5] << 16) | ((uint32_t)iv_full[6] << 8) | ((uint32_t)iv_full[7]);
    block[2] = ((uint32_t)iv_full[8] << 24) | ((uint32_t)iv_full[9] << 16) | ((uint32_t)iv_full[10] << 8) | ((uint32_t)iv_full[11]);
    block[3] = ((uint32_t)iv_full[12] << 24) | ((uint32_t)iv_full[13] << 16) | ((uint32_t)iv_full[14] << 8) | ((uint32_t)iv_full[15]);

    int64_t fold64[64];
    for (int j = 0; j < 64; j++) fold64[j] = 0;

    for (int b = 0; b < 131072; b++) {
        aes256_encrypt_block_smem(rk, block, block, s_TE0, s_SBOX);

        uint32_t lo0 = cuda_bswap32(block[0]);
        uint32_t hi0 = cuda_bswap32(block[1]);
        int64_t w0 = (int64_t)(((uint64_t)hi0 << 32) | (uint64_t)lo0);

        uint32_t lo1 = cuda_bswap32(block[2]);
        uint32_t hi1 = cuda_bswap32(block[3]);
        int64_t w1 = (int64_t)(((uint64_t)hi1 << 32) | (uint64_t)lo1);

        int word_idx0 = b * 2;
        int word_idx1 = word_idx0 + 1;
        d_scratchpad_v22[word_idx0] = w0;
        d_scratchpad_v22[word_idx1] = w1;

        fold64[word_idx0 & 63] ^= w0;
        fold64[word_idx1 & 63] ^= w1;
    }

    const uint32_t mask = 262143;
    for (int iter = 0; iter < 128; iter++) {
        uint8_t opCode = (initial_digest[iter % 64] ^ (uint8_t)d_seed[iter % seed_len]) % 10;
        int src = (iter + 1) & 7;
        int dst = iter & 7;
        uint32_t memIdx = ((uint32_t)r[dst]) & mask;

        switch (opCode) {
            case 0: {
                int64_t m = d_scratchpad_v22[memIdx];
                r[dst] = r[dst] + m;
                break;
            }
            case 1: r[dst] = r[dst] - r[src]; break;
            case 2: r[dst] = r[dst] * (r[src] | 1ULL); break;
            case 3: r[dst] ^= r[src]; break;
            case 4: {
                uint32_t shift = (uint32_t)r[src] & 63;
                int64_t sr = r[dst];
                int64_t right = (shift == 0) ? ((sr < 0) ? -1LL : 0LL) : (sr >> (64 - shift));
                r[dst] = (int64_t)(((uint64_t)sr << shift) | (uint64_t)right);
                break;
            }
            case 5: {
                int64_t old_val = d_scratchpad_v22[memIdx];
                int64_t new_val = r[dst] ^ (int64_t)iter;
                d_scratchpad_v22[memIdx] = new_val;
                fold64[memIdx & 63] ^= (old_val ^ new_val);
                break;
            }
            case 6: {
                f[dst % 4] += f[src % 4];
                r[dst] ^= (int64_t)floor(fabs(f[dst % 4]));
                break;
            }
            case 7: {
                f[dst % 4] *= 1.00001;
                r[dst] ^= (int64_t)floor(fabs(f[dst % 4]));
                break;
            }
            case 8: {
                uint32_t nextMem = (memIdx + 64) & mask;
                int64_t tmp1 = d_scratchpad_v22[memIdx];
                int64_t tmp2 = d_scratchpad_v22[nextMem];
                d_scratchpad_v22[memIdx] = tmp2;
                d_scratchpad_v22[nextMem] = tmp1;
                break;
            }
            case 9: r[dst] = -r[dst]; break;
        }
    }

    uint8_t finalBuf[64];
    for (int i = 0; i < 8; i++) {
        uint64_t val = (uint64_t)r[i];
        for (int b = 0; b < 8; b++) {
            finalBuf[i * 8 + b] = (uint8_t)(val >> (b * 8));
        }
    }

    uint8_t h1[32];
    cuda_sha256_64bytes(finalBuf, h1);

    cuda_sha256_sponge(h1, fold64, d_out_hash);
}

struct CudaWorkerContext {
    int device_id;
    int total_threads;
    int nonces_per_thread;
    int blocks;
    int threads_per_block;
    cudaStream_t stream;

    int64_t* d_scratchpads;
    int64_t* d_scratchpads_v22;
    int v22_total_threads;
    int v22_blocks;

    char* d_prefix;
    char* d_suffix;
    char* d_seed;
    int* d_found_count;
    uint64_t* d_found_nonces;

    int last_prefix_len;
    char last_prefix[512];
    int last_suffix_len;
    char last_suffix[512];
    int last_seed_len;
    char last_seed[256];
};

extern "C" {

int cuda_bridge_get_device_count() {
    int count = 0;
    cudaError_t err = cudaGetDeviceCount(&count);
    return (err == cudaSuccess) ? count : 0;
}

int cuda_bridge_get_device_info(int device_id, char* name_out, size_t name_len, size_t* total_mem, int* sm_count, int* major, int* minor) {
    cudaDeviceProp prop;
    if (cudaGetDeviceProperties(&prop, device_id) != cudaSuccess) return -1;
    if (name_out && name_len > 0) {
        strncpy(name_out, prop.name, name_len - 1);
        name_out[name_len - 1] = 0;
    }
    if (total_mem) *total_mem = prop.totalGlobalMem;
    if (sm_count) *sm_count = prop.multiProcessorCount;
    if (major) *major = prop.major;
    if (minor) *minor = prop.minor;
    return 0;
}

void* cuda_bridge_worker_create(int device_id, int total_threads, int nonces_per_thread) {
    if (cudaSetDevice(device_id) != cudaSuccess) return NULL;

    CudaWorkerContext* ctx = (CudaWorkerContext*)calloc(1, sizeof(CudaWorkerContext));
    if (!ctx) return NULL;

    ctx->device_id = device_id;
    ctx->threads_per_block = 256;
    ctx->blocks = (total_threads + ctx->threads_per_block - 1) / ctx->threads_per_block;
    ctx->total_threads = ctx->blocks * ctx->threads_per_block;
    ctx->nonces_per_thread = (nonces_per_thread > 0) ? nonces_per_thread : 4;

    cudaStreamCreate(&ctx->stream);

    // Scratchpads for v1 will be allocated lazily in run_batch if a v1 job is executed.
    ctx->d_scratchpads = NULL;

    // Adaptive v2.2 Scratchpad allocation (2MB per thread interleaved)
    // Try 2560 -> 2048 -> 1536 -> 1024 -> 768 -> 512 -> 256 -> 128 -> 64 threads
    size_t free_mem = 0, total_mem = 0;
    cudaMemGetInfo(&free_mem, &total_mem);

    ctx->d_scratchpads_v22 = NULL;
    ctx->v22_total_threads = 0;
    ctx->v22_blocks = 0;

    int candidate_threads[] = { 2560, 2048, 1536, 1024, 768, 512, 256, 128, 64 };
    for (int i = 0; i < (int)(sizeof(candidate_threads) / sizeof(candidate_threads[0])); i++) {
        int th = candidate_threads[i];
        size_t needed = (size_t)th * 262144ULL * sizeof(int64_t);
        if (free_mem > needed + (size_t)(256 * 1024 * 1024)) {
            if (cudaMalloc(&ctx->d_scratchpads_v22, needed) == cudaSuccess) {
                ctx->v22_total_threads = th;
                ctx->v22_blocks = (th + ctx->threads_per_block - 1) / ctx->threads_per_block;
                break;
            }
        }
    }

    if (ctx->v22_total_threads > 0) {
        printf("[CUDA] Allocated %d v2.2 concurrent threads (%.1f GB VRAM reserved for 2MB scratchpads)\n",
               ctx->v22_total_threads, (double)(ctx->v22_total_threads * 2) / 1024.0);
    }

    cudaMalloc(&ctx->d_prefix, 512);
    cudaMalloc(&ctx->d_suffix, 512);
    cudaMalloc(&ctx->d_seed, 256);
    cudaMalloc(&ctx->d_found_count, sizeof(int));
    cudaMalloc(&ctx->d_found_nonces, MAX_SOLUTIONS * sizeof(uint64_t));

    ctx->last_prefix_len = -1;
    ctx->last_suffix_len = -1;
    ctx->last_seed_len = -1;

    return (void*)ctx;
}

void cuda_bridge_worker_destroy(void* handle) {
    if (!handle) return;
    CudaWorkerContext* ctx = (CudaWorkerContext*)handle;
    cudaSetDevice(ctx->device_id);
    if (ctx->stream) cudaStreamDestroy(ctx->stream);
    if (ctx->d_scratchpads) cudaFree(ctx->d_scratchpads);
    if (ctx->d_scratchpads_v22) cudaFree(ctx->d_scratchpads_v22);
    if (ctx->d_prefix) cudaFree(ctx->d_prefix);
    if (ctx->d_suffix) cudaFree(ctx->d_suffix);
    if (ctx->d_seed) cudaFree(ctx->d_seed);
    if (ctx->d_found_count) cudaFree(ctx->d_found_count);
    if (ctx->d_found_nonces) cudaFree(ctx->d_found_nonces);
    free(ctx);
}

int cuda_bridge_worker_run_batch(
    void* handle,
    const char* prefix, int prefix_len,
    const char* suffix, int suffix_len,
    const char* seed, int seed_len,
    uint64_t target_u64,
    int target_diff,
    uint64_t base_nonce,
    uint64_t* found_nonces_out,
    int max_found,
    int* found_count_out,
    uint64_t* hashes_done_out
) {
    if (!handle) return -1;
    CudaWorkerContext* ctx = (CudaWorkerContext*)handle;
    cudaSetDevice(ctx->device_id);

    // Update prefix / suffix / seed on device if changed
    if (prefix_len != ctx->last_prefix_len || memcmp(prefix, ctx->last_prefix, prefix_len) != 0) {
        cudaMemcpyAsync(ctx->d_prefix, prefix, prefix_len, cudaMemcpyHostToDevice, ctx->stream);
        ctx->last_prefix_len = prefix_len;
        memcpy(ctx->last_prefix, prefix, prefix_len);
    }
    if (suffix_len != ctx->last_suffix_len || memcmp(suffix, ctx->last_suffix, suffix_len) != 0) {
        cudaMemcpyAsync(ctx->d_suffix, suffix, suffix_len, cudaMemcpyHostToDevice, ctx->stream);
        ctx->last_suffix_len = suffix_len;
        memcpy(ctx->last_suffix, suffix, suffix_len);
    }
    if (seed_len != ctx->last_seed_len || memcmp(seed, ctx->last_seed, seed_len) != 0) {
        cudaMemcpyAsync(ctx->d_seed, seed, seed_len, cudaMemcpyHostToDevice, ctx->stream);
        ctx->last_seed_len = seed_len;
        memcpy(ctx->last_seed, seed, seed_len);
    }

    // Reset found count
    cudaMemsetAsync(ctx->d_found_count, 0, sizeof(int), ctx->stream);

    // Ensure null-terminated seed for reliable strstr parsing
    char seed_str[256];
    int slen = (seed_len < 255) ? seed_len : 255;
    if (seed && slen > 0) {
        memcpy(seed_str, seed, slen);
        seed_str[slen] = '\0';
    } else {
        seed_str[0] = '\0';
    }

    // Launch mining kernel
    bool is_v22 = (strstr(seed_str, "v2.2") != NULL || strstr(seed_str, "reticulum-randomx-v2.2") != NULL);
    bool is_v2 = !is_v22 && (strstr(seed_str, "v2") != NULL || strstr(seed_str, "reticulum-randomx-v2") != NULL);

    if (is_v22 && ctx->d_scratchpads_v22) {
        cortex_mine_v22_kernel<<<ctx->v22_blocks, ctx->threads_per_block, 0, ctx->stream>>>(
            ctx->d_prefix, prefix_len,
            ctx->d_suffix, suffix_len,
            ctx->d_seed, seed_len,
            target_diff,
            target_u64,
            base_nonce,
            ctx->nonces_per_thread,
            ctx->d_scratchpads_v22,
            ctx->v22_total_threads,
            ctx->d_found_count,
            ctx->d_found_nonces
        );
    } else if (is_v2) {
        cortex_mine_v2_kernel<<<ctx->blocks, ctx->threads_per_block, 0, ctx->stream>>>(
            ctx->d_prefix, prefix_len,
            ctx->d_suffix, suffix_len,
            ctx->d_seed, seed_len,
            target_diff,
            target_u64,
            base_nonce,
            ctx->nonces_per_thread,
            ctx->d_found_count,
            ctx->d_found_nonces
        );
    } else {
        if (!ctx->d_scratchpads) {
            size_t sp_size = (size_t)ctx->total_threads * 4096 * sizeof(int64_t);
            if (cudaMalloc(&ctx->d_scratchpads, sp_size) != cudaSuccess) {
                ctx->total_threads = 16384;
                ctx->blocks = ctx->total_threads / ctx->threads_per_block;
                sp_size = (size_t)ctx->total_threads * 4096 * sizeof(int64_t);
                cudaMalloc(&ctx->d_scratchpads, sp_size);
            }
        }
        cortex_mine_kernel<<<ctx->blocks, ctx->threads_per_block, 0, ctx->stream>>>(
            ctx->d_prefix, prefix_len,
            ctx->d_suffix, suffix_len,
            ctx->d_seed, seed_len,
            target_diff,
            target_u64,
            base_nonce,
            ctx->nonces_per_thread,
            ctx->d_scratchpads,
            ctx->d_found_count,
            ctx->d_found_nonces
        );
    }

    int h_found_count = 0;
    cudaMemcpyAsync(&h_found_count, ctx->d_found_count, sizeof(int), cudaMemcpyDeviceToHost, ctx->stream);
    cudaError_t kerr = cudaGetLastError();
    if (kerr != cudaSuccess) {
        printf("[CUDA ERROR] Kernel launch error: %s\n", cudaGetErrorString(kerr));
    }
    cudaError_t serr = cudaStreamSynchronize(ctx->stream);
    if (serr != cudaSuccess) {
        printf("[CUDA ERROR] Stream sync error: %s\n", cudaGetErrorString(serr));
    }

    if (h_found_count > 0 && found_nonces_out && max_found > 0) {
        int copy_count = (h_found_count > max_found) ? max_found : h_found_count;
        cudaMemcpy(found_nonces_out, ctx->d_found_nonces, copy_count * sizeof(uint64_t), cudaMemcpyDeviceToHost);
        *found_count_out = copy_count;
    } else {
        *found_count_out = 0;
    }

    if (hashes_done_out) {
        uint64_t threads = (is_v22 && ctx->d_scratchpads_v22) ? (uint64_t)ctx->v22_total_threads : (uint64_t)ctx->total_threads;
        *hashes_done_out = threads * (uint64_t)ctx->nonces_per_thread;
    }
    return 0;
}

int cuda_bridge_self_test(int device_id) {
    if (cudaSetDevice(device_id) != cudaSuccess) return 0;

    int64_t* d_sp;
    uint8_t* d_hash;
    char* d_hdr;
    char* d_seed;

    if (cudaMalloc(&d_sp, 4096 * sizeof(int64_t)) != cudaSuccess) return 0;
    cudaMalloc(&d_hash, 32);
    cudaMalloc(&d_hdr, 256);
    cudaMalloc(&d_seed, 256);

    const char* seed = "cortex-randomx-genesis-seed-v1";
    int seed_len = strlen(seed);
    cudaMemcpy(d_seed, seed, seed_len, cudaMemcpyHostToDevice);

    // Test Vector 123
    const char* hdr123 = "test_header_123";
    int h123_len = strlen(hdr123);
    cudaMemcpy(d_hdr, hdr123, h123_len, cudaMemcpyHostToDevice);

    cortex_test_kernel<<<1, 1>>>(d_hdr, h123_len, d_seed, seed_len, d_sp, d_hash);
    cudaDeviceSynchronize();

    uint8_t res123[32];
    cudaMemcpy(res123, d_hash, 32, cudaMemcpyDeviceToHost);

    const uint8_t exp123[32] = {
        0xb1, 0xb9, 0x59, 0x9c, 0x0a, 0x73, 0xa8, 0x4c,
        0x57, 0x77, 0x36, 0x9c, 0x3a, 0x2a, 0xf5, 0x0e,
        0x78, 0xcc, 0x63, 0xb6, 0xe0, 0xc2, 0x2c, 0x30,
        0xf1, 0x91, 0xc9, 0x8f, 0xc0, 0x63, 0x16, 0xa5
    };
    if (memcmp(res123, exp123, 32) != 0) {
        cudaFree(d_sp); cudaFree(d_hash); cudaFree(d_hdr); cudaFree(d_seed);
        return 0;
    }

    // Test Vector 99999
    const char* hdr99k = "test_header_99999";
    int h99k_len = strlen(hdr99k);
    cudaMemcpy(d_hdr, hdr99k, h99k_len, cudaMemcpyHostToDevice);

    cortex_test_kernel<<<1, 1>>>(d_hdr, h99k_len, d_seed, seed_len, d_sp, d_hash);
    cudaDeviceSynchronize();

    uint8_t res99k[32];
    cudaMemcpy(res99k, d_hash, 32, cudaMemcpyDeviceToHost);

    const uint8_t exp99k[32] = {
        0x91, 0x2f, 0x8c, 0xb7, 0xed, 0x73, 0x77, 0x36,
        0x58, 0xaf, 0x2f, 0x42, 0x12, 0xaa, 0x40, 0xbb,
        0x36, 0x5d, 0x1a, 0x5a, 0x20, 0x8e, 0xb0, 0x9c,
        0xd6, 0x6e, 0x56, 0x7b, 0x3c, 0xf7, 0x0a, 0x5c
    };
    if (memcmp(res99k, exp99k, 32) != 0) {
        cudaFree(d_sp); cudaFree(d_hash); cudaFree(d_hdr); cudaFree(d_seed);
        return 0;
    }

    // Test Vector v2.1 Hard Fork
    const char* seed_v2 = "reticulum-randomx-v2-epoch-17";
    int s_v2_len = strlen(seed_v2);
    cudaMemcpy(d_seed, seed_v2, s_v2_len, cudaMemcpyHostToDevice);
    cudaMemcpy(d_hdr, hdr123, h123_len, cudaMemcpyHostToDevice);

    cortex_test_v2_kernel<<<1, 1>>>(d_hdr, h123_len, d_seed, s_v2_len, d_hash);
    cudaDeviceSynchronize();

    uint8_t res_v2[32];
    cudaMemcpy(res_v2, d_hash, 32, cudaMemcpyDeviceToHost);

    const uint8_t exp_v2[32] = {
        0x4a, 0x26, 0xd0, 0x92, 0xa4, 0x83, 0x60, 0x7d,
        0xa8, 0x18, 0xf9, 0xe2, 0x76, 0xdb, 0x2c, 0x5d,
        0x96, 0x24, 0xe8, 0x9d, 0xab, 0x9b, 0xe5, 0x46,
        0x2b, 0x79, 0x68, 0x07, 0x9e, 0x6b, 0xf2, 0x2f
    };
    if (memcmp(res_v2, exp_v2, 32) != 0) {
        cudaFree(d_sp); cudaFree(d_hash); cudaFree(d_hdr); cudaFree(d_seed);
        return 0;
    }

    // Test Vector v2.2 Hard Fork (2MB scratchpad)
    int64_t* d_sp_v22 = NULL;
    if (cudaMalloc(&d_sp_v22, 262144 * sizeof(int64_t)) == cudaSuccess) {
        const char* seed_v22 = "reticulum-randomx-v2.2-epoch-18";
        int s_v22_len = strlen(seed_v22);
        const char* hdr_v22 = "test_header";
        int h_v22_len = strlen(hdr_v22);

        cudaMemcpy(d_seed, seed_v22, s_v22_len, cudaMemcpyHostToDevice);
        cudaMemcpy(d_hdr, hdr_v22, h_v22_len, cudaMemcpyHostToDevice);

        cortex_test_v22_kernel<<<1, 1>>>(d_hdr, h_v22_len, d_seed, s_v22_len, d_sp_v22, d_hash);
        cudaDeviceSynchronize();

        uint8_t res_v22[32];
        cudaMemcpy(res_v22, d_hash, 32, cudaMemcpyDeviceToHost);
        cudaFree(d_sp_v22);

        const uint8_t exp_v22[32] = {
            0x3c, 0xd0, 0x83, 0x24, 0xba, 0x2b, 0xbc, 0x68,
            0x8f, 0xce, 0x17, 0xa9, 0x9a, 0x6b, 0xad, 0xf1,
            0x85, 0xca, 0x8d, 0x28, 0x5f, 0x09, 0x35, 0x0c,
            0x6f, 0xbf, 0xbf, 0x3e, 0x17, 0xc2, 0xca, 0x88
        };
        if (memcmp(res_v22, exp_v22, 32) != 0) {
            cudaFree(d_sp); cudaFree(d_hash); cudaFree(d_hdr); cudaFree(d_seed);
            return 0;
        }
    } else {
        cudaFree(d_sp); cudaFree(d_hash); cudaFree(d_hdr); cudaFree(d_seed);
        return 0;
    }

    cudaFree(d_sp); cudaFree(d_hash); cudaFree(d_hdr); cudaFree(d_seed);
    return 1;
}

}

