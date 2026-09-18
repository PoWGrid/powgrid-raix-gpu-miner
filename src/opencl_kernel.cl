#pragma OPENCL EXTENSION cl_khr_fp64 : enable

#define ROTR64(x, n) (rotate((ulong)(x), 64UL - (ulong)(n)))
#define CH64(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ64(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_512(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define EP1_512(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define SIG0_512(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define SIG1_512(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

constant ulong K512[80] = {
    0x428a2f98d728ae22UL, 0x7137449123ef65cdUL, 0xb5c0fbcfec4d3b2fUL, 0xe9b5dba58189dbbcUL,
    0x3956c25bf348b538UL, 0x59f111f1b605d019UL, 0x923f82a4af194f9bUL, 0xab1c5ed5da6d8118UL,
    0xd807aa98a3030242UL, 0x12835b0145706fbeUL, 0x243185be4ee4b28cUL, 0x550c7dc3d5ffb4e2UL,
    0x72be5d74f27b896fUL, 0x80deb1fe3b1696b1UL, 0x9bdc06a725c71235UL, 0xc19bf174cf692694UL,
    0xe49b69c19ef14ad2UL, 0xefbe4786384f25e3UL, 0x0fc19dc68b8cd5b5UL, 0x240ca1cc77ac9c65UL,
    0x2de92c6f592b0275UL, 0x4a7484aa6ea6e483UL, 0x5cb0a9dcbd41fbd4UL, 0x76f988da831153b5UL,
    0x983e5152ee66dfabUL, 0xa831c66d2db43210UL, 0xb00327c898fb213fUL, 0xbf597fc7beef0ee4UL,
    0xc6e00bf33da88fc2UL, 0xd5a79147930aa725UL, 0x06ca6351e003826fUL, 0x142929670a0e6e70UL,
    0x27b70a8546d22ffcUL, 0x2e1b21385c26c926UL, 0x4d2c6dfc5ac42aedUL, 0x53380d139d95b3dfUL,
    0x650a73548baf63deUL, 0x766a0abb3c77b2a8UL, 0x81c2c92e47edaee6UL, 0x92722c851482353bUL,
    0xa2bfe8a14cf10364UL, 0xa81a664bbc423001UL, 0xc24b8b70d0f89791UL, 0xc76c51a30654be30UL,
    0xd192e819d6ef5218UL, 0xd69906245565a910UL, 0xf40e35855771202aUL, 0x106aa07032bbd1b8UL,
    0x19a4c116b8d2d0c8UL, 0x1e376c085141ab53UL, 0x2748774cdf8eeb99UL, 0x34b0bcb5e19b48a8UL,
    0x391c0cb3c5c95a63UL, 0x4ed8aa4ae3418acbUL, 0x5b9cca4f7763e373UL, 0x682e6ff3d6b2b8a3UL,
    0x748f82ee5defb2fcUL, 0x78a5636f43172f60UL, 0x84c87814a1f0ab72UL, 0x8cc702081a6439ecUL,
    0x90befffa23631e28UL, 0xa4506cebde82bde9UL, 0xbef9a3f7b2c67915UL, 0xc67178f2e372532bUL,
    0xca273eceea26619cUL, 0xd186b8c721c0c207UL, 0xeada7dd6cde0eb1eUL, 0xf57d4f7fee6ed178UL,
    0x06f067aa72176fbaUL, 0x0a637dc5a2c898a6UL, 0x113f9804bef90daeUL, 0x1b710b35131c471bUL,
    0x28db77f523047d84UL, 0x32caab7b40c72493UL, 0x3c9ebe0a15c9bebcUL, 0x431d67c49c100d4cUL,
    0x4cc5d4becb3e42b6UL, 0x597f299cfc657e2aUL, 0x5fcb6fab3ad6faecUL, 0x6c44198c4a475817UL
};

void sha512_transform(__private ulong state[8], const __private uchar data[128]) {
    ulong w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((ulong)data[i * 8 + 0] << 56) |
               ((ulong)data[i * 8 + 1] << 48) |
               ((ulong)data[i * 8 + 2] << 40) |
               ((ulong)data[i * 8 + 3] << 32) |
               ((ulong)data[i * 8 + 4] << 24) |
               ((ulong)data[i * 8 + 5] << 16) |
               ((ulong)data[i * 8 + 6] << 8)  |
               ((ulong)data[i * 8 + 7]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = SIG1_512(w[i - 2]) + w[i - 7] + SIG0_512(w[i - 15]) + w[i - 16];
    }
    ulong a = state[0], b = state[1], c = state[2], d = state[3];
    ulong e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 80; i++) {
        ulong t1 = h + EP1_512(e) + CH64(e, f, g) + K512[i] + w[i];
        ulong t2 = EP0_512(a) + MAJ64(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void opencl_sha512(const __private uchar* data, int len, __private uchar digest[64]) {
    ulong state[8] = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };
    uchar block[128];
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
    ulong bits = (ulong)len * 8UL;
    block[120] = (uchar)(bits >> 56);
    block[121] = (uchar)(bits >> 48);
    block[122] = (uchar)(bits >> 40);
    block[123] = (uchar)(bits >> 32);
    block[124] = (uchar)(bits >> 24);
    block[125] = (uchar)(bits >> 16);
    block[126] = (uchar)(bits >> 8);
    block[127] = (uchar)(bits);
    sha512_transform(state, block);
    for (int i = 0; i < 8; i++) {
        digest[i * 8 + 0] = (uchar)(state[i] >> 56);
        digest[i * 8 + 1] = (uchar)(state[i] >> 48);
        digest[i * 8 + 2] = (uchar)(state[i] >> 40);
        digest[i * 8 + 3] = (uchar)(state[i] >> 32);
        digest[i * 8 + 4] = (uchar)(state[i] >> 24);
        digest[i * 8 + 5] = (uchar)(state[i] >> 16);
        digest[i * 8 + 6] = (uchar)(state[i] >> 8);
        digest[i * 8 + 7] = (uchar)(state[i]);
    }
}

void opencl_sha512_64bytes(const __private uchar key_in[64], __private uchar digest[64]) {
    ulong state[8] = {
        0x6a09e667f3bcc908UL, 0xbb67ae8584caa73bUL,
        0x3c6ef372fe94f82bUL, 0xa54ff53a5f1d36f1UL,
        0x510e527fade682d1UL, 0x9b05688c2b3e6c1fUL,
        0x1f83d9abfb41bd6bUL, 0x5be0cd19137e2179UL
    };
    uchar block[128];
    for (int i = 0; i < 64; i++) block[i] = key_in[i];
    block[64] = 0x80;
    for (int i = 65; i < 120; i++) block[i] = 0;
    block[120] = 0; block[121] = 0; block[122] = 0; block[123] = 0;
    block[124] = 0; block[125] = 0; block[126] = 2; block[127] = 0;
    sha512_transform(state, block);
    for (int i = 0; i < 8; i++) {
        digest[i * 8 + 0] = (uchar)(state[i] >> 56);
        digest[i * 8 + 1] = (uchar)(state[i] >> 48);
        digest[i * 8 + 2] = (uchar)(state[i] >> 40);
        digest[i * 8 + 3] = (uchar)(state[i] >> 32);
        digest[i * 8 + 4] = (uchar)(state[i] >> 24);
        digest[i * 8 + 5] = (uchar)(state[i] >> 16);
        digest[i * 8 + 6] = (uchar)(state[i] >> 8);
        digest[i * 8 + 7] = (uchar)(state[i]);
    }
}

#define ROTR32(x, n) (rotate((uint)(x), 32U - (uint)(n)))
#define CH32(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ32(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0_256(x) (ROTR32(x, 2) ^ ROTR32(x, 13) ^ ROTR32(x, 22))
#define EP1_256(x) (ROTR32(x, 6) ^ ROTR32(x, 11) ^ ROTR32(x, 25))
#define SIG0_256(x) (ROTR32(x, 7) ^ ROTR32(x, 18) ^ ((x) >> 3))
#define SIG1_256(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^ ((x) >> 10))

constant uint K256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U, 0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

void sha256_transform(__private uint state[8], const __private uchar data[64]) {
    uint w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint)data[i * 4 + 0] << 24) |
               ((uint)data[i * 4 + 1] << 16) |
               ((uint)data[i * 4 + 2] << 8)  |
               ((uint)data[i * 4 + 3]);
    }
    for (int i = 16; i < 64; i++) {
        w[i] = SIG1_256(w[i - 2]) + w[i - 7] + SIG0_256(w[i - 15]) + w[i - 16];
    }
    uint a = state[0], b = state[1], c = state[2], d = state[3];
    uint e = state[4], f = state[5], g = state[6], h = state[7];
    for (int i = 0; i < 64; i++) {
        uint t1 = h + EP1_256(e) + CH32(e, f, g) + K256[i] + w[i];
        uint t2 = EP0_256(a) + MAJ32(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void opencl_sha256_64bytes(const __private uchar data[64], __private uchar digest[32]) {
    uint state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    sha256_transform(state, data);
    uchar block[64];
    block[0] = 0x80;
    for (int i = 1; i < 56; i++) block[i] = 0;
    block[56] = 0; block[57] = 0; block[58] = 0; block[59] = 0;
    block[60] = 0; block[61] = 0; block[62] = 2; block[63] = 0;
    sha256_transform(state, block);
    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uchar)(state[i] >> 24);
        digest[i * 4 + 1] = (uchar)(state[i] >> 16);
        digest[i * 4 + 2] = (uchar)(state[i] >> 8);
        digest[i * 4 + 3] = (uchar)(state[i]);
    }
}

void opencl_sha256_sponge(const __private uchar h1[32], const __private long sp_head[64], __private uchar digest[32]) {
    uint state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    uchar block[64];

    // Block 0: h1[0..31] + sp_head[0..3]
    for (int i = 0; i < 32; i++) block[i] = h1[i];
    for (int i = 0; i < 4; i++) {
        ulong val = (ulong)sp_head[i];
        for (int b = 0; b < 8; b++) block[32 + i * 8 + b] = (uchar)(val >> (b * 8));
    }
    sha256_transform(state, block);

    // Blocks 1..7: sp_head[4 + (blk-1)*8 .. 4 + (blk-1)*8 + 7]
    for (int blk = 1; blk <= 7; blk++) {
        int baseIdx = 4 + (blk - 1) * 8;
        for (int i = 0; i < 8; i++) {
            ulong val = (ulong)sp_head[baseIdx + i];
            for (int b = 0; b < 8; b++) block[i * 8 + b] = (uchar)(val >> (b * 8));
        }
        sha256_transform(state, block);
    }

    // Block 8: sp_head[60..63] + padding + 4352 bits
    for (int i = 0; i < 4; i++) {
        ulong val = (ulong)sp_head[60 + i];
        for (int b = 0; b < 8; b++) block[i * 8 + b] = (uchar)(val >> (b * 8));
    }
    block[32] = 0x80;
    for (int i = 33; i < 56; i++) block[i] = 0;
    ulong bits = 544UL * 8UL;
    for (int i = 0; i < 8; i++) block[56 + i] = (uchar)(bits >> ((7 - i) * 8));
    sha256_transform(state, block);

    for (int i = 0; i < 8; i++) {
        digest[i * 4 + 0] = (uchar)(state[i] >> 24);
        digest[i * 4 + 1] = (uchar)(state[i] >> 16);
        digest[i * 4 + 2] = (uchar)(state[i] >> 8);
        digest[i * 4 + 3] = (uchar)(state[i]);
    }
}

int u64_to_str_cl(ulong val, __private char* out) {
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

#define MAX_SOLUTIONS_CL 32

__kernel void cortex_opencl_mine(
    __global const char* d_prefix, int prefix_len,
    __global const char* d_suffix, int suffix_len,
    __global const char* d_seed, int seed_len,
    int target_diff,
    ulong target_u64,
    ulong base_nonce,
    int nonces_per_thread,
    __global long* d_scratchpads,
    volatile __global int* d_found_count,
    __global ulong* d_found_nonces
) {
    int tid = get_global_id(0);
    int total_threads = get_global_size(0);
    __global long* scratchpad = d_scratchpads + (size_t)tid * 4096;

    for (int iter_nonce = 0; iter_nonce < nonces_per_thread; iter_nonce++) {
        ulong nonce = base_nonce + (ulong)iter_nonce * (ulong)total_threads + (ulong)tid;

        char header[512];
        for (int i = 0; i < prefix_len; i++) header[i] = d_prefix[i];
        int nonce_len = u64_to_str_cl(nonce, header + prefix_len);
        int cur_len = prefix_len + nonce_len;
        for (int i = 0; i < suffix_len; i++) header[cur_len + i] = d_suffix[i];
        int header_len = cur_len + suffix_len;

        // 1. key = sha512(header + ":" + seed)
        uchar h_s[512];
        for (int i = 0; i < header_len; i++) h_s[i] = (uchar)header[i];
        h_s[header_len] = ':';
        for (int i = 0; i < seed_len; i++) h_s[header_len + 1 + i] = (uchar)d_seed[i];
        int hs_len = header_len + 1 + seed_len;

        uchar key[64];
        opencl_sha512(h_s, hs_len, key);

        for (int i = 0; i < 4096; i += 8) {
            for (int j = 0; j < 8; j++) {
                ulong val = ((ulong)key[j * 8 + 0]) |
                            (((ulong)key[j * 8 + 1]) << 8) |
                            (((ulong)key[j * 8 + 2]) << 16) |
                            (((ulong)key[j * 8 + 3]) << 24) |
                            (((ulong)key[j * 8 + 4]) << 32) |
                            (((ulong)key[j * 8 + 5]) << 40) |
                            (((ulong)key[j * 8 + 6]) << 48) |
                            (((ulong)key[j * 8 + 7]) << 56);
                scratchpad[i + j] = (long)val;
            }
            if (i % 64 == 0) {
                uchar next_key[64];
                opencl_sha512_64bytes(key, next_key);
                for (int k = 0; k < 64; k++) key[k] = next_key[k];
            }
        }

        // 2. initialDigest = sha512(seed + ":" + header)
        uchar s_h[512];
        for (int i = 0; i < seed_len; i++) s_h[i] = (uchar)d_seed[i];
        s_h[seed_len] = ':';
        for (int i = 0; i < header_len; i++) s_h[seed_len + 1 + i] = (uchar)header[i];
        int sh_len = seed_len + 1 + header_len;

        uchar initialDigest[64];
        opencl_sha512(s_h, sh_len, initialDigest);

        long r[8];
        double f[4];
        for (int i = 0; i < 8; i++) {
            ulong val = ((ulong)initialDigest[i * 8 + 0]) |
                        (((ulong)initialDigest[i * 8 + 1]) << 8) |
                        (((ulong)initialDigest[i * 8 + 2]) << 16) |
                        (((ulong)initialDigest[i * 8 + 3]) << 24) |
                        (((ulong)initialDigest[i * 8 + 4]) << 32) |
                        (((ulong)initialDigest[i * 8 + 5]) << 40) |
                        (((ulong)initialDigest[i * 8 + 6]) << 48) |
                        (((ulong)initialDigest[i * 8 + 7]) << 56);
            r[i] = (long)val;
        }
        for (int i = 0; i < 4; i++) {
            f[i] = (double)(r[i] % 1000000) / 1000.0;
        }

        // 3. VM Execution
        const int mask = 4095;
        for (int iter = 0; iter < 64; iter++) {
            int opCode = (initialDigest[iter % 64] ^ (uchar)d_seed[iter % seed_len]) % 10;
            int srcIdx = (iter + 1) % 8;
            int dstIdx = iter % 8;
            uint u32 = (uint)r[dstIdx];
            int memIdx = (int)(u32 & mask);

            switch (opCode) {
                case 0: r[dstIdx] = r[dstIdx] + scratchpad[memIdx]; break;
                case 1: r[dstIdx] = r[dstIdx] - r[srcIdx]; break;
                case 2: r[dstIdx] = r[dstIdx] * (r[srcIdx] | 1UL); break;
                case 3: r[dstIdx] = r[dstIdx] ^ r[srcIdx]; break;
                case 4: {
                    int shift = (int)(r[srcIdx] & 63);
                    long sr = r[dstIdx];
                    long right = (shift == 0) ? (sr < 0 ? -1 : 0) : (sr >> (64 - shift));
                    ulong ur = ((ulong)sr << shift) | (ulong)right;
                    r[dstIdx] = (long)ur;
                    break;
                }
                case 5: scratchpad[memIdx] = r[dstIdx] ^ (long)iter; break;
                case 6: {
                    f[dstIdx % 4] = f[dstIdx % 4] + f[srcIdx % 4];
                    long v = (long)floor(fabs(f[dstIdx % 4]));
                    r[dstIdx] = r[dstIdx] ^ v;
                    break;
                }
                case 7: {
                    f[dstIdx % 4] = f[dstIdx % 4] * 1.00001;
                    long v = (long)floor(fabs(f[dstIdx % 4]));
                    r[dstIdx] = r[dstIdx] ^ v;
                    break;
                }
                case 8: {
                    int nextMem = (memIdx + 64) & mask;
                    long temp = scratchpad[memIdx];
                    scratchpad[memIdx] = scratchpad[nextMem];
                    scratchpad[nextMem] = temp;
                    break;
                }
                case 9: r[dstIdx] = -r[dstIdx]; break;
            }
        }

        // 4. Final Sponge Digest
        uchar finalBuf[64];
        for (int i = 0; i < 8; i++) {
            ulong val = (ulong)r[i];
            finalBuf[i * 8 + 0] = (uchar)(val);
            finalBuf[i * 8 + 1] = (uchar)(val >> 8);
            finalBuf[i * 8 + 2] = (uchar)(val >> 16);
            finalBuf[i * 8 + 3] = (uchar)(val >> 24);
            finalBuf[i * 8 + 4] = (uchar)(val >> 32);
            finalBuf[i * 8 + 5] = (uchar)(val >> 40);
            finalBuf[i * 8 + 6] = (uchar)(val >> 48);
            finalBuf[i * 8 + 7] = (uchar)(val >> 56);
        }
        uchar h1[32];
        opencl_sha256_64bytes(finalBuf, h1);

        long sp_head[64];
        for (int i = 0; i < 64; i++) sp_head[i] = scratchpad[i];

        uchar h2[32];
        opencl_sha256_sponge(h1, sp_head, h2);

        // Check difficulty
        bool match = false;
        if (target_u64 > 0) {
            ulong h2_u64 = ((ulong)h2[0] << 56) | ((ulong)h2[1] << 48) |
                           ((ulong)h2[2] << 40) | ((ulong)h2[3] << 32) |
                           ((ulong)h2[4] << 24) | ((ulong)h2[5] << 16) |
                           ((ulong)h2[6] << 8)  | ((ulong)h2[7]);
            match = (h2_u64 <= target_u64);
        } else {
            match = true;
            for (int k = 0; k < target_diff; k++) {
                uchar nibble = (k % 2 == 0) ? (h2[k / 2] >> 4) : (h2[k / 2] & 0x0F);
                if (nibble != 0) { match = false; break; }
            }
        }

        if (match) {
            int slot = atomic_add(d_found_count, 1);
            if (slot < MAX_SOLUTIONS_CL) {
                d_found_nonces[slot] = nonce;
            }
        }
    }
}

__kernel void test_opencl_single_hash(
    __global const char* header_in, int header_len,
    __global const char* seed_in, int seed_len,
    __global long* d_scratchpads,
    __global uchar* out_hash
) {
    int tid = get_global_id(0);
    __global long* scratchpad = d_scratchpads + (size_t)tid * 4096;

    char header[512];
    for (int i = 0; i < header_len; i++) header[i] = header_in[i];

    uchar h_s[512];
    for (int i = 0; i < header_len; i++) h_s[i] = (uchar)header[i];
    h_s[header_len] = ':';
    for (int i = 0; i < seed_len; i++) h_s[header_len + 1 + i] = (uchar)seed_in[i];
    int hs_len = header_len + 1 + seed_len;

    uchar key[64];
    opencl_sha512(h_s, hs_len, key);

    for (int i = 0; i < 4096; i += 8) {
        for (int j = 0; j < 8; j++) {
            ulong val = ((ulong)key[j * 8 + 0]) |
                        (((ulong)key[j * 8 + 1]) << 8) |
                        (((ulong)key[j * 8 + 2]) << 16) |
                        (((ulong)key[j * 8 + 3]) << 24) |
                        (((ulong)key[j * 8 + 4]) << 32) |
                        (((ulong)key[j * 8 + 5]) << 40) |
                        (((ulong)key[j * 8 + 6]) << 48) |
                        (((ulong)key[j * 8 + 7]) << 56);
            scratchpad[i + j] = (long)val;
        }
        if (i % 64 == 0) {
            uchar next_key[64];
            opencl_sha512_64bytes(key, next_key);
            for (int k = 0; k < 64; k++) key[k] = next_key[k];
        }
    }

    uchar s_h[512];
    for (int i = 0; i < seed_len; i++) s_h[i] = (uchar)seed_in[i];
    s_h[seed_len] = ':';
    for (int i = 0; i < header_len; i++) s_h[seed_len + 1 + i] = (uchar)header[i];
    int sh_len = seed_len + 1 + header_len;

    uchar initialDigest[64];
    opencl_sha512(s_h, sh_len, initialDigest);

    long r[8];
    double f[4];
    for (int i = 0; i < 8; i++) {
        ulong val = ((ulong)initialDigest[i * 8 + 0]) |
                    (((ulong)initialDigest[i * 8 + 1]) << 8) |
                    (((ulong)initialDigest[i * 8 + 2]) << 16) |
                    (((ulong)initialDigest[i * 8 + 3]) << 24) |
                    (((ulong)initialDigest[i * 8 + 4]) << 32) |
                    (((ulong)initialDigest[i * 8 + 5]) << 40) |
                    (((ulong)initialDigest[i * 8 + 6]) << 48) |
                    (((ulong)initialDigest[i * 8 + 7]) << 56);
        r[i] = (long)val;
    }
    for (int i = 0; i < 4; i++) {
        f[i] = (double)(r[i] % 1000000) / 1000.0;
    }

    const int mask = 4095;
    for (int iter = 0; iter < 64; iter++) {
        int opCode = (initialDigest[iter % 64] ^ (uchar)seed_in[iter % seed_len]) % 10;
        int srcIdx = (iter + 1) % 8;
        int dstIdx = iter % 8;
        uint u32 = (uint)r[dstIdx];
        int memIdx = (int)(u32 & mask);

        switch (opCode) {
            case 0: r[dstIdx] = r[dstIdx] + scratchpad[memIdx]; break;
            case 1: r[dstIdx] = r[dstIdx] - r[srcIdx]; break;
            case 2: r[dstIdx] = r[dstIdx] * (r[srcIdx] | 1UL); break;
            case 3: r[dstIdx] = r[dstIdx] ^ r[srcIdx]; break;
            case 4: {
                int shift = (int)(r[srcIdx] & 63);
                long sr = r[dstIdx];
                long right = (shift == 0) ? (sr < 0 ? -1 : 0) : (sr >> (64 - shift));
                ulong ur = ((ulong)sr << shift) | (ulong)right;
                r[dstIdx] = (long)ur;
                break;
            }
            case 5: scratchpad[memIdx] = r[dstIdx] ^ (long)iter; break;
            case 6: {
                f[dstIdx % 4] = f[dstIdx % 4] + f[srcIdx % 4];
                long v = (long)floor(fabs(f[dstIdx % 4]));
                r[dstIdx] = r[dstIdx] ^ v;
                break;
            }
            case 7: {
                f[dstIdx % 4] = f[dstIdx % 4] * 1.00001;
                long v = (long)floor(fabs(f[dstIdx % 4]));
                r[dstIdx] = r[dstIdx] ^ v;
                break;
            }
            case 8: {
                int nextMem = (memIdx + 64) & mask;
                long temp = scratchpad[memIdx];
                scratchpad[memIdx] = scratchpad[nextMem];
                scratchpad[nextMem] = temp;
                break;
            }
            case 9: r[dstIdx] = -r[dstIdx]; break;
        }
    }

    uchar finalBuf[64];
    for (int i = 0; i < 8; i++) {
        ulong val = (ulong)r[i];
        finalBuf[i * 8 + 0] = (uchar)(val);
        finalBuf[i * 8 + 1] = (uchar)(val >> 8);
        finalBuf[i * 8 + 2] = (uchar)(val >> 16);
        finalBuf[i * 8 + 3] = (uchar)(val >> 24);
        finalBuf[i * 8 + 4] = (uchar)(val >> 32);
        finalBuf[i * 8 + 5] = (uchar)(val >> 40);
        finalBuf[i * 8 + 6] = (uchar)(val >> 48);
        finalBuf[i * 8 + 7] = (uchar)(val >> 56);
    }
    uchar h1[32];
    opencl_sha256_64bytes(finalBuf, h1);

    long sp_head[64];
    for (int i = 0; i < 64; i++) sp_head[i] = scratchpad[i];

    uchar h2[32];
    opencl_sha256_sponge(h1, sp_head, h2);

    for (int i = 0; i < 32; i++) out_hash[i] = h2[i];
}
