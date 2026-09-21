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

void opencl_sha256(const __private uchar* data, int len, __private uchar digest[32]) {
    uint state[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    uchar block[64];
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
    ulong bits = (ulong)len * 8UL;
    for (int i = 0; i < 8; i++) block[56 + i] = (uchar)(bits >> ((7 - i) * 8));
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

// ----------------------------------------------------------------------------------
// RandomX v2.1 (Hard Fork) OpenCL Implementation with AES T-Tables & Keystream Cache
// ----------------------------------------------------------------------------------

constant uchar AES_SBOX_CL[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

constant uint AES_RCON_CL[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

constant uint AES_TE0_CL[256] = {
    0xc66363a5U, 0xf87c7c84U, 0xee777799U, 0xf67b7b8dU,
    0xfff2f20dU, 0xd66b6bbdU, 0xde6f6fb1U, 0x91c5c554U,
    0x60303050U, 0x02010103U, 0xce6767a9U, 0x562b2b7dU,
    0xe7fefe19U, 0xb5d7d762U, 0x4dababe6U, 0xec76769aU,
    0x8fcaca45U, 0x1f82829dU, 0x89c9c940U, 0xfa7d7d87U,
    0xeffafa15U, 0xb25959ebU, 0x8e4747c9U, 0xfbf0f00bU,
    0x41adadecU, 0xb3d4d467U, 0x5fa2a2fdU, 0x45afafeaU,
    0x239c9cbfU, 0x53a4a4f7U, 0xe4727296U, 0x9bc0c05bU,
    0x75b7b7c2U, 0xe1fdfd1cU, 0x3d9393aeU, 0x4c26266aU,
    0x6c36365aU, 0x7e3f3f41U, 0xf5f7f702U, 0x83cccc4fU,
    0x6834345cU, 0x51a5a5f4U, 0xd1e5e534U, 0xf9f1f108U,
    0xe2717193U, 0xabd8d873U, 0x62313153U, 0x2a15153fU,
    0x0804040cU, 0x95c7c752U, 0x46232365U, 0x9dc3c35eU,
    0x30181828U, 0x379696a1U, 0x0a05050fU, 0x2f9a9ab5U,
    0x0e070709U, 0x24121236U, 0x1b80809bU, 0xdfe2e23dU,
    0xcdebeb26U, 0x4e272769U, 0x7fb2b2cdU, 0xea75759fU,
    0x1209091bU, 0x1d83839eU, 0x582c2c74U, 0x341a1a2eU,
    0x361b1b2dU, 0xdc6e6eb2U, 0xb45a5aeeU, 0x5ba0a0fbU,
    0xa45252f6U, 0x763b3b4dU, 0xb7d6d661U, 0x7db3b3ceU,
    0x5229297bU, 0xdde3e33eU, 0x5e2f2f71U, 0x13848497U,
    0xa65353f5U, 0xb9d1d168U, 0x00000000U, 0xc1eded2cU,
    0x40202060U, 0xe3fcfc1fU, 0x79b1b1c8U, 0xb65b5bedU,
    0xd46a6abeU, 0x8dcbcb46U, 0x67bebed9U, 0x7239394bU,
    0x944a4adeU, 0x984c4cd4U, 0xb05858e8U, 0x85cfcf4aU,
    0xbbd0d06bU, 0xc5efef2aU, 0x4faaaae5U, 0xedfbfb16U,
    0x864343c5U, 0x9a4d4dd7U, 0x66333355U, 0x11858594U,
    0x8a4545cfU, 0xe9f9f910U, 0x04020206U, 0xfe7f7f81U,
    0xa05050f0U, 0x783c3c44U, 0x259f9fbaU, 0x4ba8a8e3U,
    0xa25151f3U, 0x5da3a3feU, 0x804040c0U, 0x058f8f8aU,
    0x3f9292adU, 0x219d9dbcU, 0x70383848U, 0xf1f5f504U,
    0x63bcbcdfU, 0x77b6b6c1U, 0xafdada75U, 0x42212163U,
    0x20101030U, 0xe5ffff1aU, 0xfdf3f30eU, 0xbfd2d26dU,
    0x81cdcd4cU, 0x180c0c14U, 0x26131335U, 0xc3ecec2fU,
    0xbe5f5fe1U, 0x359797a2U, 0x884444ccU, 0x2e171739U,
    0x93c4c457U, 0x55a7a7f2U, 0xfc7e7e82U, 0x7a3d3d47U,
    0xc86464acU, 0xba5d5de7U, 0x3219192bU, 0xe6737395U,
    0xc06060a0U, 0x19818198U, 0x9e4f4fd1U, 0xa3dcdc7fU,
    0x44222266U, 0x542a2a7eU, 0x3b9090abU, 0x0b888883U,
    0x8c4646caU, 0xc7eeee29U, 0x6bb8b8d3U, 0x2814143cU,
    0xa7dede79U, 0xbc5e5ee2U, 0x160b0b1dU, 0xaddbdb76U,
    0xdbe0e03bU, 0x64323256U, 0x743a3a4eU, 0x140a0a1eU,
    0x924949dbU, 0x0c06060aU, 0x4824246cU, 0xb85c5ce4U,
    0x9fc2c25dU, 0xbdd3d36eU, 0x43acacefU, 0xc46262a6U,
    0x399191a8U, 0x319595a4U, 0xd3e4e437U, 0xf279798bU,
    0xd5e7e732U, 0x8bc8c843U, 0x6e373759U, 0xda6d6db7U,
    0x018d8d8cU, 0xb1d5d564U, 0x9c4e4ed2U, 0x49a9a9e0U,
    0xd86c6cb4U, 0xac5656faU, 0xf3f4f407U, 0xcfeaea25U,
    0xca6565afU, 0xf47a7a8eU, 0x47aeaee9U, 0x10080818U,
    0x6fbabad5U, 0xf0787888U, 0x4a25256fU, 0x5c2e2e72U,
    0x381c1c24U, 0x57a6a6f1U, 0x73b4b4c7U, 0x97c6c651U,
    0xcbe8e823U, 0xa1dddd7cU, 0xe874749cU, 0x3e1f1f21U,
    0x964b4bddU, 0x61bdbddcU, 0x0d8b8b86U, 0x0f8a8a85U,
    0xe0707090U, 0x7c3e3e42U, 0x71b5b5c4U, 0xcc6666aaU,
    0x904848d8U, 0x06030305U, 0xf7f6f601U, 0x1c0e0e12U,
    0xc26161a3U, 0x6a35355fU, 0xae5757f9U, 0x69b9b9d0U,
    0x17868691U, 0x99c1c158U, 0x3a1d1d27U, 0x279e9eb9U,
    0xd9e1e138U, 0xebf8f813U, 0x2b9898b3U, 0x22111133U,
    0xd26969bbU, 0xa9d9d970U, 0x078e8e89U, 0x339494a7U,
    0x2d9b9bb6U, 0x3c1e1e22U, 0x15878792U, 0xc9e9e920U,
    0x87cece49U, 0xaa5555ffU, 0x50282878U, 0xa5dfdf7aU,
    0x038c8c8fU, 0x59a1a1f8U, 0x09898980U, 0x1a0d0d17U,
    0x65bfbfdaU, 0xd7e6e631U, 0x844242c6U, 0xd06868b8U,
    0x824141c3U, 0x299999b0U, 0x5a2d2d77U, 0x1e0f0f11U,
    0x7bb0b0cbU, 0xa85454fcU, 0x6dbbbbd6U, 0x2c16163aU
};

inline uint cl_bswap32(uint x) {
    return ((x >> 24) & 0xffU) | ((x >> 8) & 0xff00U) | ((x << 8) & 0xff0000U) | ((x << 24) & 0xff000000U);
}

#define AES_ROTR32_CL(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define AES_TE1_CL(b) AES_ROTR32_CL(AES_TE0_CL[b], 8)
#define AES_TE2_CL(b) AES_ROTR32_CL(AES_TE0_CL[b], 16)
#define AES_TE3_CL(b) AES_ROTR32_CL(AES_TE0_CL[b], 24)

inline uint aes_sub_word_cl(uint w) {
    return ((uint)AES_SBOX_CL[(w >> 24) & 0xff] << 24) |
           ((uint)AES_SBOX_CL[(w >> 16) & 0xff] << 16) |
           ((uint)AES_SBOX_CL[(w >> 8) & 0xff] << 8) |
           ((uint)AES_SBOX_CL[w & 0xff]);
}

inline uint aes_rot_word_cl(uint w) {
    return (w << 8) | (w >> 24);
}

void aes256_key_expansion_cl(const __private uchar key[32], __private uint rk[15][4]) {
    uint w[60];
    #pragma unroll
    for (int i = 0; i < 8; i++) {
        w[i] = ((uint)key[i * 4 + 0] << 24) |
               ((uint)key[i * 4 + 1] << 16) |
               ((uint)key[i * 4 + 2] << 8)  |
               ((uint)key[i * 4 + 3]);
    }
    #pragma unroll
    for (int i = 8; i < 60; i++) {
        uint temp = w[i - 1];
        if (i % 8 == 0) {
            temp = aes_sub_word_cl(aes_rot_word_cl(temp)) ^ (AES_RCON_CL[(i / 8) - 1] << 24);
        } else if (i % 8 == 4) {
            temp = aes_sub_word_cl(temp);
        }
        w[i] = w[i - 8] ^ temp;
    }
    #pragma unroll
    for (int r = 0; r < 15; r++) {
        #pragma unroll
        for (int c = 0; c < 4; c++) {
            rk[r][c] = w[r * 4 + c];
        }
    }
}

inline void aes256_encrypt_block_cl(const __private uint rk[15][4], const __private uint in[4], __private uint out[4]) {
    uint s0 = in[0] ^ rk[0][0];
    uint s1 = in[1] ^ rk[0][1];
    uint s2 = in[2] ^ rk[0][2];
    uint s3 = in[3] ^ rk[0][3];

    #pragma unroll
    for (int r = 1; r < 14; r++) {
        uint t0 = AES_TE0_CL[(s0 >> 24) & 0xff] ^ AES_TE1_CL((uchar)(s1 >> 16)) ^ AES_TE2_CL((uchar)(s2 >> 8)) ^ AES_TE3_CL((uchar)s3) ^ rk[r][0];
        uint t1 = AES_TE0_CL[(s1 >> 24) & 0xff] ^ AES_TE1_CL((uchar)(s2 >> 16)) ^ AES_TE2_CL((uchar)(s3 >> 8)) ^ AES_TE3_CL((uchar)s0) ^ rk[r][1];
        uint t2 = AES_TE0_CL[(s2 >> 24) & 0xff] ^ AES_TE1_CL((uchar)(s3 >> 16)) ^ AES_TE2_CL((uchar)(s0 >> 8)) ^ AES_TE3_CL((uchar)s1) ^ rk[r][2];
        uint t3 = AES_TE0_CL[(s3 >> 24) & 0xff] ^ AES_TE1_CL((uchar)(s0 >> 16)) ^ AES_TE2_CL((uchar)(s1 >> 8)) ^ AES_TE3_CL((uchar)s2) ^ rk[r][3];
        s0 = t0; s1 = t1; s2 = t2; s3 = t3;
    }

    // Round 14 (Final round, no MixColumns)
    out[0] = (((uint)AES_SBOX_CL[(s0 >> 24) & 0xff] << 24) |
              ((uint)AES_SBOX_CL[(s1 >> 16) & 0xff] << 16) |
              ((uint)AES_SBOX_CL[(s2 >> 8) & 0xff] << 8) |
              ((uint)AES_SBOX_CL[s3 & 0xff])) ^ rk[14][0];

    out[1] = (((uint)AES_SBOX_CL[(s1 >> 24) & 0xff] << 24) |
              ((uint)AES_SBOX_CL[(s2 >> 16) & 0xff] << 16) |
              ((uint)AES_SBOX_CL[(s3 >> 8) & 0xff] << 8) |
              ((uint)AES_SBOX_CL[s0 & 0xff])) ^ rk[14][1];

    out[2] = (((uint)AES_SBOX_CL[(s2 >> 24) & 0xff] << 24) |
              ((uint)AES_SBOX_CL[(s3 >> 16) & 0xff] << 16) |
              ((uint)AES_SBOX_CL[(s0 >> 8) & 0xff] << 8) |
              ((uint)AES_SBOX_CL[s1 & 0xff])) ^ rk[14][2];

    out[3] = (((uint)AES_SBOX_CL[(s3 >> 24) & 0xff] << 24) |
              ((uint)AES_SBOX_CL[(s0 >> 16) & 0xff] << 16) |
              ((uint)AES_SBOX_CL[(s1 >> 8) & 0xff] << 8) |
              ((uint)AES_SBOX_CL[s2 & 0xff])) ^ rk[14][3];
}

inline long v2_get_word_cl(
    uint idx,
    const __private uint rk[15][4],
    const __private long spongeHead[64],
    const __private uint writeCacheAddr[48],
    const __private long writeCacheVal[48],
    uint writeCacheCount
) {
    if (idx < 64) {
        return spongeHead[idx];
    }
    for (uint c = 0; c < writeCacheCount; c++) {
        if (writeCacheAddr[c] == idx) {
            return writeCacheVal[c];
        }
    }

    uint blk = idx >> 1;
    uint in_blk[4] = { 0, 0, 0, blk };
    uint ct[4];
    aes256_encrypt_block_cl(rk, in_blk, ct);

    if ((idx & 1) == 0) {
        uint lo = cl_bswap32(ct[0]);
        uint hi = cl_bswap32(ct[1]);
        return (long)(((ulong)hi << 32) | (ulong)lo);
    } else {
        uint lo = cl_bswap32(ct[2]);
        uint hi = cl_bswap32(ct[3]);
        return (long)(((ulong)hi << 32) | (ulong)lo);
    }
}

inline void v2_set_word_cl(
    uint idx,
    long val,
    __private long spongeHead[64],
    __private uint writeCacheAddr[48],
    __private long writeCacheVal[48],
    __private uint* writeCacheCount
) {
    if (idx < 64) {
        spongeHead[idx] = val;
        return;
    }
    for (uint c = 0; c < *writeCacheCount; c++) {
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

__kernel void cortex_opencl_mine_v2(
    __global const char* d_prefix, int prefix_len,
    __global const char* d_suffix, int suffix_len,
    __global const char* d_seed, int seed_len,
    int target_diff,
    ulong target_u64,
    ulong base_nonce,
    int nonces_per_thread,
    volatile __global int* d_found_count,
    __global ulong* d_found_nonces
) {
    int tid = get_global_id(0);
    ulong thread_base = base_nonce + (ulong)tid * (ulong)nonces_per_thread;

    for (int n = 0; n < nonces_per_thread; n++) {
        if (*d_found_count > 0) return;

        ulong nonce = thread_base + (ulong)n;

        char header[384];
        for (int i = 0; i < prefix_len; i++) header[i] = d_prefix[i];
        int nonce_len = u64_to_str_cl(nonce, header + prefix_len);
        int cur_len = prefix_len + nonce_len;
        for (int i = 0; i < suffix_len; i++) header[cur_len + i] = d_suffix[i];
        int header_len = cur_len + suffix_len;

        // 1. seed_key = sha256(header + ":" + seed)
        uchar hs_buf[384];
        for (int i = 0; i < header_len; i++) hs_buf[i] = (uchar)header[i];
        hs_buf[header_len] = ':';
        for (int i = 0; i < seed_len; i++) hs_buf[header_len + 1 + i] = (uchar)d_seed[i];
        int hs_len = header_len + 1 + seed_len;

        uchar seed_key[32];
        opencl_sha256(hs_buf, hs_len, seed_key);

        // 2. initial_digest = sha512(seed + ":" + header)
        uchar sh_buf[384];
        for (int i = 0; i < seed_len; i++) sh_buf[i] = (uchar)d_seed[i];
        sh_buf[seed_len] = ':';
        for (int i = 0; i < header_len; i++) sh_buf[seed_len + 1 + i] = (uchar)header[i];
        int sh_len = seed_len + 1 + header_len;

        uchar initial_digest[64];
        opencl_sha512(sh_buf, sh_len, initial_digest);

        // 3. Initialize registers
        long r[8];
        for (int i = 0; i < 8; i++) {
            ulong val = 0;
            for (int b = 0; b < 8; b++) {
                val |= ((ulong)initial_digest[i * 8 + b]) << (b * 8);
            }
            r[i] = (long)val;
        }

        double f[4];
        for (int i = 0; i < 4; i++) {
            f[i] = (double)(r[i] % 1000000) / 1000.0;
        }

        // Expand AES-256 round keys
        uint rk[15][4];
        aes256_key_expansion_cl(seed_key, rk);

        // Generate first 64 words (512 bytes) of keystream
        long spongeHead[64];
        for (int blk = 0; blk < 32; blk++) {
            uint in_blk[4] = { 0, 0, 0, (uint)blk };
            uint ct[4];
            aes256_encrypt_block_cl(rk, in_blk, ct);

            uint lo0 = cl_bswap32(ct[0]);
            uint hi0 = cl_bswap32(ct[1]);
            spongeHead[blk * 2] = (long)(((ulong)hi0 << 32) | (ulong)lo0);

            uint lo1 = cl_bswap32(ct[2]);
            uint hi1 = cl_bswap32(ct[3]);
            spongeHead[blk * 2 + 1] = (long)(((ulong)hi1 << 32) | (ulong)lo1);
        }

        // Sparse Write Cache
        uint writeCacheAddr[48];
        long writeCacheVal[48];
        uint writeCacheCount = 0;

        #define getWordV2_cl(idx) v2_get_word_cl((idx), rk, spongeHead, writeCacheAddr, writeCacheVal, writeCacheCount)
        #define setWordV2_cl(idx, val) v2_set_word_cl((idx), (val), spongeHead, writeCacheAddr, writeCacheVal, &writeCacheCount)

        // 128-cycle RandomX VM loop
        const uint mask = 262143;
        for (int iter = 0; iter < 128; iter++) {
            uchar opCode = (initial_digest[iter % 64] ^ (uchar)d_seed[iter % seed_len]) % 10;
            int src = (iter + 1) & 7;
            int dst = iter & 7;
            uint memIdx = ((uint)r[dst]) & mask;

            switch (opCode) {
                case 0: r[dst] = r[dst] + getWordV2_cl(memIdx); break;
                case 1: r[dst] = r[dst] - r[src]; break;
                case 2: r[dst] = r[dst] * (r[src] | 1UL); break;
                case 3: r[dst] ^= r[src]; break;
                case 4: {
                    uint shift = (uint)r[src] & 63;
                    long sr = r[dst];
                    long right = (shift == 0) ? ((sr < 0) ? -1L : 0L) : (sr >> (64 - shift));
                    r[dst] = (long)(((ulong)sr << shift) | (ulong)right);
                    break;
                }
                case 5: setWordV2_cl(memIdx, r[dst] ^ (long)iter); break;
                case 6: {
                    f[dst % 4] += f[src % 4];
                    r[dst] ^= (long)floor(fabs(f[dst % 4]));
                    break;
                }
                case 7: {
                    f[dst % 4] *= 1.00001;
                    r[dst] ^= (long)floor(fabs(f[dst % 4]));
                    break;
                }
                case 8: {
                    uint nextMem = (memIdx + 64) & mask;
                    long tmp = getWordV2_cl(memIdx);
                    long tmp2 = getWordV2_cl(nextMem);
                    setWordV2_cl(memIdx, tmp2);
                    setWordV2_cl(nextMem, tmp);
                    break;
                }
                case 9: r[dst] = -r[dst]; break;
            }
        }
        #undef getWordV2_cl
        #undef setWordV2_cl

        // Step 4 Final Sponge Digest
        uchar finalBuf[64];
        for (int i = 0; i < 8; i++) {
            ulong val = (ulong)r[i];
            for (int b = 0; b < 8; b++) {
                finalBuf[i * 8 + b] = (uchar)(val >> (b * 8));
            }
        }

        uchar h1[32];
        opencl_sha256_64bytes(finalBuf, h1);

        uchar h2[32];
        opencl_sha256_sponge(h1, spongeHead, h2);

        // Check target difficulty
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

__kernel void test_opencl_v2_hash(
    __global const char* header_in, int header_len,
    __global const char* seed_in, int seed_len,
    __global uchar* out_hash
) {
    // 1. seed_key = sha256(header + ":" + seed)
    uchar hs_buf[384];
    for (int i = 0; i < header_len; i++) hs_buf[i] = (uchar)header_in[i];
    hs_buf[header_len] = ':';
    for (int i = 0; i < seed_len; i++) hs_buf[header_len + 1 + i] = (uchar)seed_in[i];
    int hs_len = header_len + 1 + seed_len;

    uchar seed_key[32];
    opencl_sha256(hs_buf, hs_len, seed_key);

    // 2. initial_digest = sha512(seed + ":" + header)
    uchar sh_buf[384];
    for (int i = 0; i < seed_len; i++) sh_buf[i] = (uchar)seed_in[i];
    sh_buf[seed_len] = ':';
    for (int i = 0; i < header_len; i++) sh_buf[seed_len + 1 + i] = (uchar)header_in[i];
    int sh_len = seed_len + 1 + header_len;

    uchar initial_digest[64];
    opencl_sha512(sh_buf, sh_len, initial_digest);

    // 3. Initialize registers
    long r[8];
    for (int i = 0; i < 8; i++) {
        ulong val = 0;
        for (int b = 0; b < 8; b++) {
            val |= ((ulong)initial_digest[i * 8 + b]) << (b * 8);
        }
        r[i] = (long)val;
    }

    double f[4];
    for (int i = 0; i < 4; i++) {
        f[i] = (double)(r[i] % 1000000) / 1000.0;
    }

    // Expand AES-256 round keys
    uint rk[15][4];
    aes256_key_expansion_cl(seed_key, rk);

    // Generate first 64 words (512 bytes) of keystream
    long spongeHead[64];
    for (int blk = 0; blk < 32; blk++) {
        uint in_blk[4] = { 0, 0, 0, (uint)blk };
        uint ct[4];
        aes256_encrypt_block_cl(rk, in_blk, ct);

        uint lo0 = cl_bswap32(ct[0]);
        uint hi0 = cl_bswap32(ct[1]);
        spongeHead[blk * 2] = (long)(((ulong)hi0 << 32) | (ulong)lo0);

        uint lo1 = cl_bswap32(ct[2]);
        uint hi1 = cl_bswap32(ct[3]);
        spongeHead[blk * 2 + 1] = (long)(((ulong)hi1 << 32) | (ulong)lo1);
    }

    // Sparse Write Cache
    uint writeCacheAddr[48];
    long writeCacheVal[48];
    uint writeCacheCount = 0;

    #define getWordV2_cl(idx) v2_get_word_cl((idx), rk, spongeHead, writeCacheAddr, writeCacheVal, writeCacheCount)
    #define setWordV2_cl(idx, val) v2_set_word_cl((idx), (val), spongeHead, writeCacheAddr, writeCacheVal, &writeCacheCount)

    // 128-cycle RandomX VM loop
    const uint mask = 262143;
    for (int iter = 0; iter < 128; iter++) {
        uchar opCode = (initial_digest[iter % 64] ^ (uchar)seed_in[iter % seed_len]) % 10;
        int src = (iter + 1) & 7;
        int dst = iter & 7;
        uint memIdx = ((uint)r[dst]) & mask;

        switch (opCode) {
            case 0: r[dst] = r[dst] + getWordV2_cl(memIdx); break;
            case 1: r[dst] = r[dst] - r[src]; break;
            case 2: r[dst] = r[dst] * (r[src] | 1UL); break;
            case 3: r[dst] ^= r[src]; break;
            case 4: {
                uint shift = (uint)r[src] & 63;
                long sr = r[dst];
                long right = (shift == 0) ? ((sr < 0) ? -1L : 0L) : (sr >> (64 - shift));
                r[dst] = (long)(((ulong)sr << shift) | (ulong)right);
                break;
            }
            case 5: setWordV2_cl(memIdx, r[dst] ^ (long)iter); break;
            case 6: {
                f[dst % 4] += f[src % 4];
                r[dst] ^= (long)floor(fabs(f[dst % 4]));
                break;
            }
            case 7: {
                f[dst % 4] *= 1.00001;
                r[dst] ^= (long)floor(fabs(f[dst % 4]));
                break;
            }
            case 8: {
                uint nextMem = (memIdx + 64) & mask;
                long tmp = getWordV2_cl(memIdx);
                long tmp2 = getWordV2_cl(nextMem);
                setWordV2_cl(memIdx, tmp2);
                setWordV2_cl(nextMem, tmp);
                break;
            }
            case 9: r[dst] = -r[dst]; break;
        }
    }
    #undef getWordV2_cl
    #undef setWordV2_cl

    // Step 4 Final Sponge Digest
    uchar finalBuf[64];
    for (int i = 0; i < 8; i++) {
        ulong val = (ulong)r[i];
        for (int b = 0; b < 8; b++) {
            finalBuf[i * 8 + b] = (uchar)(val >> (b * 8));
        }
    }

    uchar h1[32];
    opencl_sha256_64bytes(finalBuf, h1);

    uchar h2[32];
    opencl_sha256_sponge(h1, spongeHead, h2);

    for (int i = 0; i < 32; i++) out_hash[i] = h2[i];
}
