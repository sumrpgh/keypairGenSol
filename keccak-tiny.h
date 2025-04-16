#ifndef KECCAK_TINY_H
#define KECCAK_TINY_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define KECCAK_ROUNDS 24

// 64-bit rotate left
static inline uint64_t ROTL64(uint64_t x, int y) {
    return ((x << y) | (x >> (64 - y)));
}

// Keccak-f1600 permutation
static void keccak_f1600(uint64_t state[25]) {
    // constants
    const uint64_t keccakf_rndc[24] = {
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008
    };
    
    const int keccakf_rotc[24] = {
        1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
        27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };
    
    const int keccakf_piln[24] = {
        10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    // variables
    int i, j, r;
    uint64_t t, bc[5];

    // actual iteration
    for (r = 0; r < KECCAK_ROUNDS; r++) {
        // Theta
        for (i = 0; i < 5; i++) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        
        for (i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
            for (j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }

        // Rho Pi
        t = state[1];
        for (i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = state[j];
            state[j] = ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        // Chi
        for (j = 0; j < 25; j += 5) {
            for (i = 0; i < 5; i++) {
                bc[i] = state[j + i];
            }
            for (i = 0; i < 5; i++) {
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        state[0] ^= keccakf_rndc[r];
    }
}

// Keccak-256 hash function (outputs 32 bytes)
int keccak256(uint8_t* out, size_t outlen, const uint8_t* in, size_t inlen) {
    uint64_t state[25] = {0};
    uint8_t temp[144];
    size_t rsiz = 136, rsizw = rsiz / 8;
    size_t i;

    // absorb
    while (inlen >= rsiz) {
        for (i = 0; i < rsizw; i++) {
            state[i] ^= ((uint64_t*) in)[i];
        }
        in += rsiz;
        inlen -= rsiz;
        keccak_f1600(state);
    }

    // pad
    memset(temp, 0, rsiz);
    for (i = 0; i < inlen; i++) {
        temp[i] = in[i];
    }
    temp[inlen] = 0x01;
    temp[rsiz - 1] |= 0x80;
    
    for (i = 0; i < rsizw; i++) {
        state[i] ^= ((uint64_t*) temp)[i];
    }

    // squeeze
    keccak_f1600(state);
    memcpy(out, state, outlen < 32 ? outlen : 32);
    
    return 0;
}

#endif /* KECCAK_TINY_H */ 