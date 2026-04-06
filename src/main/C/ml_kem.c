#include "ml_kem.h"
#include <stdio.h>

uint8_t* bytesToBits(const uint8_t* bytes, size_t l) {
    uint8_t* bits = malloc(l * 8 * sizeof(uint8_t));
    if (bits == NULL) return NULL;

    for (size_t i = 0; i < l; i++) {
        for (size_t j = 0; j < 8; j++) {
            bits[8 * i + j] = (bytes[i] >> j) & 1;
        }
    }

    return bits;
}

uint8_t* bitsToBytes(const uint8_t* bits, size_t l) {
    uint8_t* bytes = malloc(l * sizeof(uint8_t));
    if (bytes == NULL) return NULL;

    for (size_t i = 0; i < l; i++) {
        //printf("i: %d\n",i);
        bytes[i] = 0;
        for (size_t j = 0; j < 8; j++) {
            bytes[i] |= (bits[8 * i + j] & 1) << j;
        }
    }
    return bytes;
}

uint16_t compress(uint16_t x, uint8_t d) {
    uint32_t two_d = (uint32_t)1 << d;
    uint32_t numerator = (uint32_t)x * two_d + MLKEM_Q / 2;
    return (uint16_t)((numerator / MLKEM_Q) & (two_d - 1));
}

uint16_t decompress(uint16_t y, uint8_t d) {
    uint32_t two_d = (uint32_t)1 << d;
    uint32_t numerator = (uint32_t)y * MLKEM_Q + (two_d / 2);
    return (uint16_t)(numerator >> d);
}

uint8_t* byteEncode(const uint16_t* F, uint8_t d){
    uint8_t* b = malloc(MLKEM_N * d * sizeof(uint8_t));
    for(uint16_t i = 0; i < MLKEM_N; i++){
        uint16_t a = F[i];
            for(uint8_t j = 0; j < d; j++){
                b[i*d + j] = a & 1;
                a = (a - b[i*d + j])/2;
            }
    }

    uint8_t* B = bitsToBytes(b,(32*d));
    free(b);

    return B;
}

uint16_t* byteDecode(const uint8_t* B, uint8_t d){
    uint16_t* F = malloc(MLKEM_N * sizeof(uint16_t));
    uint8_t* b = bytesToBits(B,32*d);
    uint16_t m = m = (d < 12) ? ((uint16_t)1 << d) : MLKEM_Q;
    for(uint16_t i = 0; i < MLKEM_N; i++){
        uint16_t sum = 0;
        for(uint8_t j = 0; j < d; j++){
            sum += (uint16_t)b[i*d + j] << j;
        }
        F[i] = sum % m;
    }
    free(b);
    return F;
}

uint16_t* sampleNTT(const uint8_t* B){
    XOF_ctx ctx;
    XOF_Init(&ctx);
    XOF_Absorb(&ctx,B,34);
    XOF_Finalize(&ctx);

    uint16_t* a = malloc(MLKEM_N * sizeof(uint16_t));
    uint16_t j = 0;
    uint8_t C[3];
    while(j < MLKEM_N){
        XOF_Squeeze(&ctx,C,3);
        uint16_t d1 = (uint16_t)(C[0] + MLKEM_N*(C[1] & 15));
        uint16_t d2 = (uint16_t)((C[1]/16) + 16*C[2]);
        if(d1 < MLKEM_Q){
            a[j] = d1;
            j += 1;
        }
        if((d2 < MLKEM_Q) && (j < MLKEM_N)){
            a[j] = d2;
            j += 1;
        }
    }
    return a;
}

uint16_t* samplePolyCBD(const uint8_t* B){
    uint8_t b[8*64*MLKEM_ETA] = {0};

    for (size_t i = 0; i < (64*2); i++) {
        for (size_t j = 0; j < 8; j++) {
            b[8 * i + j] = (B[i] >> j) & 1;
        }
    }

    //uint8_t* b = bytesToBits(B,(64 * ETA));
    uint16_t* f = malloc(MLKEM_N * sizeof(uint16_t));
    for(uint16_t i = 0; i < MLKEM_N; i++){
        int16_t x = b[2*i*MLKEM_ETA] + b[2*i*MLKEM_ETA + 1];
        int16_t y = b[2*i*MLKEM_ETA + MLKEM_ETA] + b[2*i*MLKEM_ETA + MLKEM_ETA + 1];
        f[i] = (uint16_t)((((x-y)% MLKEM_Q) + MLKEM_Q) % MLKEM_Q); //handles negative modulo case
    }
    //free(b);
    return f;
}

void NTT(uint16_t *f) {
    size_t i = 1;
    for (uint32_t len = 128; len >= 2; len /= 2) {
        for (uint32_t start = 0; start < MLKEM_N; start += 2 * len) {
            int32_t zeta = (int32_t)zetaPowers[i];
            i++;
            for (uint32_t j = start; j < start + len; j++) {
                int32_t t = (zeta * (int32_t)f[j + len]) % MLKEM_Q;
                f[j + len] = (uint16_t)(((int32_t)f[j] - t + MLKEM_Q) % MLKEM_Q);
                f[j] = (uint16_t)(((int32_t)f[j] + t) % MLKEM_Q);
            }
        }
    }
}

void NTTInverse(uint16_t *f) {
    size_t i = 127;
    for (uint32_t len = 2; len <= 128; len *= 2) {
        for (uint32_t start = 0; start < MLKEM_N; start += 2 * len) {
            int32_t zeta = (int32_t)zetaPowers[i];
            i--;
            for (uint32_t j = start; j < start + len; j++) {
                int32_t t = (int32_t)f[j];
                f[j] = (uint16_t)(((int32_t)f[j + len] + t) % MLKEM_Q);
                f[j + len] = (uint16_t)((zeta * ((int32_t)f[j + len] - t + MLKEM_Q)) % MLKEM_Q);
            }
        }
    }
    for (size_t k = 0; k < MLKEM_N; k++) {
        f[k] = (uint16_t)(((int32_t)f[k] * 3303) % MLKEM_Q);
    }
}




