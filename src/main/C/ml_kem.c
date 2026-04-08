#include "ml_kem.h"
#include <stdio.h>

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

void byteEncode(uint8_t* B, const uint16_t* F, uint8_t d){
    uint8_t* b = malloc(MLKEM_N * d * sizeof(uint8_t));
    for(uint16_t i = 0; i < MLKEM_N; i++){
        uint16_t a = F[i];
            for(uint8_t j = 0; j < d; j++){
                b[i*d + j] = a & 1;
                a = (a - b[i*d + j])/2;
            }
    }
    //B = bitsToBytes(b,(32*d));
    //should do error handling here too
    //bytes is of size l
    for (size_t i = 0; i < 32*d; i++) {
        //printf("i: %d\n",i);
        B[i] = 0;
        for (size_t j = 0; j < 8; j++) {
            B[i] |= (b[8 * i + j] & 1) << j;
        }
    }
    free(b);
}

void byteDecode(uint16_t* F, const uint8_t* B, uint8_t d){
    uint8_t* b = malloc(32 * d * 8 * sizeof(uint8_t));
    for (size_t i = 0; i < 32*d; i++) {
        for (size_t j = 0; j < 8; j++) {
            b[8 * i + j] = (B[i] >> j) & 1;
        }
    }
    uint16_t m = m = (d < 12) ? ((uint16_t)1 << d) : MLKEM_Q;
    for(uint16_t i = 0; i < MLKEM_N; i++){
        uint16_t sum = 0;
        for(uint8_t j = 0; j < d; j++){
            sum += (uint16_t)b[i*d + j] << j;
        }
        F[i] = sum % m;
    }
    free(b);
}

void sampleNTT(uint16_t* a, const uint8_t* B, const uint8_t j, const uint8_t i){
    XOF_ctx ctx;
    XOF_Init(&ctx);
    XOF_Absorb(&ctx,B,32);
    XOF_Absorb(&ctx,&j,1);
    XOF_Absorb(&ctx,&i,1);
    XOF_Finalize(&ctx);
    uint16_t k = 0;
    uint8_t C[3];
    while(k < MLKEM_N){
        XOF_Squeeze(&ctx,C,3);
        uint16_t d1 = (uint16_t)(C[0] + MLKEM_N*(C[1] & 15));
        uint16_t d2 = (uint16_t)((C[1]/16) + 16*C[2]);
        if(d1 < MLKEM_Q){
            a[k] = d1;
            k += 1;
        }
        if((d2 < MLKEM_Q) && (k < MLKEM_N)){
            a[k] = d2;
            k += 1;
        }
    }
}

void samplePolyCBD(uint16_t* f, const uint8_t* B){
    uint8_t b[8*64*MLKEM_ETA] = {0};

    for (size_t i = 0; i < (64*2); i++) {
        for (size_t j = 0; j < 8; j++) {
            b[8 * i + j] = (B[i] >> j) & 1;
        }
    }

    //uint8_t* b = bytesToBits(B,(64 * ETA));
    for(uint16_t i = 0; i < MLKEM_N; i++){
        int16_t x = b[2*i*MLKEM_ETA] + b[2*i*MLKEM_ETA + 1];
        int16_t y = b[2*i*MLKEM_ETA + MLKEM_ETA] + b[2*i*MLKEM_ETA + MLKEM_ETA + 1];
        f[i] = (uint16_t)((((x-y)% MLKEM_Q) + MLKEM_Q) % MLKEM_Q); //handles negative modulo case
    }
    //free(b);
}

void ntt(uint16_t *f) {
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

void nttInverse(uint16_t *f) {
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

void multiplyNTT(uint16_t *h, const uint16_t *f, const uint16_t *g) {
    for (uint16_t i = 0; i < 128; i++) {
        int32_t temp = ((int32_t)f[2*i + 1] * g[2*i + 1]) % MLKEM_Q;
        int32_t tz = (temp * zetaOddPowers[i]) % MLKEM_Q;
        if (tz < 0) tz += MLKEM_Q;
        h[2*i]     = (uint16_t)((((int32_t)f[2*i] * g[2*i]) % MLKEM_Q + tz) % MLKEM_Q);
        h[2*i + 1] = (uint16_t)(((((int32_t)f[2*i] * g[2*i + 1]) % MLKEM_Q) + (((int32_t)f[2*i + 1] * g[2*i]) % MLKEM_Q)) % MLKEM_Q);
    }
}

void K_PKE_KeyGen(uint8_t* ekPKE, uint8_t* dkPKE, const uint8_t* d){
    uint8_t bytes[33];
    memcpy(bytes,d,32);
    bytes[32] = K;
    uint8_t seed[64];
    G(seed,bytes,33);
    //reuse bytes to store sigma + N
    memcpy(bytes,seed + 32,32);
    bytes[32] = 0;
    //seed[0] is rho, seed[32] is pointer to gamma
    //these for loops can probably be unrolled
    //generate A,s,e in NTT domain
    uint16_t A[K][K][MLKEM_N];
    for(uint8_t i = 0; i < K; i++){
        for(uint8_t j = 0; j < K; j++){
            sampleNTT(A[i][j],seed,j,i);
        }
    }
    uint16_t s[K][MLKEM_N];
    uint8_t seedCBD[CBD_SEED_LEN] = {0};
    for(uint8_t i = 0; i < K; i++){
        PRF(seedCBD,CBD_SEED_LEN,bytes,33);
        samplePolyCBD(s[i],seedCBD);
        ntt(s[i]);
        bytes[32] = bytes[32] + 1;
    }
    uint16_t e[K][MLKEM_N];
    for(uint8_t i = 0; i < K; i++){
        PRF(seedCBD,CBD_SEED_LEN,bytes,33);
        samplePolyCBD(e[i],seedCBD);
        ntt(e[i]);
        bytes[32] = bytes[32] + 1;
    }
    uint16_t t[K][MLKEM_N] = {0};
    //t = A*s
    for(uint8_t i = 0; i < K; i++){
        for(uint8_t j = 0; j < K; j++){
            uint16_t h[256];
            multiplyNTT(h,A[i][j],s[j]);
            for(uint16_t k = 0; k < MLKEM_N; k++){
                t[i][k] = (t[i][k] + h[k]) % MLKEM_Q;
            }
        }
    }
    //t = t + e
    for(uint8_t i = 0; i < K; i++){
        for(uint16_t j = 0; j < MLKEM_N; j++){
            t[i][j] = (t[i][j] + e[i][j]) % MLKEM_Q;
        }
    }
    //byte encoding - also can be unrolled
    for(uint8_t i = 0; i < K; i++){
        byteEncode(ekPKE + 384*i,t[i],12);
        byteEncode(dkPKE + 384*i,s[i],12);
    }
    memcpy(ekPKE + 384*K,seed,32);
}

void K_PKE_Encrypt(uint8_t* c, const uint8_t* ekPKE, const uint8_t* m, const uint8_t* r){
    //more loop unrolling can probably happen here too
    uint8_t seedPRF[33];    
    uint16_t t[K][MLKEM_N];
    for(uint8_t i = 0; i < K; i++){
        byteDecode(t[i],ekPKE + 384*i,12);
    }
    uint8_t rho[32];
    memcpy(rho,ekPKE + 384*K,32);
    memcpy(seedPRF,r,32);
    seedPRF[32] = 0;
    //generating A
    uint16_t A[K][K][MLKEM_N];
    for(uint8_t i = 0; i < K; i++){
        for(uint8_t j = 0; j < K; j++){
            sampleNTT(A[i][j],rho,j,i);
        }
    }
    //generating y,e1,e2
    uint16_t y[K][MLKEM_N];
    uint8_t seedCBD[CBD_SEED_LEN] = {0};
    for(uint8_t i = 0; i < K; i++){
        PRF(seedCBD,CBD_SEED_LEN,seedPRF,33);
        samplePolyCBD(y[i],seedCBD);
        ntt(y[i]);
        seedPRF[32] = seedPRF[32] + 1;
    }
    uint16_t e1[K][MLKEM_N];
    for(uint8_t i = 0; i < K; i++){
        PRF(seedCBD,CBD_SEED_LEN,seedPRF,33);
        samplePolyCBD(e1[i],seedCBD);
        seedPRF[32] = seedPRF[32] + 1;
    }
    uint16_t e2[MLKEM_N];
    PRF(seedCBD,CBD_SEED_LEN,seedPRF,33);
    samplePolyCBD(e2,seedCBD);
    //U = A^t * y
    uint16_t u[K][MLKEM_N] = {0};
    for(uint8_t i = 0; i < K; i++){
        for(uint8_t j = 0; j < K; j++){
            uint16_t h[256];
            multiplyNTT(h,A[j][i],y[j]);
            for(uint16_t k = 0; k < MLKEM_N; k++){
                u[i][k] = (u[i][k] + h[k]) % MLKEM_Q;
            }
        }
        nttInverse(u[i]);
    }
    //U = U + e1
    for(uint8_t i = 0; i < K; i++){
        for(uint16_t j = 0; j < MLKEM_N; j++){
            u[i][j] = (u[i][j] + e1[i][j]) % MLKEM_Q;
        }
    }
    //computing upsilon
    uint16_t mu [MLKEM_N];
    byteDecode(mu,m,1);
    for(uint16_t i = 0; i < MLKEM_N; i++){
        mu[i] = decompress(mu[i],1);
    }
    uint16_t upsilon [MLKEM_N] = {0};
    for(uint8_t i = 0; i < K; i++){
        uint16_t h[MLKEM_N];
        multiplyNTT(h,t[i],y[i]);
        for(uint16_t k = 0; k < MLKEM_N; k++){
                upsilon[k] = (upsilon[k] + h[k]) % MLKEM_Q;
        }
    }
    nttInverse(upsilon);
    for(uint16_t i = 0; i < MLKEM_N; i++){
        upsilon[i] = (upsilon[i] + e2[i]) % MLKEM_Q;
        upsilon[i] = (upsilon[i] + mu[i]) % MLKEM_Q;
    }
    //encoding ciphertext
    for(uint8_t i = 0; i < K; i++){
        for(uint16_t j = 0; j < MLKEM_N; j++){
            u[i][j] = compress(u[i][j],D_U);
        }
        byteEncode(c + 32*D_U*i,u[i],D_U);
    }
    for(uint16_t i = 0; i < MLKEM_N; i++){
            upsilon[i] = compress(upsilon[i],D_UPSILON);
    }
    byteEncode(c + 32*D_U*K,upsilon,D_UPSILON);
    return;
}




