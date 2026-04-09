#include "auxiliary.h"

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

    for (size_t i = 0; i < (64*MLKEM_ETA); i++) {
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
