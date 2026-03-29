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
    uint32_t numerator = (uint32_t)x * two_d + Q / 2;
    return (uint16_t)((numerator / Q) & (two_d - 1));
}

uint16_t decompress(uint16_t y, uint8_t d) {
    uint32_t two_d = (uint32_t)1 << d;
    uint32_t numerator = (uint32_t)y * Q + (two_d / 2);
    return (uint16_t)(numerator >> d);
}

uint8_t* byteEncode(const uint16_t* F, uint8_t d){
    uint8_t* b = malloc(N * d * sizeof(uint8_t));
    for(uint16_t i = 0; i < N; i++){
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
    uint16_t* F = malloc(256 * sizeof(uint16_t));
    uint8_t* b = bytesToBits(B,32*d);
    uint16_t m = m = (d < 12) ? ((uint16_t)1 << d) : Q;
    for(uint16_t i = 0; i < N; i++){
        uint16_t sum = 0;
        for(uint8_t j = 0; j < d; j++){
            sum += (uint16_t)b[i*d + j] << j;
        }
        F[i] = sum % m;
    }
    free(b);
    return F;
}


