#include "ml_kem.h"

uint8_t *bytesToBits(const uint8_t *bytes, size_t l) {
    uint8_t *bits = malloc(l * 8 * sizeof(uint8_t));
    if (bits == NULL) return NULL;

    for (size_t i = 0; i < l; i++) {
        for (size_t j = 0; j < 8; j++) {
            bits[8 * i + j] = (bytes[i] >> j) & 1;
        }
    }

    return bits;
}

uint8_t *bitsToBytes(const uint8_t *bits, size_t l) {
    uint8_t *bytes = malloc(l * sizeof(uint8_t));
    if (bytes == NULL) return NULL;

    for (size_t i = 0; i < l; i++) {
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
