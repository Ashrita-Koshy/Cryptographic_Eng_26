#ifndef AUXILIARY_H
#define AUXILIARY_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "fips202.h"

#define XOF_ctx               keccak_state
#define XOF_Init(a)           shake128_init(a)
#define XOF_Absorb(a, b, c)   shake128_absorb(a, b, c)
#define XOF_Finalize(a)       shake128_finalize(a)
#define XOF_Squeeze(a, b, c)  shake128_squeeze(b, c, a)
#define G(a, b, c)            sha3_512(a, b, c)
#define H(a, b, c)            sha3_256(a, b, c)
#define J(a, b, c, d)         shake256(a, b, c, d)
#define PRF(a, b, c, d)       shake256(a, b, c, d)

/*These can probably be inlined since d is almost always going to be 12 or 1*/
uint16_t compress(uint16_t x, uint8_t d);
uint16_t decompress(uint16_t y, uint8_t d);

/*Pretty sure these are only used with d = 12, so could maybe unroll inner for loop, might not be worth it though*/
/*Also worth noting, since d is probably oonly going to equal 12, can probably get rid of any memory allocation with these bits/bytes related functions*/
void byteEncode(uint8_t* B, const uint16_t* F, uint8_t d);
void byteDecode(uint16_t* F, const uint8_t* B, uint8_t d);

void sampleNTT(uint16_t* a, const uint8_t* B, const uint8_t col, const uint8_t row);
void samplePolyCBD(uint16_t* f, const uint8_t* B);

#endif
