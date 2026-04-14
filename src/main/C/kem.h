#ifndef ML_KEM_H
#define ML_KEM_H

#include "pke.h"
#include "rng.h"

typedef struct {
    uint8_t ek[PKE_PUB_KEY_LEN];
    uint8_t dk[KEM_DECAP_LEN];
} KemKeyPair;

typedef struct {
    uint8_t k[SECRET_LEN];
    uint8_t c[PKE_CIPHERTEX_LEN];
} KemEncapsulation;

typedef struct {
    uint8_t k[SECRET_LEN];
} KemDecapsulation;

//maybe these functions should return something instead
int ML_KEM_KeyGen(KemKeyPair* keys);
int ML_KEM_Encaps(KemEncapsulation* encaps, uint8_t* ek, size_t ekLen);
int ML_KEM_Decaps(KemDecapsulation * decaps, uint8_t* c, size_t cLen, uint8_t* dk, size_t dkLen);

#endif
