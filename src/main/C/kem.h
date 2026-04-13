#include "pke.h"
//#include "rng.h"

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

void ML_KEM_KeyGen_Internal(uint8_t* ek, uint8_t* dk, uint8_t* d, uint8_t* z);
void ML_KEM_Encaps_Internal(uint8_t* secret, uint8_t* c,uint8_t* ek, uint8_t* m);
void ML_KEM_Decaps_Internal(uint8_t* secret, uint8_t* c, uint8_t* dk);
