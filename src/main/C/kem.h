#include "pke.h"
#include <time.h> //TO-DO - REPLACE WITH ACTAUL RNG HEADER

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
KemKeyPair ML_KEM_KeyGen();
KemEncapsulation ML_KEM_Encaps(uint8_t* ek, size_t ekLen);
KemDecapsulation ML_KEM_Decaps(uint8_t* c, size_t cLen, uint8_t* dk, size_t dkLen);
