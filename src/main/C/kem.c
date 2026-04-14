#include "kem.h"
#include "rng.h"

void ML_KEM_KeyGen_Internal(uint8_t* ek, uint8_t* dk, uint8_t* d, uint8_t* z){
    K_PKE_KeyGen(ek,dk,d);
    memcpy(dk + PKE_PRV_KEY_LEN,ek,PKE_PUB_KEY_LEN);
    uint8_t h[KEY_HASH_LEN];
    H(h,ek,PKE_PUB_KEY_LEN);
    memcpy(dk + PKE_PRV_KEY_LEN + PKE_PUB_KEY_LEN,h,KEY_HASH_LEN);
    memcpy(dk + PKE_PRV_KEY_LEN + PKE_PUB_KEY_LEN + KEY_HASH_LEN,z,RANDOM_LEN);
}

 int ML_KEM_KeyGen(KemKeyPair* keys){
    uint8_t d[RANDOM_LEN] = {0};
    uint8_t z[RANDOM_LEN] = {0};
    randombytes_init(NULL,NULL,256);
    if(randombytes(d, RANDOM_LEN) != 0){
        //handle error
        //clear the buffer on error
        return RANDOM_GEN_ERROR; 
    }
    if(randombytes(z, RANDOM_LEN) != 0){
        //handle error
        //clear the buffer on error 
        return RANDOM_GEN_ERROR; 
    }
    ML_KEM_KeyGen_Internal(keys->ek,keys->dk,d,z);
    return 0;
}

void ML_KEM_Encaps_Internal(uint8_t* secret, uint8_t* c,uint8_t* ek, uint8_t* m){
    uint8_t keyHash[KEY_HASH_LEN];
    H(keyHash,ek,PKE_PUB_KEY_LEN);
    uint8_t messageKey[RANDOM_LEN + KEY_HASH_LEN];
    uint8_t messageKeyHash[ENCAPS_HASH_LEN];
    memcpy(messageKey,m,RANDOM_LEN);
    memcpy(messageKey + RANDOM_LEN,keyHash,KEY_HASH_LEN);
    G(messageKeyHash,messageKey,ENCAPS_HASH_LEN);
    memcpy(secret,messageKeyHash,SECRET_LEN);
    K_PKE_Encrypt(c,ek,m,messageKeyHash + SECRET_LEN);
}

int ML_KEM_Encaps(KemEncapsulation* encaps, uint8_t* ek, size_t ekLen){
    if(ekLen != PKE_PUB_KEY_LEN){
        return KEY_SIZE_ERROR;
    }
    uint8_t test[PKE_PUB_KEY_LEN - 32];
    for(uint8_t i = 0; i < K; i++){
        uint16_t poly[MLKEM_N];
        byteDecode(poly,ek + POLY_BYTE_LEN*i,ENCODING_LEN);
        byteEncode(test + POLY_BYTE_LEN*i,poly,ENCODING_LEN);
    }
    if(memcmp(test,ek,POLY_BYTE_LEN*K) != 0){
        return MALFORMED_KEY_ERROR;
    }
    //RNG GENERATOR
    uint8_t m[RANDOM_LEN] = {0};
    randombytes_init(NULL,NULL,256);
    if(randombytes(m, RANDOM_LEN) != 0){
        //handle error
        //clear the buffer on error
        return RANDOM_GEN_ERROR; 
    }

    ML_KEM_Encaps_Internal(encaps->k, encaps->c, ek, m);
    return 0;
}

void ML_KEM_Decaps_Internal(uint8_t* secret, uint8_t* c, uint8_t* dk){
    //dkPKE is the first bits of dk
    //ekPKE is at index 384*k
    //ekPKE hash is at 768*k + 32
    //z is at KEY_HASH_OFFSET + 32
    uint8_t m[RANDOM_LEN];
    K_PKE_Decrypt(m,dk,c);
    uint8_t messageKey[RANDOM_LEN + KEY_HASH_LEN];
    uint8_t messageKeyHash[ENCAPS_HASH_LEN];
    memcpy(messageKey,m,RANDOM_LEN);
    memcpy(messageKey + RANDOM_LEN,dk + KEY_HASH_OFFSET,KEY_HASH_LEN);
    G(messageKeyHash,messageKey,ENCAPS_HASH_LEN);
    memcpy(secret,messageKeyHash,SECRET_LEN);
    uint8_t secret_bar[RANDOM_LEN];
    uint8_t barData[RANDOM_LEN + PKE_CIPHERTEX_LEN];
    memcpy(barData,dk + Z_OFFSET,RANDOM_LEN);
    memcpy(barData + RANDOM_LEN,c,PKE_CIPHERTEX_LEN);
    J(secret_bar,SECRET_LEN,barData,RANDOM_LEN + PKE_CIPHERTEX_LEN);
    uint8_t c_bar[PKE_CIPHERTEX_LEN];
    K_PKE_Encrypt(c_bar,dk + PKE_PRV_KEY_LEN,m,messageKeyHash + SECRET_LEN);
    if(memcmp(c,c_bar,PKE_CIPHERTEX_LEN)){
        memcpy(secret,secret_bar,SECRET_LEN);
    }
}

int ML_KEM_Decaps(KemDecapsulation * decaps, uint8_t* c, size_t cLen, uint8_t* dk, size_t dkLen){
    if(dkLen != KEM_DECAP_LEN){
        return KEY_SIZE_ERROR;
    }
    if(cLen != PKE_CIPHERTEX_LEN){
        return CIPHERTEXT_SIZE_ERROR;
    }
    uint8_t h[KEY_HASH_LEN];
    H(h,dk + PKE_PRV_KEY_LEN,PKE_PUB_KEY_LEN);
    if(memcmp(h,dk + KEY_HASH_OFFSET,KEY_HASH_LEN) != 0){
        return MALFORMED_KEY_ERROR;
    }
    ML_KEM_Decaps_Internal(decaps->k,c,dk);
    return 0;
}

