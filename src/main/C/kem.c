#include "kem.h"
#include "rng.h"

/*
Function: ML_KEM_KeyGen_Internal
Parameters:
    - Array to Store KEM Encapsulation Key 
    - Array to Store KEM Decapsulation Key
    - Random seeds d, z
Description:
    - Implements the internal key generation defined in FIPS 203. H uses SHA3-256 from fips202.h
*/
static void ML_KEM_KeyGen_Internal(uint8_t* ek, uint8_t* dk, uint8_t* d, uint8_t* z){
    //generate key pairs
    K_PKE_KeyGen(ek,dk,d);
    memcpy(dk + PKE_PRV_KEY_LEN,ek,PKE_PUB_KEY_LEN);
    uint8_t h[KEY_HASH_LEN];
    //compute hash of public key
    H(h,ek,PKE_PUB_KEY_LEN);
    memcpy(dk + PKE_PRV_KEY_LEN + PKE_PUB_KEY_LEN,h,KEY_HASH_LEN);
    memcpy(dk + PKE_PRV_KEY_LEN + PKE_PUB_KEY_LEN + KEY_HASH_LEN,z,RANDOM_LEN);
}

/*
Function: ML_KEM_KeyGen
Parameters:
    - KemKeyPair struct passed by reference
Description:
    - Defines KEM Key Generation algorithm defined in FIPS 203. Uses
    the RNG from rng.h
*/
 int ML_KEM_KeyGen(KemKeyPair* keys){
    //generate d and z using hardware RNG
    uint8_t d[RANDOM_LEN] = {0};
    uint8_t z[RANDOM_LEN] = {0};
    randombytes_init();
    if(randombytes(d, RANDOM_LEN) != 0){
        return RANDOM_GEN_ERROR; 
    }
    if(randombytes(z, RANDOM_LEN) != 0){
        return RANDOM_GEN_ERROR; 
    }
    //call internal ML_KEM function
    ML_KEM_KeyGen_Internal(keys->ek,keys->dk,d,z);
    return 0;
}

/*
Function: ML_KEM_Encaps_Internal
Paramaters: 
    - Array to store shared secret
    - Array to store ciphertext
    - KEM Encapsulation Key
    - Random Message m
Description:
    - Implements the internal encapsulation function defined in FIPS 203. Uses SHA3-256 and
    SHA3-512 from fips202.h file.
*/
static void ML_KEM_Encaps_Internal(uint8_t* secret, uint8_t* c,uint8_t* ek, uint8_t* m){
    //compute hash of public key
    uint8_t keyHash[KEY_HASH_LEN];
    H(keyHash,ek,PKE_PUB_KEY_LEN);
    //compute hash of message and public key hash
    uint8_t messageKey[RANDOM_LEN + KEY_HASH_LEN];
    uint8_t messageKeyHash[ENCAPS_HASH_LEN];
    memcpy(messageKey,m,RANDOM_LEN);
    memcpy(messageKey + RANDOM_LEN,keyHash,KEY_HASH_LEN);
    G(messageKeyHash,messageKey,ENCAPS_HASH_LEN);
    memcpy(secret,messageKeyHash,SECRET_LEN);
    //call PKE encryption function
    K_PKE_Encrypt(c,ek,m,messageKeyHash + SECRET_LEN);
}

/*
Function: ML_KEM_Encaps
Parameters: 
    - Encapsulation struct containing arrays to store shared secret and ciphertext
    - KEM Encapsulation Key
    - Size of encapsulation key
Description:
    - Implements the encapsulation function defined in FIPS 203.
*/
int ML_KEM_Encaps(KemEncapsulation* encaps, uint8_t* ek, size_t ekLen){
    //verify length of public key
    if(ekLen != PKE_PUB_KEY_LEN){
        return KEY_SIZE_ERROR;
    }
    uint8_t test[PKE_PUB_KEY_LEN - 32];
    uint8_t i;
    //verify the key is not malformed
    for(i = 0; i < K; i++){
        uint16_t poly[MLKEM_N];
        byteDecode(poly,ek + POLY_BYTE_LEN*i,ENCODING_LEN);
        byteEncode(test + POLY_BYTE_LEN*i,poly,ENCODING_LEN);
    }
    if(memcmp(test,ek,POLY_BYTE_LEN*K) != 0){
        return MALFORMED_KEY_ERROR;
    }
    //generate m using the hardware RNG
    uint8_t m[RANDOM_LEN] = {0};
    randombytes_init();
    if(randombytes(m, RANDOM_LEN) != 0){
        return RANDOM_GEN_ERROR; 
    }

    ML_KEM_Encaps_Internal(encaps->k, encaps->c, ek, m);
    return 0;
}

/*
Function: ML_KEM_Decaps_Internal
Parameters:
    - Array to store shared secret
    - Ciphertext
    - Decapsulation key dk
Description
    - Implements the internal decapsulation function defined in FIPS 203. Uses SHA3-512 and
    SHAKE256 algorithms defined in fips202.h
*/
static void ML_KEM_Decaps_Internal(uint8_t* secret, uint8_t* c, uint8_t* dk){
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
    //hash of the encryption key hash and message
    G(messageKeyHash,messageKey,ENCAPS_HASH_LEN);
    memcpy(secret,messageKeyHash,SECRET_LEN);
    uint8_t secret_bar[RANDOM_LEN];
    uint8_t barData[RANDOM_LEN + PKE_CIPHERTEX_LEN];
    memcpy(barData,dk + Z_OFFSET,RANDOM_LEN);
    memcpy(barData + RANDOM_LEN,c,PKE_CIPHERTEX_LEN);
    //generate implicit rejection value from hash
    J(secret_bar,SECRET_LEN,barData,RANDOM_LEN + PKE_CIPHERTEX_LEN);
    uint8_t c_bar[PKE_CIPHERTEX_LEN];
    //re-encrypt to verify ciphertext matches 1-1
    K_PKE_Encrypt(c_bar,dk + PKE_PRV_KEY_LEN,m,messageKeyHash + SECRET_LEN);
    if(memcmp(c,c_bar,PKE_CIPHERTEX_LEN)){
        memcpy(secret,secret_bar,SECRET_LEN);
    }
}

/*
Function: ML_KEM_Decaps
Parameters:
    - Decapsulation containing array to store shared secret
    - Ciphertext c
    - Length of ciphertext
    - KEM Decapsulation key
    - Length of decapsulation key
Description:
    - Implements decapsulation function defined in FIPS 203. Uses SHA3-256 from fips202.h
*/
int ML_KEM_Decaps(KemDecapsulation * decaps, uint8_t* c, size_t cLen, uint8_t* dk, size_t dkLen){
    //verify length of decapsulation key and ciphertext
    if(dkLen != KEM_DECAP_LEN){
        return KEY_SIZE_ERROR;
    }
    if(cLen != PKE_CIPHERTEX_LEN){
        return CIPHERTEXT_SIZE_ERROR;
    }
    //compute hash of public encryption key
    uint8_t h[KEY_HASH_LEN];
    H(h,dk + PKE_PRV_KEY_LEN,PKE_PUB_KEY_LEN);
    if(memcmp(h,dk + KEY_HASH_OFFSET,KEY_HASH_LEN) != 0){
        return MALFORMED_KEY_ERROR;
    }
    //call underlying KEM decapsulation function
    ML_KEM_Decaps_Internal(decaps->k,c,dk);
    return 0;
}

