#include "pke.h"

void generateVariables(uint8_t* rho, uint8_t* sigma, uint16_t (*A)[K][MLKEM_N], uint16_t (*s)[MLKEM_N], uint16_t (*e1)[MLKEM_N], uint16_t *e2){
    //these for loops can probably be unrolled
    //generate A
    for(uint8_t i = 0; i < K; i++){
        for(uint8_t j = 0; j < K; j++){
            sampleNTT(A[i][j],rho,j,i);
        }
    }
    //generate s
    uint8_t seedCBD[CBD_SEED_LEN] = {0};
    for(uint8_t i = 0; i < K; i++){
        PRF(seedCBD,CBD_SEED_LEN,sigma,KEY_SEED_LEN);
        samplePolyCBD(s[i],seedCBD);
        ntt(s[i]);
        sigma[RANDOM_LEN] = sigma[RANDOM_LEN] + 1;
    }
    //generate e or e1
    for(uint8_t i = 0; i < K; i++){
        PRF(seedCBD,CBD_SEED_LEN,sigma,KEY_SEED_LEN);
        samplePolyCBD(e1[i],seedCBD);
        if (e2 == NULL){
            ntt(e1[i]);
        }
        sigma[RANDOM_LEN] = sigma[RANDOM_LEN] + 1;
    }
    if(e2 != NULL){
        PRF(seedCBD,CBD_SEED_LEN,sigma,KEY_SEED_LEN);
        samplePolyCBD(e2,seedCBD);
    }
}

void generatePublicKey(uint16_t (*t)[MLKEM_N], uint16_t (*A)[K][MLKEM_N], uint16_t (*s)[MLKEM_N], uint16_t (*e)[MLKEM_N]){
    //t = A*s
    for(uint8_t i = 0; i < K; i++){
        for(uint8_t j = 0; j < K; j++){
            uint16_t h[MLKEM_N];
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
}

void generateU(uint16_t (*u)[MLKEM_N],uint16_t (*t)[MLKEM_N],uint16_t (*A)[K][MLKEM_N],uint16_t (*y)[MLKEM_N],uint16_t (*e1)[MLKEM_N]){
    for(uint8_t i = 0; i < K; i++){
        for(uint8_t j = 0; j < K; j++){
            uint16_t h[MLKEM_N];
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
}

void generateUpsilon(uint16_t* upsilon, const uint8_t* m,uint16_t (*t)[MLKEM_N],uint16_t (*y)[MLKEM_N],uint16_t* e2){
    //generate mu from m
    uint16_t mu [MLKEM_N];
    byteDecode(mu,m,1);
    for(uint16_t i = 0; i < MLKEM_N; i++){
        mu[i] = decompress(mu[i],1);
    }
    //upsilon = t transpose * y
    for(uint8_t i = 0; i < K; i++){
        uint16_t h[MLKEM_N];
        multiplyNTT(h,t[i],y[i]);
        for(uint16_t k = 0; k < MLKEM_N; k++){
                upsilon[k] = (upsilon[k] + h[k]) % MLKEM_Q;
        }
    }
    //upsilon = upsilon + e2 + mu
    nttInverse(upsilon);
    for(uint16_t i = 0; i < MLKEM_N; i++){
        upsilon[i] = (upsilon[i] + e2[i]) % MLKEM_Q;
        upsilon[i] = (upsilon[i] + mu[i]) % MLKEM_Q;
    }
}

void computeW(uint16_t* w,uint16_t (*s)[MLKEM_N],uint16_t* upsilon,uint16_t (*u)[MLKEM_N]){
    for(uint8_t i = 0; i < K; i++){
        uint16_t h[MLKEM_N];
        multiplyNTT(h,s[i],u[i]);
        for(uint16_t k = 0; k < MLKEM_N; k++){
                w[k] = (w[k] + h[k]) % MLKEM_Q;
        }
    }
    nttInverse(w);
    for(uint16_t i = 0; i < MLKEM_N; i++){
        int16_t difference = ((int16_t)upsilon[i] - w[i]) % MLKEM_Q;
        w[i] = (difference < 0) ? (uint16_t)(difference + MLKEM_Q) : (uint16_t)difference;
        w[i] = compress(w[i],1);
    }
}

void K_PKE_KeyGen(uint8_t* ekPKE, uint8_t* dkPKE, const uint8_t* d){
    //generate rho and sigma
    uint8_t bytes[KEY_SEED_LEN];
    memcpy(bytes,d,RANDOM_LEN);
    bytes[RANDOM_LEN] = K;
    uint8_t seed[PKE_SEED_KEN];
    G(seed,bytes,KEY_SEED_LEN);
    //reuse bytes array to store sigma + N
    memcpy(bytes,seed + RANDOM_LEN,RANDOM_LEN);
    bytes[RANDOM_LEN] = 0;

    //generate A,s,e in NTT domain
    uint16_t A[K][K][MLKEM_N];
    uint16_t s[K][MLKEM_N];
    uint16_t e[K][MLKEM_N];
    generateVariables(seed,bytes,A,s,e,NULL);

    //generate public key t
    uint16_t t[K][MLKEM_N] = {0};
    generatePublicKey(t,A,s,e);

    //byte encoding - also could be unrolled
    for(uint8_t i = 0; i < K; i++){
        byteEncode(ekPKE + POLY_BYTE_LEN*i,t[i],ENCODING_LEN);
        byteEncode(dkPKE + POLY_BYTE_LEN*i,s[i],ENCODING_LEN);
    }
    memcpy(ekPKE + POLY_BYTE_LEN*K,seed,RANDOM_LEN);
}

void K_PKE_Encrypt(uint8_t* c, const uint8_t* ekPKE, const uint8_t* m, const uint8_t* r){
    //seedPRF stores randomness r + counter
    uint8_t seedPRF[KEY_SEED_LEN];
    //decode public key, rho and randomness    
    uint16_t t[K][MLKEM_N];
    for(uint8_t i = 0; i < K; i++){
        byteDecode(t[i],ekPKE + POLY_BYTE_LEN*i,ENCODING_LEN);
    }
    uint8_t rho[RANDOM_LEN];
    memcpy(rho,ekPKE + POLY_BYTE_LEN*K,RANDOM_LEN);
    memcpy(seedPRF,r,RANDOM_LEN);
    seedPRF[RANDOM_LEN] = 0;
    //generating A, y, e1
    uint16_t A[K][K][MLKEM_N];
    uint16_t y[K][MLKEM_N];
    uint16_t e1[K][MLKEM_N];
    uint16_t e2[MLKEM_N];
    generateVariables(rho,seedPRF,A,y,e1,e2);
    //U = A^t * y
    uint16_t u[K][MLKEM_N] = {0};
    generateU(u,t,A,y,e1);
    //computing upsilon
    uint16_t upsilon [MLKEM_N] = {0};
    generateUpsilon(upsilon,m,t,y,e2);
    //encode ciphertext
    for(uint8_t i = 0; i < K; i++){
        for(uint16_t j = 0; j < MLKEM_N; j++){
            u[i][j] = compress(u[i][j],D_U);
        }
        byteEncode(c + D_U_ENCODING_LEN*i,u[i],D_U);
    }
    for(uint16_t i = 0; i < MLKEM_N; i++){
            upsilon[i] = compress(upsilon[i],D_UPSILON);
    }
    byteEncode(c + D_U_ENCODING_LEN*K,upsilon,D_UPSILON);
    return;
}

void K_PKE_Decrypt(uint8_t* m, const uint8_t* dkPKE, const uint8_t* c){
    //extract ciphertext
    uint8_t c1 [C_1_LEN];
    memcpy(c1,c,C_1_LEN);
    uint8_t c2 [C_2_LEN];
    memcpy(c2,c + C_1_LEN,C_2_LEN);
    //extract u and upsilon
    uint16_t u [K][MLKEM_N];
    for(uint8_t i = 0; i < K; i++){
        byteDecode(u[i],c1 + D_U_ENCODING_LEN*i,D_U);
        for(uint16_t j = 0; j < MLKEM_N; j++){
            u[i][j] = decompress(u[i][j],D_U);
        }
        ntt(u[i]);
    }
    uint16_t upsilon [MLKEM_N];
    byteDecode(upsilon,c2,D_UPSILON);
    for(uint16_t i = 0; i < MLKEM_N; i++){
        upsilon[i] = decompress(upsilon[i],D_UPSILON);
    }
    //extract secret key
    uint16_t s[K][MLKEM_N];
    for(uint8_t i = 0; i < K; i++){
        byteDecode(s[i],dkPKE + POLY_BYTE_LEN*i,ENCODING_LEN);
    }
    //compute w
    uint16_t w[MLKEM_N] = {0};
    computeW(w,s,upsilon,u);
    //encode message
    byteEncode(m,w,1);
}




