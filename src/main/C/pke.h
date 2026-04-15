#ifndef PKE_KYBER_H
#define PKE_KYBER_H

#include "config.h"
#include "auxiliary.h"
#include "ntt.h"

void generateVariables(uint8_t* rho, uint8_t* sigma, uint16_t (*A)[K][MLKEM_N], uint16_t (*s)[MLKEM_N], uint16_t (*e1)[MLKEM_N], uint16_t* e2);
void generatePublicKey(uint16_t (*t)[MLKEM_N], uint16_t (*A)[K][MLKEM_N], uint16_t (*s)[MLKEM_N], uint16_t (*e)[MLKEM_N]);
void generateU(uint16_t (*u)[MLKEM_N],uint16_t (*t)[MLKEM_N],uint16_t (*A)[K][MLKEM_N],uint16_t (*y)[MLKEM_N],uint16_t (*e1)[MLKEM_N]);
void generateUpsilon(uint16_t* upsilon, const uint8_t* m,uint16_t (*t)[MLKEM_N],uint16_t (*y)[MLKEM_N],uint16_t* e2);
void generateW(uint16_t* w,uint16_t (*s)[MLKEM_N],uint16_t* upsilon,uint16_t (*u)[MLKEM_N]);

void K_PKE_KeyGen(uint8_t* ekPKE, uint8_t* dkPKE, const uint8_t* d);
void K_PKE_Encrypt(uint8_t* c, const uint8_t* ekPKE, const uint8_t* m, const uint8_t* r);
void K_PKE_Decrypt(uint8_t* m, const uint8_t* dkPKE, const uint8_t* c);

#endif
