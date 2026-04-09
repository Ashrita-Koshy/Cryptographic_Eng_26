#include "config.h"
#include "auxiliary.h"
#include "ntt.h"

void K_PKE_KeyGen(uint8_t* ekPKE, uint8_t* dkPKE, const uint8_t* d);
void K_PKE_Encrypt(uint8_t* c, const uint8_t* ekPKE, const uint8_t* m, const uint8_t* r);
void K_PKE_Decrypt(uint8_t* m, const uint8_t* dkPKE, const uint8_t* c);
