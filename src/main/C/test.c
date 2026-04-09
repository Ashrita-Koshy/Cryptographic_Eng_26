#include "kem.h"
#include <stdio.h>

int main(void){
    KemKeyPair mykey = ML_KEM_KeyGen();
    KemEncapsulation send = ML_KEM_Encaps(mykey.ek,PKE_PUB_KEY_LEN);
    KemDecapsulation received = ML_KEM_Decaps(send.c,PKE_CIPHERTEX_LEN,mykey.dk,KEM_DECAP_LEN);
    for(int i = 0; i < SECRET_LEN; i++){
        printf("%d %d\n",send.k[i],received.k[i]);
    }
    return 0;
}
