#include "kem.h"
#include <stdio.h>

int main(void){
    int count = 0;
    for(int i = 0; i < 100; i++){
        KemKeyPair mykey;
        int success = ML_KEM_KeyGen(&mykey);
        if (success == 0) {
            KemEncapsulation send;
            success = ML_KEM_Encaps(&send,mykey.ek,PKE_PUB_KEY_LEN);
            if (success == 0){
                KemDecapsulation received;
                success = ML_KEM_Decaps(&received,send.c,PKE_CIPHERTEX_LEN,mykey.dk,KEM_DECAP_LEN);
                if(success == 0){
                    if(memcmp(send.k,received.k,32) == 0){
                        printf("%d %d \n",send.k[0],received.k[0]);
                        count++;
                    }
                }
            }
        }
    }
    printf("Num Passed: %d",count);
    return 0;
}
