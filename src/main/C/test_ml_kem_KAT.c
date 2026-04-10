#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kem.h"
#include "rng.h"
#include "cJSON.h"
#include "test_ml_kem_KAT.h"

#define MAXBUF 100000

// Functions

char* read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    char* data = malloc(len + 1);
    fread(data, 1, len, f);
    data[len] = 0;
    fclose(f);
    return data;
}

void hex_to_bytes(const char* hex, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++)
        sscanf(hex + 2*i, "%2hhx", &out[i]);
}

void bytes_to_hex(const uint8_t* in, size_t len, char* out) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + 2*i, "%02x", in[i]);
    out[2*len] = 0;
}

void run_keygen_kat(const char* prompt, const char* expected) {

    char* ptxt = read_file(prompt);
    char* etxt = read_file(expected);

    cJSON* pr = cJSON_Parse(ptxt);
    cJSON* er = cJSON_Parse(etxt);

    cJSON* tg_p = cJSON_GetObjectItem(pr, "testGroups");
    cJSON* tg_e = cJSON_GetObjectItem(er, "testGroups");

    for (int g = 0; g < cJSON_GetArraySize(tg_p); g++) {

        cJSON* tests_p = cJSON_GetObjectItem(
            cJSON_GetArrayItem(tg_p, g), "tests");
        cJSON* tests_e = cJSON_GetObjectItem(
            cJSON_GetArrayItem(tg_e, g), "tests");

        for (int i = 0; i < cJSON_GetArraySize(tests_p); i++) {

            cJSON* tp = cJSON_GetArrayItem(tests_p, i);
            cJSON* te = cJSON_GetArrayItem(tests_e, i);

            uint8_t d[32], z[32];
            hex_to_bytes(cJSON_GetObjectItem(tp,"d")->valuestring, d, 32);
            hex_to_bytes(cJSON_GetObjectItem(tp,"z")->valuestring, z, 32);

            randombytes_init(d, z, 256);

            KemKeyPair kp = ML_KEM_KeyGen();

            char ek_hex[2*PKE_PUB_KEY_LEN+1];
            char dk_hex[2*KEM_DECAP_LEN+1];

            bytes_to_hex(kp.ek, PKE_PUB_KEY_LEN, ek_hex);
            bytes_to_hex(kp.dk, KEM_DECAP_LEN, dk_hex);

            if (strcasecmp(ek_hex,
                cJSON_GetObjectItem(te,"ek")->valuestring)==0 &&
                strcasecmp(dk_hex,
                cJSON_GetObjectItem(te,"dk")->valuestring)==0)
                printf("[KeyGen %d] PASS\n",
                    cJSON_GetObjectItem(tp,"tcId")->valueint);
            else
                printf("[KeyGen %d] FAIL\n",
                    cJSON_GetObjectItem(tp,"tcId")->valueint);
        }
    }
}

void run_encap_kat(const char* prompt, const char* expected) {

    char* ptxt = read_file(prompt);
    char* etxt = read_file(expected);

    cJSON* pr = cJSON_Parse(ptxt);
    cJSON* er = cJSON_Parse(etxt);

    cJSON* tg_p = cJSON_GetObjectItem(pr, "testGroups");
    cJSON* tg_e = cJSON_GetObjectItem(er, "testGroups");

    for (int g = 0; g < cJSON_GetArraySize(tg_p); g++) {

        cJSON* tests_p = cJSON_GetObjectItem(
            cJSON_GetArrayItem(tg_p, g), "tests");
        cJSON* tests_e = cJSON_GetObjectItem(
            cJSON_GetArrayItem(tg_e, g), "tests");

        for (int i = 0; i < cJSON_GetArraySize(tests_p); i++) {

            cJSON* tp = cJSON_GetArrayItem(tests_p, i);
            cJSON* te = cJSON_GetArrayItem(tests_e, i);

            uint8_t ek[PKE_PUB_KEY_LEN], m[32];
            hex_to_bytes(cJSON_GetObjectItem(tp,"ek")->valuestring, ek, PKE_PUB_KEY_LEN);
            hex_to_bytes(cJSON_GetObjectItem(tp,"msg")->valuestring, m, 32);

            randombytes_init(m, NULL, 256);

            KemEncapsulation enc = ML_KEM_Encaps(ek, PKE_PUB_KEY_LEN);

            char c_hex[2*PKE_CIPHERTEX_LEN+1];
            char k_hex[65];

            bytes_to_hex(enc.c, PKE_CIPHERTEX_LEN, c_hex);
            bytes_to_hex(enc.k, 32, k_hex);

            if (strcasecmp(c_hex,
                cJSON_GetObjectItem(te,"c")->valuestring)==0 &&
                strcasecmp(k_hex,
                cJSON_GetObjectItem(te,"k")->valuestring)==0)
                printf("[Encap %d] PASS\n",
                    cJSON_GetObjectItem(tp,"tcId")->valueint);
            else
                printf("[Encap %d] FAIL\n",
                    cJSON_GetObjectItem(tp,"tcId")->valueint);
        }
    }
}

void run_decap_kat(const char* prompt, const char* expected) {

    char* ptxt = read_file(prompt);
    char* etxt = read_file(expected);

    cJSON* pr = cJSON_Parse(ptxt);
    cJSON* er = cJSON_Parse(etxt);

    cJSON* tg_p = cJSON_GetObjectItem(pr, "testGroups");
    cJSON* tg_e = cJSON_GetObjectItem(er, "tests");

    for (int g = 0; g < cJSON_GetArraySize(tg_p); g++) {

        cJSON* tests_p = cJSON_GetObjectItem(
            cJSON_GetArrayItem(tg_p, g), "tests");
        cJSON* tests_e = cJSON_GetObjectItem(
            cJSON_GetArrayItem(tg_e, g), "tests");

        for (int i = 0; i < cJSON_GetArraySize(tests_p); i++) {

            cJSON* tp = cJSON_GetArrayItem(tests_p, i);
            cJSON* te = cJSON_GetArrayItem(tests_e, i);

            uint8_t dk[KEM_DECAP_LEN], c[PKE_CIPHERTEX_LEN];
            hex_to_bytes(cJSON_GetObjectItem(tp,"dk")->valuestring, dk, KEM_DECAP_LEN);
            hex_to_bytes(cJSON_GetObjectItem(tp,"c")->valuestring, c, PKE_CIPHERTEX_LEN);

            KemDecapsulation dec =
                ML_KEM_Decaps(c, PKE_CIPHERTEX_LEN,
                              dk, KEM_DECAP_LEN);

            char k_hex[65];
            bytes_to_hex(dec.k, 32, k_hex);

            if (strcasecmp(k_hex,
                cJSON_GetObjectItem(te,"k")->valuestring)==0)
                printf("[Decap %d] PASS\n",
                    cJSON_GetObjectItem(tp,"tcId")->valueint);
            else
                printf("[Decap %d] FAIL\n",
                    cJSON_GetObjectItem(tp,"tcId")->valueint);
        }
    }
}

int main() { 
    run_keygen_kat( 
        "known_answers_tests/ML-KEM-keyGen-FIPS203/prompt.json", 
        "known_answers_tests/ML-KEM-keyGen-FIPS203/expectedResults.json" 
    ); 
        
    run_encap_kat( 
        "known_answers_tests/ML-KEM-encapDecap-FIPS203/prompt.json", 
        "known_answers_tests/ML-KEM-encapDecap-FIPS203/expectedResults.json" 
    ); 
    
    run_decap_kat( 
        "known_answers_tests/ML-KEM-encapDecap-FIPS203/prompt.json", 
        "known_answers_tests/ML-KEM-encapDecap-FIPS203/expectedResults.json" 
    ); 
    
    printf("\nALL KAT TESTS COMPLETED\n"); 
    
}