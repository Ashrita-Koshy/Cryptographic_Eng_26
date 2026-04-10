#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "kem.h"
#include "fips202.h"
#include "cJSON.h"

#define MAX_BUF 8192

// ---------- Utility: Read entire file ----------
char* read_file(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) { printf("Cannot open %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    char* data = malloc(len + 1);
    if (!data) { fclose(f); exit(1); }
    fread(data, 1, len, f);
    data[len] = 0;
    fclose(f);
    return data;
}

// ----------  hex to bytes ----------
void hex_to_bytes(const char* hex, uint8_t* out, size_t outlen) {
    const char *pos = hex;
    if (hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) pos += 2;
    
    for (size_t i = 0; i < outlen; i++) {
        sscanf(pos + 2*i, "%2hhx", &out[i]);
    }
}

// ---------- bytes to hex ----------
void bytes_to_hex(const uint8_t* in, size_t len, char* out) {
    for (size_t i = 0; i < len; i++)
        sprintf(out + 2*i, "%02x", in[i]); 
    out[2*len] = '\0';
}

// ============================================================
// KEYGEN KAT
// ============================================================
void test_keygen(const char* prompt_path, const char* expected_path) {
    char* prompt_txt = read_file(prompt_path);
    char* exp_txt    = read_file(expected_path);

    cJSON* prompt_root = cJSON_Parse(prompt_txt);
    cJSON* expected_root = cJSON_Parse(exp_txt);

    cJSON* prompt_tgs = cJSON_GetObjectItem(prompt_root, "testGroups");
    cJSON* expected_tgs = cJSON_GetObjectItem(expected_root, "testGroups");

    for (int g = 0; g < cJSON_GetArraySize(prompt_tgs); g++) {
        cJSON* tg_p = cJSON_GetArrayItem(prompt_tgs, g);
        cJSON* tg_e = cJSON_GetArrayItem(expected_tgs, g);

        if (strcmp(cJSON_GetObjectItem(tg_p, "parameterSet")->valuestring, "ML-KEM-1024") != 0)
            continue;

        cJSON* tests_p = cJSON_GetObjectItem(tg_p, "tests");
        cJSON* tests_e = cJSON_GetObjectItem(tg_e, "tests");

        for (int i = 0; i < cJSON_GetArraySize(tests_p); i++) {
            cJSON* t_p = cJSON_GetArrayItem(tests_p, i);
            cJSON* t_e = cJSON_GetArrayItem(tests_e, i);

            uint8_t z[32], d[32];
            hex_to_bytes(cJSON_GetObjectItem(t_p, "z")->valuestring, z, 32);
            hex_to_bytes(cJSON_GetObjectItem(t_p, "d")->valuestring, d, 32);

            uint8_t ek[PKE_PUB_KEY_LEN];
            uint8_t dk[KEM_DECAP_LEN];

            ML_KEM_KeyGen_Internal(ek, dk, d, z);

            char ek_hex[2*PKE_PUB_KEY_LEN+1];
            char dk_hex[2*KEM_DECAP_LEN+1];
            bytes_to_hex(ek, PKE_PUB_KEY_LEN, ek_hex);
            bytes_to_hex(dk, KEM_DECAP_LEN, dk_hex);

            const char* exp_ek = cJSON_GetObjectItem(t_e, "ek")->valuestring;
            const char* exp_dk = cJSON_GetObjectItem(t_e, "dk")->valuestring;

            if (strcasecmp(ek_hex, exp_ek) == 0 && strcasecmp(dk_hex, exp_dk) == 0) {
                printf("[KeyGen tcId %d] PASS\n", cJSON_GetObjectItem(t_p, "tcId")->valueint);
            } else {
                printf("[KeyGen tcId %d] FAIL\n", cJSON_GetObjectItem(t_p, "tcId")->valueint);
            }
        }
    }
    cJSON_Delete(prompt_root);
    cJSON_Delete(expected_root);
    free(prompt_txt);
    free(exp_txt);
}

// ============================================================
// ENCAP / DECAP KAT
// ============================================================
void test_encap_decap(const char* prompt_path, const char* expected_path) {
    char* prompt_txt = read_file(prompt_path);
    char* exp_txt    = read_file(expected_path);

    cJSON* prompt_root = cJSON_Parse(prompt_txt);
    cJSON* expected_root = cJSON_Parse(exp_txt);

    cJSON* prompt_tgs = cJSON_GetObjectItem(prompt_root, "testGroups");
    cJSON* expected_tgs = cJSON_GetObjectItem(expected_root, "testGroups");

    for (int g = 0; g < cJSON_GetArraySize(prompt_tgs); g++) {
        cJSON* tg_p = cJSON_GetArrayItem(prompt_tgs, g);
        cJSON* tg_e = cJSON_GetArrayItem(expected_tgs, g);

        if (strcmp(cJSON_GetObjectItem(tg_p, "parameterSet")->valuestring, "ML-KEM-1024") != 0)
            continue;

        const char* func = cJSON_GetObjectItem(tg_p, "function")->valuestring;
        cJSON* tests_p = cJSON_GetObjectItem(tg_p, "tests");
        cJSON* tests_e = cJSON_GetObjectItem(tg_e, "tests");

        for (int i = 0; i < cJSON_GetArraySize(tests_p); i++) {
            cJSON* t_p = cJSON_GetArrayItem(tests_p, i);
            cJSON* t_e = cJSON_GetArrayItem(tests_e, i);

            if (strcmp(func, "encapsulation") == 0) {
                uint8_t ek[PKE_PUB_KEY_LEN], m[32], k[32], c[PKE_CIPHERTEX_LEN];
                hex_to_bytes(cJSON_GetObjectItem(t_p, "ek")->valuestring, ek, PKE_PUB_KEY_LEN);
                hex_to_bytes(cJSON_GetObjectItem(t_p, "msg")->valuestring, m, 32);

                ML_KEM_Encaps_Internal(ek, m, k, c);

                char k_hex[65], c_hex[2*PKE_CIPHERTEX_LEN+1];
                bytes_to_hex(k, 32, k_hex);
                bytes_to_hex(c, PKE_CIPHERTEX_LEN, c_hex);

                const char* exp_k = cJSON_GetObjectItem(t_e, "k")->valuestring;
                const char* exp_c = cJSON_GetObjectItem(t_e, "c")->valuestring;

                if (strcasecmp(k_hex, exp_k) == 0 && strcasecmp(c_hex, exp_c) == 0) {
                    printf("[Encap tcId %d] PASS\n", cJSON_GetObjectItem(t_p, "tcId")->valueint);
                } else {
                    printf("[Encap tcId %d] FAIL\n", cJSON_GetObjectItem(t_p, "tcId")->valueint);
                }
            } else if (strcmp(func, "decapsulation") == 0) {
                uint8_t dk[KEM_DECAP_LEN], c[PKE_CIPHERTEX_LEN], k[32];
                hex_to_bytes(cJSON_GetObjectItem(t_p, "dk")->valuestring, dk, KEM_DECAP_LEN);
                hex_to_bytes(cJSON_GetObjectItem(t_p, "c")->valuestring, c, PKE_CIPHERTEX_LEN);

                ML_KEM_Decaps_Internal(dk, c, k);

                char k_hex[65];
                bytes_to_hex(k, 32, k_hex);
                const char* exp_k = cJSON_GetObjectItem(t_e, "k")->valuestring;

                if (strcasecmp(k_hex, exp_k) == 0) {
                    printf("[Decap tcId %d] PASS\n", cJSON_GetObjectItem(t_p, "tcId")->valueint);
                } else {
                    printf("[Decap tcId %d] FAIL\n", cJSON_GetObjectItem(t_p, "tcId")->valueint);
                }
            }
        }
    }
    cJSON_Delete(prompt_root);
    cJSON_Delete(expected_root);
    free(prompt_txt);
    free(exp_txt);
}

int main() {
    test_keygen(
        "known_answers_tests/ML-KEM-keyGen-FIPS203/prompt.json",
        "known_answers_tests/ML-KEM-keyGen-FIPS203/expectedResults.json"
    );

    test_encap_decap(
        "known_answers_tests/ML-KEM-encapDecap-FIPS203/prompt.json",
        "known_answers_tests/ML-KEM-encapDecap-FIPS203/expectedResults.json"
    );

    printf("\nALL KAT TESTS COMPLETED\n");
    return 0;
}