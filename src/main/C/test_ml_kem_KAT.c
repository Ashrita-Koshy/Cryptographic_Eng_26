#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cJSON.h"
#include "kem.h"  
#include "rng.h"


#define PUB_KEY_LEN     1568
#define PRIV_KEY_LEN    3168
#define CIPHERTEXT_LEN  1568
#define SHARED_SEC_LEN  32
#define SEED_LEN        32


// --- Helper Functions ---
void hex_to_bytes(const char *hex, uint8_t *bytes) {
    if (!hex) return;
    for (size_t i = 0; i < strlen(hex) / 2; i++) {
        sscanf(hex + 2 * i, "%02hhx", &bytes[i]);
    }
}

void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex) {
    for (size_t i = 0; i < len; i++) {
        sprintf(hex + 2 * i, "%02X", bytes[i]);
    }
    hex[2 * len] = '\0';
}

char* read_file_to_string(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *data = malloc(len + 1);
    if (data) {
        fread(data, 1, len, f);
        data[len] = '\0';
    }
    fclose(f);
    return data;
}

//copy of internal functions
static void ML_KEM_KeyGen_Internal(uint8_t* ek, uint8_t* dk, uint8_t* d, uint8_t* z){
    K_PKE_KeyGen(ek,dk,d);
    memcpy(dk + PKE_PRV_KEY_LEN,ek,PKE_PUB_KEY_LEN);
    uint8_t h[KEY_HASH_LEN];
    H(h,ek,PKE_PUB_KEY_LEN);
    memcpy(dk + PKE_PRV_KEY_LEN + PKE_PUB_KEY_LEN,h,KEY_HASH_LEN);
    memcpy(dk + PKE_PRV_KEY_LEN + PKE_PUB_KEY_LEN + KEY_HASH_LEN,z,RANDOM_LEN);
}

static void ML_KEM_Encaps_Internal(uint8_t* secret, uint8_t* c,uint8_t* ek, uint8_t* m){
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

static void ML_KEM_Decaps_Internal(uint8_t* secret, uint8_t* c, uint8_t* dk){
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

cJSON* find_test_by_id(cJSON *root, int tcId) {
    cJSON *groups = cJSON_GetObjectItem(root, "testGroups");
    cJSON *group, *test;
    cJSON_ArrayForEach(group, groups) {
        cJSON *tests = cJSON_GetObjectItem(group, "tests");
        cJSON_ArrayForEach(test, tests) {
            if (cJSON_GetObjectItem(test, "tcId")->valueint == tcId) return test;
        }
    }
    return NULL;
}

// --- Test Functions ---
void test_acvp_keygen(const char *prompt_file, const char *expected_file) {
    printf("\n==================================================\n");
    printf("KeyGen Validation: %s\n", prompt_file);

    char *p_raw = read_file_to_string(prompt_file);
    char *e_raw = read_file_to_string(expected_file);
    if (!p_raw || !e_raw) { printf("[-] Failed to load JSON files\n"); return; }

    cJSON *p_json = cJSON_Parse(p_raw);
    cJSON *e_json = cJSON_Parse(e_raw);
    int passed = 0, skipped = 0;

    cJSON *group;
    cJSON_ArrayForEach(group, cJSON_GetObjectItem(p_json, "testGroups")) {
        if (strcmp(cJSON_GetObjectItem(group, "parameterSet")->valuestring, "ML-KEM-1024") != 0) {
            skipped += cJSON_GetArraySize(cJSON_GetObjectItem(group, "tests"));
            continue;
        }

        cJSON *test;
        cJSON_ArrayForEach(test, cJSON_GetObjectItem(group, "tests")) {
            int tcId = cJSON_GetObjectItem(test, "tcId")->valueint;
            uint8_t d[SEED_LEN], z[SEED_LEN];
            uint8_t my_ek[PUB_KEY_LEN], my_dk[PRIV_KEY_LEN];
            char my_ek_hex[PUB_KEY_LEN*2+1], my_dk_hex[PRIV_KEY_LEN*2+1];

            hex_to_bytes(cJSON_GetObjectItem(test, "d")->valuestring, d);
            hex_to_bytes(cJSON_GetObjectItem(test, "z")->valuestring, z);

            ML_KEM_KeyGen_Internal(my_ek, my_dk, d, z);

            bytes_to_hex(my_ek, PUB_KEY_LEN, my_ek_hex);
            bytes_to_hex(my_dk, PRIV_KEY_LEN, my_dk_hex);

            cJSON *exp = find_test_by_id(e_json, tcId);
            if (exp && strcasecmp(my_ek_hex, cJSON_GetObjectItem(exp, "ek")->valuestring) == 0 &&
                strcasecmp(my_dk_hex, cJSON_GetObjectItem(exp, "dk")->valuestring) == 0) {
                passed++;
            } else {
                printf("[-] KeyGen mismatch at tcId %d\n", tcId);
                goto end;
            }
        }
    }
    printf("[SUCCESS] KeyGen Passed: %d (Skipped: %d)\n", passed, skipped);

end:
    cJSON_Delete(p_json); cJSON_Delete(e_json);
    free(p_raw); free(e_raw);
}

void test_acvp_encap_decap(const char *prompt_file, const char *expected_file) {
    printf("\n==================================================\n");
    printf("Encap/Decap Validation: %s\n", prompt_file);

    char *p_raw = read_file_to_string(prompt_file);
    char *e_raw = read_file_to_string(expected_file);
    if (!p_raw || !e_raw) { printf("[-] Failed to load JSON files\n"); return; }

    cJSON *p_json = cJSON_Parse(p_raw);
    cJSON *e_json = cJSON_Parse(e_raw);
    if (!p_json || !e_json) { printf("[-] JSON Parse Error\n"); return; }

    int passed = 0, skipped = 0;
    cJSON *groups = cJSON_GetObjectItem(p_json, "testGroups");

    cJSON *group;
    cJSON_ArrayForEach(group, groups) {
        cJSON *pSet = cJSON_GetObjectItem(group, "parameterSet");
        if (!pSet || strcmp(pSet->valuestring, "ML-KEM-1024") != 0) {
            skipped += cJSON_GetArraySize(cJSON_GetObjectItem(group, "tests"));
            continue;
        }

        const char *func = cJSON_GetObjectItem(group, "function")->valuestring;
        cJSON *tests = cJSON_GetObjectItem(group, "tests");

        cJSON *test;
        cJSON_ArrayForEach(test, tests) {
            int tcId = cJSON_GetObjectItem(test, "tcId")->valueint;
            
            cJSON *exp = find_test_by_id(e_json, tcId);
            if (!exp) {
                printf("[-] Skipping tcId %d: No expected result found\n", tcId);    // If expected result is found early
                continue;
            }

            if (strcmp(func, "encapsulation") == 0) {
                uint8_t ek[PUB_KEY_LEN], m[SEED_LEN], my_k[SHARED_SEC_LEN], my_c[CIPHERTEXT_LEN];
                char my_k_hex[SHARED_SEC_LEN*2+1], my_c_hex[CIPHERTEXT_LEN*2+1];

                cJSON *ek_obj = cJSON_GetObjectItem(test, "ek");
                cJSON *m_obj = cJSON_GetObjectItem(test, "msg") ? cJSON_GetObjectItem(test, "msg") : 
                               (cJSON_GetObjectItem(test, "m") ? cJSON_GetObjectItem(test, "m") : cJSON_GetObjectItem(test, "payload"));

                if (!ek_obj || !m_obj) { printf("[-] tcId %d: Missing input fields\n", tcId); goto end; }

                hex_to_bytes(ek_obj->valuestring, ek);
                hex_to_bytes(m_obj->valuestring, m);

                ML_KEM_Encaps_Internal(my_k, my_c, ek, m);

                bytes_to_hex(my_k, SHARED_SEC_LEN, my_k_hex);
                bytes_to_hex(my_c, CIPHERTEXT_LEN, my_c_hex);

                cJSON *exp_k = cJSON_GetObjectItem(exp, "k");
                cJSON *exp_c = cJSON_GetObjectItem(exp, "c");
                if (!exp_k || !exp_c) { printf("[-] tcId %d: Missing expected fields\n", tcId); goto end; }

                if (strcasecmp(my_k_hex, exp_k->valuestring) == 0 &&
                    strcasecmp(my_c_hex, exp_c->valuestring) == 0) {
                    passed++;
                } else { printf("[-] Encap mismatch at tcId %d\n", tcId); goto end; }
            } 
            else if (strcmp(func, "decapsulation") == 0) {
                uint8_t dk[PRIV_KEY_LEN], c[CIPHERTEXT_LEN], my_k[SHARED_SEC_LEN];
                char my_k_hex[SHARED_SEC_LEN*2+1];

                cJSON *dk_obj = cJSON_GetObjectItem(test, "dk");
                cJSON *c_obj = cJSON_GetObjectItem(test, "c");
                if (!dk_obj || !c_obj) { printf("[-] tcId %d: Missing decap inputs\n", tcId); goto end; }

                hex_to_bytes(dk_obj->valuestring, dk);
                hex_to_bytes(c_obj->valuestring, c);

                ML_KEM_Decaps_Internal(my_k, c, dk);

                bytes_to_hex(my_k, SHARED_SEC_LEN, my_k_hex);
                
                cJSON *prompt_k_obj = cJSON_GetObjectItem(test, "k");
                cJSON *tp = cJSON_GetObjectItem(exp, "testPassed");

                if (tp) { 
                    if (!prompt_k_obj) { printf("[-] tcId %d: Missing prompt k\n", tcId); goto end; }
                    int match = (strcasecmp(my_k_hex, prompt_k_obj->valuestring) == 0);
                    if (match == cJSON_IsTrue(tp)) passed++;
                    else { printf("[-] Decap Rejection logic failed at tcId %d\n", tcId); goto end; }
                } else {
                    cJSON *exp_k = cJSON_GetObjectItem(exp, "k");
                    if (!exp_k) { printf("[-] tcId %d: Missing expected k\n", tcId); goto end; }
                    if (strcasecmp(my_k_hex, exp_k->valuestring) == 0) passed++;
                    else { printf("[-] Decap mismatch at tcId %d\n", tcId); goto end; }
                }
            }
        }
    }
    printf("[SUCCESS] Encap/Decap Passed: %d (Skipped: %d)\n", passed, skipped);

end:
    cJSON_Delete(p_json); cJSON_Delete(e_json);
    free(p_raw); free(e_raw);
}

int main() {
    test_acvp_keygen(
        "known_answers_tests/ML-KEM-keyGen-FIPS203/prompt.json",
        "known_answers_tests/ML-KEM-keyGen-FIPS203/expectedResults.json"
    );

    test_acvp_encap_decap(
        "known_answers_tests/ML-KEM-encapDecap-FIPS203/prompt.json",
        "known_answers_tests/ML-KEM-encapDecap-FIPS203/expectedResults.json"
    );

    return 0;
}
