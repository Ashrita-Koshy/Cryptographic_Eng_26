#ifndef TEST_ML_KEM_KAT_H
#define TEST_ML_KEM_KAT_H

void run_keygen_kat(const char* prompt, const char* expected);
void run_encap_kat(const char* prompt, const char* expected);
void run_decap_kat(const char* prompt, const char* expected);

#endif