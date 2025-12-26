#ifndef RSA_H
#define RSA_H

typedef struct {
    long n;
    long e;
    long d;
} RSAKey;

int rsa_generate_keys(long p, long q, RSAKey *key);
long rsa_encrypt(long msg, RSAKey key);
long rsa_decrypt(long cipher, RSAKey key);
long str_to_long(const char* str, int len);
void long_to_str(long num, char* str, int len);
void rsa_encrypt_string(const char* msg, long* cipher, int* blocks, RSAKey key);
void rsa_decrypt_string(long* cipher, int blocks, int last_block_size, char* msg, RSAKey key);

#endif
