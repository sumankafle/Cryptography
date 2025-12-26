#include <stdio.h>
#include <string.h>
#include "rsa.h"

// Greatest Common Divisor
static long gcd(long a, long b) {
    while (b != 0) {
        long t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Modular multiplicative inverse (d ≡ e^-1 mod phi)
static long modinv(long e, long phi) {
    long t = 0, newt = 1;
    long r = phi, newr = e;

    while (newr != 0) {
        long quotient = r / newr;
        long tmp;

        tmp = t; t = newt; newt = tmp - quotient * newt;
        tmp = r; r = newr; newr = tmp - quotient * newr;
    }

    if (r > 1) return -1;  // e is not invertible
    if (t < 0) t += phi;
    return t;
}

// Modular exponentiation
static long mod_exp(long base, long exp, long mod) {
    long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1) result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// Generate small RSA keys
int rsa_generate_keys(long p, long q, RSAKey *key) {
    if (p == q) return 0;

    long n = p * q;
    long phi = (p - 1) * (q - 1);

    long e;
    for (e = 3; e < phi; e += 2) {
        if (gcd(e, phi) == 1) break;
    }

    long d = modinv(e, phi);
    if (d == -1) return 0;  // failed

    key->n = n;
    key->e = e;
    key->d = d;
    return 1;
}

// Convert a string block (up to 4 chars) to a number
long str_to_long(const char* str, int len) {
    long num = 0;
    for (int i = 0; i < len; i++) {
        num <<= 8;          // shift by 1 byte
        num |= (unsigned char)str[i];
    }
    return num;
}

// Convert number back to string
void long_to_str(long num, char* str, int len) {
    for (int i = len-1; i >= 0; i--) {
        str[i] = num & 0xFF;
        num >>= 8;
    }
}

// Encrypt message
long rsa_encrypt(long msg, RSAKey key) {
    return mod_exp(msg, key.e, key.n);
}

// Decrypt message
long rsa_decrypt(long cipher, RSAKey key) {
    return mod_exp(cipher, key.d, key.n);
}

// Encrypt string message
void rsa_encrypt_string(const char* msg, long* cipher, int* blocks, RSAKey key) {
    int len = strlen(msg);
    int block_size = 4; // demo block size
    *blocks = (len + block_size - 1) / block_size;
    int last_block_size = len % block_size;
    if (last_block_size == 0) last_block_size = block_size;

    for (int i = 0; i < *blocks; i++) {
        int chunk = (i == *blocks - 1) ? last_block_size : block_size;
        long m = 0;
        for (int j = 0; j < chunk; j++) {
            m <<= 8;
            m |= (unsigned char)msg[i*block_size + j];
        }
        cipher[i] = rsa_encrypt(m, key);
    }
}

// Decrypt string message
void rsa_decrypt_string(long* cipher, int blocks, int last_block_size, char* msg, RSAKey key) {
    int block_size = 4;
    for (int i = 0; i < blocks; i++) {
        long m = rsa_decrypt(cipher[i], key);
        int chunk = (i == blocks - 1) ? last_block_size : block_size;
        for (int j = chunk - 1; j >= 0; j--) {
            msg[i*block_size + j] = m & 0xFF;
            m >>= 8;
        }
    }
    msg[blocks*block_size - (block_size - last_block_size)] = '\0';
}
