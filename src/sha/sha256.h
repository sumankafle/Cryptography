/*********************************************************************
 * Filename:   sha256.h
 * Description: Public API definition for SHA-256 hashing algorithm.
 *
 * Author:     Suman Kafle
 * Date:       2023/04/31
 *
 *
 * Disclaimer: This software is provided "as is", without any express
 * or implied warranty. Use at your own risk.
 *********************************************************************/

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>

/* SHA-256 produces a 256-bit (32-byte) hash value */
#define SHA256_BLOCK_SIZE 32

/* Basic data types */
typedef unsigned char BYTE;   /* 8-bit byte */
typedef unsigned int  WORD;   /* 32-bit word */

/* SHA-256 context structure */
typedef struct {
    BYTE data[64];            /* Current 512-bit message block */
    WORD datalen;             /* Length of data in the buffer */
    unsigned long long bitlen;/* Total number of processed bits */
    WORD state[8];            /* Hash state (A–H) */
} SHA256_CTX;

/* Function prototypes */
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);

#endif /* SHA256_H */
