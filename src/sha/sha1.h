/*********************************************************************
 * Filename:   sha1.h
 * Description: API definitions for SHA-1 hashing algorithm.
 *
 * Author:     Suman Kafle
 * Date:       2023/04/31
 *
 * Copyright (c) 2023 Suman Kafle
 * All rights reserved.
 *
 * Disclaimer: This software is provided "as is" without any warranty.
 *********************************************************************/

#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>

/* SHA-1 produces a 160-bit (20 byte) hash */
#define SHA1_BLOCK_SIZE 20

/* Basic data types */
typedef unsigned char BYTE;   /* 8-bit byte */
typedef unsigned int  WORD;   /* 32-bit word */

/*
 * SHA-1 context structure
 * Holds intermediate state and message data
 */
typedef struct {
    BYTE data[64];                 /* Message block buffer */
    WORD datalen;                  /* Length of data in buffer */
    unsigned long long bitlen;     /* Total message length in bits */
    WORD state[5];                 /* Hash state (A, B, C, D, E) */
    WORD k[4];                     /* SHA-1 constants */
} SHA1_CTX;

/* Initialize SHA-1 context */
void sha1_init(SHA1_CTX *ctx);

/* Update SHA-1 with input data */
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len);

/* Finalize SHA-1 and produce hash */
void sha1_final(SHA1_CTX *ctx, BYTE hash[]);

#endif /* SHA1_H */
