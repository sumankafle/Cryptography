/*********************************************************************
 * Filename:   sha256_test.c
 * Description: Known-answer tests (KATs) and example usage for the
 *              SHA-256 hashing implementation.
 *
 * Author:     Suman Kafle
 * Date:       2023/04/31
 *
 * Copyright (c) 2023 Suman Kafle
 * All rights reserved.
 *
 * Disclaimer: This software is provided "as is", without any express
 * or implied warranty. Use at your own risk.
 *********************************************************************/

#include <stdio.h>
#include <string.h>
#include "sha256.h"

/*
 * Runs known-answer tests for SHA-256.
 * Returns 1 if all tests pass, otherwise 0.
 */
int sha256_test(void)
{
    BYTE text1[] = "abc";
    BYTE text2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    BYTE text3[] = "aaaaaaaaaa";

    BYTE hash1[SHA256_BLOCK_SIZE] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
        0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
        0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };

    BYTE hash2[SHA256_BLOCK_SIZE] = {
        0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,
        0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
        0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,
        0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1
    };

    BYTE hash3[SHA256_BLOCK_SIZE] = {
        0xcd,0xc7,0x6e,0x5c,0x99,0x14,0xfb,0x92,
        0x81,0xa1,0xc7,0xe2,0x84,0xd7,0x3e,0x67,
        0xf1,0x80,0x9a,0x48,0xa4,0x97,0x20,0x0e,
        0x04,0x6d,0x39,0xcc,0xc7,0x11,0x2c,0xd0
    };

    BYTE buf[SHA256_BLOCK_SIZE];
    SHA256_CTX ctx;
    int pass = 1;

    /* Test vector 1 */
    sha256_init(&ctx);
    sha256_update(&ctx, text1, strlen((char *)text1));
    sha256_final(&ctx, buf);
    pass &= (memcmp(hash1, buf, SHA256_BLOCK_SIZE) == 0);

    /* Test vector 2 */
    sha256_init(&ctx);
    sha256_update(&ctx, text2, strlen((char *)text2));
    sha256_final(&ctx, buf);
    pass &= (memcmp(hash2, buf, SHA256_BLOCK_SIZE) == 0);

    /* Test vector 3: repeated input */
    sha256_init(&ctx);
    for (int i = 0; i < 100000; ++i)
        sha256_update(&ctx, text3, strlen((char *)text3));
    sha256_final(&ctx, buf);
    pass &= (memcmp(hash3, buf, SHA256_BLOCK_SIZE) == 0);

    return pass;
}

int main(void)
{
    printf("SHA-256 tests: %s\n", sha256_test() ? "SUCCEEDED" : "FAILED");
    return 0;
}
