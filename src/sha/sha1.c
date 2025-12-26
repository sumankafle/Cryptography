/*********************************************************************
 * Filename:   sha1.c
 * Description: Implementation of the SHA-1 hashing algorithm
 *              according to NIST FIPS 180-2 specification.
 *
 * Author:     Suman Kafle
 * Date:       2023/04/31
 *
 *
 * Disclaimer: This software is provided "as is" without any warranty.
 *********************************************************************/

#include <stdlib.h>
#include <string.h>
#include "sha1.h"

/* Rotate left macro */
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

/*
 * SHA-1 compression function
 * Processes one 512-bit message block
 */
static void sha1_transform(SHA1_CTX *ctx, const BYTE data[])
{
    WORD a, b, c, d, e, i, j, t, m[80];

    /* Prepare message schedule */
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) |
               (data[j + 2] << 8) | (data[j + 3]);

    for ( ; i < 80; ++i)
        m[i] = ROTLEFT(m[i - 3] ^ m[i - 8] ^ m[i - 14] ^ m[i - 16], 1);

    /* Initialize working variables */
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];

    /* Main loop */
    for (i = 0; i < 20; ++i) {
        t = ROTLEFT(a, 5) + ((b & c) ^ (~b & d)) + e + ctx->k[0] + m[i];
        e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
    }
    for ( ; i < 40; ++i) {
        t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + m[i];
        e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
    }
    for ( ; i < 60; ++i) {
        t = ROTLEFT(a, 5) + ((b & c) ^ (b & d) ^ (c & d)) + e + ctx->k[2] + m[i];
        e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
    }
    for ( ; i < 80; ++i) {
        t = ROTLEFT(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + m[i];
        e = d; d = c; c = ROTLEFT(b, 30); b = a; a = t;
    }

    /* Add results to state */
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

/* Initialize SHA-1 context */
void sha1_init(SHA1_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;

    /* Initial hash values */
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;

    /* SHA-1 constants */
    ctx->k[0] = 0x5A827999;
    ctx->k[1] = 0x6ED9EBA1;
    ctx->k[2] = 0x8F1BBCDC;
    ctx->k[3] = 0xCA62C1D6;
}

/* Process input data */
void sha1_update(SHA1_CTX *ctx, const BYTE data[], size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha1_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

/* Finalize hash and output result */
void sha1_final(SHA1_CTX *ctx, BYTE hash[])
{
    WORD i = ctx->datalen;

    /* Padding */
    ctx->data[i++] = 0x80;
    if (i > 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        sha1_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    while (i < 56) ctx->data[i++] = 0x00;

    /* Append message length */
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;

    sha1_transform(ctx, ctx->data);

    /* Output hash (big-endian) */
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
    }
}
