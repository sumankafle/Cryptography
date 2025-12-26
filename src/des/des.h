/*********************************************************************
 * Filename:   des.h
 * Description: API definitions for DES and Triple-DES encryption.
 *
 * Author:     Suman Kafle
 * Date:       2023/04/31
 *
 * Copyright (c) 2023 Suman Kafle
 * All rights reserved.
 *
 * Disclaimer: This software is provided "as is" without any warranty.
 *********************************************************************/

#ifndef DES_H
#define DES_H

#include <stddef.h>

/* DES operates on 64-bit (8 byte) blocks */
#define DES_BLOCK_SIZE 8

/* Basic data types */
typedef unsigned char BYTE;   /* 8-bit byte */
typedef unsigned int  WORD;   /* 32-bit word */

/* DES operation mode */
typedef enum {
    DES_ENCRYPT,
    DES_DECRYPT
} DES_MODE;

/* Generate DES round keys */
void des_key_setup(const BYTE key[], BYTE schedule[][6], DES_MODE mode);

/* Encrypt or decrypt a single DES block */
void des_crypt(const BYTE in[], BYTE out[], const BYTE key[][6]);

/* Generate Triple-DES round keys */
void three_des_key_setup(const BYTE key[], BYTE schedule[][16][6], DES_MODE mode);

/* Encrypt or decrypt a block using Triple-DES */
void three_des_crypt(const BYTE in[], BYTE out[], const BYTE key[][16][6]);

#endif /* DES_H */
