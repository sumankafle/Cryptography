/*********************************************************************
 * Filename:   des_test.c
 * Description: Known-answer tests for DES and Triple-DES.
 *
 * Author:     Suman Kafle
 * Date:       2023/04/31
 *
 * Copyright (c) 2023 Suman Kafle
 * All rights reserved.
 *********************************************************************/

#include <stdio.h>
#include <string.h>
#include "des.h"

int des_test(void)
{
    BYTE pt[DES_BLOCK_SIZE]={0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};
    BYTE key[DES_BLOCK_SIZE]={0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1};
    BYTE out[DES_BLOCK_SIZE],back[DES_BLOCK_SIZE];
    BYTE schedule[16][6];

    des_key_setup(key,schedule,DES_ENCRYPT);
    des_crypt(pt,out,schedule);

    des_key_setup(key,schedule,DES_DECRYPT);
    des_crypt(out,back,schedule);

    return memcmp(pt,back,DES_BLOCK_SIZE)==0;
}

int main(void)
{
    printf("DES test: %s\n", des_test() ? "PASSED" : "FAILED");
    return 0;
}
