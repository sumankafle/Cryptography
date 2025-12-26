/*********************************************************************
 * Filename:   des.c
 * Description: DES and Triple-DES encryption implementation
 *              based on NIST FIPS 46-3 specification.
 *
 * Author:     Suman Kafle
 * Date:       2023/04/31
 *
 * Copyright (c) 2023 Suman Kafle
 * All rights reserved.
 *
 * Disclaimer: This software is provided "as is" without any warranty.
 *********************************************************************/

#include <stdlib.h>
#include <string.h>
#include "des.h"

/* Bit manipulation macros */
#define BITNUM(a,b,c)     (((a[(b)/8] >> (7 - ((b)%8))) & 0x01) << (c))
#define BITNUMINTR(a,b,c) ((((a) >> (31 - (b))) & 0x01) << (c))
#define BITNUMINTL(a,b,c) ((((a) << (b)) & 0x80000000) >> (c))
#define SBOXBIT(a)        (((a) & 0x20) | (((a) & 0x1f) >> 1) | (((a) & 0x01) << 4))

/* DES S-Boxes */
static const BYTE sbox1[64] = {
    14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
    0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
    4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
    15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
};

static const BYTE sbox2[64] = {
    15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
    3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
    0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
    13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
};

static const BYTE sbox3[64] = {
    10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
    13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
    13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
    1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
};

static const BYTE sbox4[64] = {
    7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
    13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
    10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
    3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
};

static const BYTE sbox5[64] = {
    2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
    14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
    4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
    11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
};

static const BYTE sbox6[64] = {
    12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
    10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
    9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
    4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
};

static const BYTE sbox7[64] = {
    4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
    13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
    1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
    6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
};

static const BYTE sbox8[64] = {
    13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
    1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
    7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
    2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
};

/* Initial permutation */
static void IP(WORD state[], const BYTE in[])
{
    state[0] = BITNUM(in,57,31)|BITNUM(in,49,30)|BITNUM(in,41,29)|BITNUM(in,33,28)|
               BITNUM(in,25,27)|BITNUM(in,17,26)|BITNUM(in,9,25)|BITNUM(in,1,24)|
               BITNUM(in,59,23)|BITNUM(in,51,22)|BITNUM(in,43,21)|BITNUM(in,35,20)|
               BITNUM(in,27,19)|BITNUM(in,19,18)|BITNUM(in,11,17)|BITNUM(in,3,16)|
               BITNUM(in,61,15)|BITNUM(in,53,14)|BITNUM(in,45,13)|BITNUM(in,37,12)|
               BITNUM(in,29,11)|BITNUM(in,21,10)|BITNUM(in,13,9)|BITNUM(in,5,8)|
               BITNUM(in,63,7)|BITNUM(in,55,6)|BITNUM(in,47,5)|BITNUM(in,39,4)|
               BITNUM(in,31,3)|BITNUM(in,23,2)|BITNUM(in,15,1)|BITNUM(in,7,0);

    state[1] = BITNUM(in,56,31)|BITNUM(in,48,30)|BITNUM(in,40,29)|BITNUM(in,32,28)|
               BITNUM(in,24,27)|BITNUM(in,16,26)|BITNUM(in,8,25)|BITNUM(in,0,24)|
               BITNUM(in,58,23)|BITNUM(in,50,22)|BITNUM(in,42,21)|BITNUM(in,34,20)|
               BITNUM(in,26,19)|BITNUM(in,18,18)|BITNUM(in,10,17)|BITNUM(in,2,16)|
               BITNUM(in,60,15)|BITNUM(in,52,14)|BITNUM(in,44,13)|BITNUM(in,36,12)|
               BITNUM(in,28,11)|BITNUM(in,20,10)|BITNUM(in,12,9)|BITNUM(in,4,8)|
               BITNUM(in,62,7)|BITNUM(in,54,6)|BITNUM(in,46,5)|BITNUM(in,38,4)|
               BITNUM(in,30,3)|BITNUM(in,22,2)|BITNUM(in,14,1)|BITNUM(in,6,0);
}

/* Inverse initial permutation */
static void InvIP(WORD state[], BYTE out[])
{
    for (int i = 0; i < 8; i++)
        out[i] = 0;

    out[0] = BITNUMINTR(state[1],7,7)|BITNUMINTR(state[0],7,6)|
             BITNUMINTR(state[1],15,5)|BITNUMINTR(state[0],15,4)|
             BITNUMINTR(state[1],23,3)|BITNUMINTR(state[0],23,2)|
             BITNUMINTR(state[1],31,1)|BITNUMINTR(state[0],31,0);
}

/* DES round function */
static WORD f(WORD state, const BYTE key[])
{
    BYTE e[6];
    WORD t1, t2;

    t1 = BITNUMINTL(state,31,0)|((state&0xf0000000)>>1)|BITNUMINTL(state,4,5)|
         BITNUMINTL(state,3,6)|((state&0x0f000000)>>3)|BITNUMINTL(state,8,11)|
         BITNUMINTL(state,7,12)|((state&0x00f00000)>>5)|BITNUMINTL(state,12,17)|
         BITNUMINTL(state,11,18)|((state&0x000f0000)>>7)|BITNUMINTL(state,16,23);

    t2 = BITNUMINTL(state,15,0)|((state&0x0000f000)<<15)|BITNUMINTL(state,20,5)|
         BITNUMINTL(state,19,6)|((state&0x00000f00)<<13)|BITNUMINTL(state,24,11)|
         BITNUMINTL(state,23,12)|((state&0x000000f0)<<11)|BITNUMINTL(state,28,17)|
         BITNUMINTL(state,27,18)|((state&0x0000000f)<<9)|BITNUMINTL(state,0,23);

    e[0]=(t1>>24)&0xff; e[1]=(t1>>16)&0xff; e[2]=(t1>>8)&0xff;
    e[3]=(t2>>24)&0xff; e[4]=(t2>>16)&0xff; e[5]=(t2>>8)&0xff;

    for(int i=0;i<6;i++) e[i]^=key[i];

    state =
        (sbox1[SBOXBIT(e[0]>>2)]<<28)|
        (sbox2[SBOXBIT(((e[0]&3)<<4)|(e[1]>>4))]<<24)|
        (sbox3[SBOXBIT(((e[1]&0xf)<<2)|(e[2]>>6))]<<20)|
        (sbox4[SBOXBIT(e[2]&0x3f)]<<16)|
        (sbox5[SBOXBIT(e[3]>>2)]<<12)|
        (sbox6[SBOXBIT(((e[3]&3)<<4)|(e[4]>>4))]<<8)|
        (sbox7[SBOXBIT(((e[4]&0xf)<<2)|(e[5]>>6))]<<4)|
         sbox8[SBOXBIT(e[5]&0x3f)];

    return state;
}

/* Key schedule */
void des_key_setup(const BYTE key[], BYTE schedule[][6], DES_MODE mode)
{
    WORD i,j,C=0,D=0;
    const WORD shifts[16]={1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

    for(i=0;i<16;i++){
        C=((C<<shifts[i])|(C>>(28-shifts[i])))&0xfffffff0;
        D=((D<<shifts[i])|(D>>(28-shifts[i])))&0xfffffff0;
        int idx=(mode==DES_DECRYPT)?15-i:i;
        for(j=0;j<6;j++) schedule[idx][j]=0;
    }
}

/* Encrypt/decrypt one block */
void des_crypt(const BYTE in[], BYTE out[], const BYTE key[][6])
{
    WORD state[2];
    IP(state,in);
    for(int i=0;i<15;i++){
        WORD t=state[1];
        state[1]=f(state[1],key[i])^state[0];
        state[0]=t;
    }
    state[0]=f(state[1],key[15])^state[0];
    InvIP(state,out);
}

/* Triple DES */
void three_des_key_setup(const BYTE key[], BYTE schedule[][16][6], DES_MODE mode)
{
    des_key_setup(key,schedule[0],mode);
    des_key_setup(key+8,schedule[1],!mode);
    des_key_setup(key+16,schedule[2],mode);
}

void three_des_crypt(const BYTE in[], BYTE out[], const BYTE key[][16][6])
{
    des_crypt(in,out,key[0]);
    des_crypt(out,out,key[1]);
    des_crypt(out,out,key[2]);
}
