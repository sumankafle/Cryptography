#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mcrypt.h>
#include "aes.h"

int encrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len){
    MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
    if (td == MCRYPT_FAILED) return 1;

    int blocksize = mcrypt_enc_get_block_size(td);
    if (buffer_len % blocksize != 0) return 1;

    if (mcrypt_generic_init(td, key, key_len, IV) < 0) {
        mcrypt_module_close(td);
        return 1;
    }

    mcrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit(td);
    mcrypt_module_close(td);
    
    return 0;
}

int decrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len){
    MCRYPT td = mcrypt_module_open("rijndael-128", NULL, "cbc", NULL);
    if (td == MCRYPT_FAILED) return 1;

    int blocksize = mcrypt_enc_get_block_size(td);
    if (buffer_len % blocksize != 0) return 1;

    if (mcrypt_generic_init(td, key, key_len, IV) < 0) {
        mcrypt_module_close(td);
        return 1;
    }

    mdecrypt_generic(td, buffer, buffer_len);
    mcrypt_generic_deinit(td);
    mcrypt_module_close(td);
    
    return 0;
}

void display(char* data, int len){
    for (int i = 0; i < len; i++)
        printf("%02x ", (unsigned char)data[i]);
    printf("\n");
}
