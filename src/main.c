#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes.h"
#include "rsa.h"
// add all test is switch case 
int main() {
    int choice;

    printf("Choose algorithm to test:\n");
    printf("1 - RSA Test\n");
    printf("2 - AES Test (default)\n");
    printf("Enter choice: ");
    if (scanf("%d", &choice) != 1) {
        choice = 2; // default to AES
    }

    switch (choice) {
        case 1: {
            // --- RSA test ---
            char plaintext[] = "Hello World!";
            RSAKey keypair;
            int last_block_size = 0;
            if (!rsa_generate_keys(61, 53, &keypair)) {
                printf("Failed to generate RSA keys\n");
                return 1;
            }
            int blocks;
            long cipher[16];  // max 16 blocks for demo
            char decrypted[32] = {0};

            rsa_encrypt_string(plaintext, cipher, &blocks, keypair);
            printf("\n== RSA Test ==\nCipher blocks: ");
            for(int i=0; i<blocks; i++) printf("%ld ", cipher[i]);
            printf("\n");

            rsa_decrypt_string(cipher, blocks, last_block_size, decrypted, keypair);
            printf("Decrypted text: %s\n", decrypted);
            break;
        }

        case 2:
        default: {
            // --- AES test ---
            char* plaintext = "test text 123";
            char* IV = "AAAAAAAAAAAAAAAA";
            char* key = "0123456789abcdef";
            int buffer_len = 16;
            char* buffer = calloc(1, buffer_len);
            strncpy(buffer, plaintext, buffer_len);

            printf("\n== AES Test ==\n");
            printf("plain: %s\n", plaintext);

            encrypt(buffer, buffer_len, IV, key, 16);
            printf("cipher: "); display(buffer, buffer_len);

            decrypt(buffer, buffer_len, IV, key, 16);
            printf("decrypt: %s\n", buffer);

            free(buffer);
            break;
        }
    }

    return 0;
}
