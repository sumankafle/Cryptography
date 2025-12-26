#ifndef AES_H
#define AES_H

int encrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len);
int decrypt(void* buffer, int buffer_len, char* IV, char* key, int key_len);
void display(char* data, int len);

#endif
