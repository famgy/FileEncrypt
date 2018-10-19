//
// Created by famgy on 18-10-15.
//

#ifndef MSMSDK_FILE_ENCRYPT_H
#define MSMSDK_FILE_ENCRYPT_H

#include <cstdio>


extern size_t fileSm4Encrypt(unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext);
extern size_t fileSm4Decrypt(unsigned char * ciphertext, size_t ciphertextSize, unsigned char *plaintext);
extern size_t fileXorEncrypt(unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext);
extern size_t fileXorDecrypt(unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext);

#endif //MSMSDK_FILE_ENCRYPT_H
