//
// Created by famgy on 18-10-15.
//

#ifndef MSMSDK_FILE_ENCRYPT_H
#define MSMSDK_FILE_ENCRYPT_H

#include <cstdio>


extern size_t fileSm4Encrypt(const unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext);
extern size_t fileSm4Decrypt(const unsigned char * ciphertext, size_t ciphertextSize, unsigned char *plaintext);
extern size_t fileXorEncrypt(const unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext);
extern size_t fileXorDecrypt(const unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext);

#endif //MSMSDK_FILE_ENCRYPT_H
