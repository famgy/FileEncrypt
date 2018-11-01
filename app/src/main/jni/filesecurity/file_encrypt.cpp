//
// Created by famgy on 18-10-15.
//

#include <cstring>
#include <cstdlib>
#include <cctype>
#include "file_encrypt.h"
#include "../crypto/sm4.h"

void sm4Encrypt(unsigned char input[], size_t inputSize, unsigned char output[], char *secretKey, char *secretIvec) {
    uint8_t ivec[16];
    uint8_t key[16];
    sm4_context sm4Context;

    memcpy(key, secretKey, 16);
    memcpy(ivec, secretIvec, 16);

    sm4_setkey_enc(&sm4Context, key);
    sm4_crypt_cbc(&sm4Context, SM4_ENCRYPT, inputSize, ivec, input, output);
}

void sm4Decrypt(unsigned char input[], size_t inputSize, unsigned char output[], char *secretKey, char *secretIvec) {
    uint8_t ivec[16];
    uint8_t key[16];
    sm4_context sm4Context;

    memcpy(key, secretKey, 16);
    memcpy(ivec, secretIvec, 16);

    sm4_setkey_dec(&sm4Context, key);
    sm4_crypt_cbc(&sm4Context, SM4_DECRYPT, inputSize, ivec, input, output);
}

/**
 * converting Java string to c string
 * appending byte to plain text
 * do sm4 encryption
 * If hexadecimal is true, you will get hexadecimal type cipher text. It is good for displaying on screen.
 * If hexadecimal is false, you will get non-hexadecimal type cipher text.
 */
size_t fileSm4Encrypt(unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext, char *secretKey, char *secretIvec) {

    //execute sm4-cbc encrypt operation on plain text which is already appended
    sm4Encrypt(plaintext, plaintextSize, ciphertext, secretKey, secretIvec);

    return plaintextSize;
}

/**
 * Convert cipher text Java string to c string.
 * Convert cipher text ascii encoding byte to hexadecimal encoding byte.
 * Convert cipher text hexadecimal encoding byte to char.
 * Decrypt cipher text.
 * return plain text.
 */
size_t fileSm4Decrypt(unsigned char * ciphertext, size_t ciphertextSize, unsigned char *plaintext, char *secretKey, char *secretIvec) {

    //check parameters
    if (ciphertext == NULL) {
        perror("cipher text is null...");
        return 0;
    }

    if (plaintext == NULL) {
        perror("plain text is null...");
        return 0;
    }

    if (ciphertextSize <= 0) {
        perror("invalid ciphertextSize argument is <= 0...");
        return 0;
    }

    //execute sm4-cbc decrypt operation
    sm4Decrypt((unsigned char*)ciphertext, ciphertextSize, plaintext, secretKey, secretIvec);

    return ciphertextSize;
}

size_t fileXorEncrypt(unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext) {
    int ciphertextSize = 0;

    //check parameters
    if (plaintext == NULL) {
        perror("plain text is null...");
        return 0;
    }

    if (ciphertext == NULL) {
        perror("cipher text is null...");
        return 0;
    }

    for (int i = 0; i < plaintextSize; i++) {
        ciphertext[i] = plaintext[i] ^ 'f';
        ciphertextSize++;
    }


    return ciphertextSize;
}

/**
 * Convert cipher text Java string to c string.
 * Convert cipher text ascii encoding byte to hexadecimal encoding byte.
 * Convert cipher text hexadecimal encoding byte to char.
 * Decrypt cipher text.
 * return plain text.
 */
size_t fileXorDecrypt(unsigned char * ciphertext, size_t ciphertextSize, unsigned char *plaintext) {
    int plaintextSize = 0;

    //check parameters
    if (ciphertext == NULL) {
        perror("cipher text is null...");
        return 0;
    }

    if (plaintext == NULL) {
        perror("plain text is null...");
        return 0;
    }

    if (ciphertextSize <= 0) {
        perror("invalid ciphertextSize argument is <= 0...");
        return 0;
    }

    for (int i = 0; i < ciphertextSize; i++) {
        plaintext[i] = ciphertext[i] ^ 'f';
        plaintextSize++;
    }

    return plaintextSize;
}