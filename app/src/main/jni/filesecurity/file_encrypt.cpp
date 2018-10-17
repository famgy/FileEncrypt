//
// Created by famgy on 18-10-15.
//

#include <cstring>
#include <cstdlib>
#include <cctype>
#include "file_encrypt.h"
#include "../crypto/sm4.h"

static unsigned char appendingByte = '`';


/**
 * Check whether input has been added appendingByte already or not.
 */
bool isAppendedContent(unsigned char *input, size_t inputSize) {
    //check parameters
    if (input == NULL) {
        perror("remove byte from an null input...");
        return false;
    }

    if (inputSize <= 0) {
        perror("invalid inputSize argument is <= 0...");
        return false;
    }

    unsigned char tmp[1];
    tmp[0] = input[inputSize - 1];

    if (input[inputSize - 1] == appendingByte) {
        return true;
    } else {
        return false;
    }
}

/**
 * Calculating how many bytes should be appended to origin.
 * The goal is result of size of origin Mod 16 is 0.
 */
unsigned int calculateAppendingBytes(const unsigned char *origin, size_t originalSize) {

    //check parameters
    if (origin == NULL) {
        perror("invalid origin argument is null...");
        return 0;
    }

    if (originalSize <= 0) {
        perror("invalid originalSize argument is <= 0...");
        return 0;
    }

    if (originalSize % 16 == 0) {
        //origin has been appended already
        if (isAppendedContent((unsigned char*) origin, originalSize)) {

            //calculate the number of appending byte.
            int i = 1;
            int appendingByteCount = 0;
            while (origin[originalSize - i] == appendingByte) {
                i++;
                appendingByteCount++;
            }

            return appendingByteCount;
        } else {
            return 0;
        }

    } else {
        if (isAppendedContent((unsigned char*) origin, originalSize)) {
            perror(
                    "origin is invalid text, it has been appended already, but mod 16 is not 0...");
        } else {
            return 16 - (originalSize % 16);
        }
    }

    return 0;
}

/**
 * Appending origin text.
 * Make sure that the length of origin text Mod 16 is 0
 */
void appendByteToText(const unsigned char *origin, size_t originalSize,
                      unsigned char *destination, int appendingSize) {
    //check parameters
    if (origin == NULL) {
        perror("parameter origin is null...");
        return;
    }

    if (destination == NULL) {
        perror("parameter destination is null...");
        return;
    }

    if (originalSize <= 0) {
        perror("invalid originalSize argument is <= 0...");
        return;
    }

    memcpy(destination, origin, originalSize);

    //appending destination at index of originalSize
    int i;
    for (i = 0; i < appendingSize; i++) {
        destination[originalSize + i] = appendingByte;
    }

    //appending '\0' to indicate the end of text
    destination[originalSize + appendingSize] = '\0';

    return;
}

/**
 * remove appending bytes from text
 */
size_t removeByteFromAppendContent(unsigned char* input, size_t inputSize) {

    //check parameters
    if (input == NULL) {
        perror("remove byte from an null input...");
        return 0;
    }

    if (!isAppendedContent(input, inputSize)) {
        perror("remove byte from input which has not been appended...");
        return inputSize;
    }

    unsigned int appendingByteSize = calculateAppendingBytes((const unsigned char*) input, (size_t) inputSize);

    return inputSize - appendingByteSize;
}

void sm4Encrypt(unsigned char input[], size_t inputSize, unsigned char output[]) {
    uint8_t ivec[16];
    uint8_t key[16];
    sm4_context sm4Context;

    memset(key, 0x88, 16);
    memset(ivec, 0x99, 16);

    sm4_setkey_enc(&sm4Context, key);
    sm4_crypt_cbc(&sm4Context, SM4_ENCRYPT, inputSize, ivec, input, output);
}

void sm4Decrypt(unsigned char input[], size_t inputSize, unsigned char output[]) {
    uint8_t ivec[16];
    uint8_t key[16];
    sm4_context sm4Context;

    memset(key, 0x88, 16);
    memset(ivec, 0x99, 16);

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
size_t fileSm4Encrypt(const unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext) {

    //check parameters
    if (plaintext == NULL) {
        perror("plain text is null...");
        return 0;
    }

    if (ciphertext == NULL) {
        perror("cipher text is null...");
        return 0;
    }

    /*
     * preprocessing plain text before sm4 encryption
     */
    unsigned int appendingSize = calculateAppendingBytes(plaintext, plaintextSize);
    unsigned int plaintextAfterAppendingSize = plaintextSize + appendingSize;

    unsigned char *plaintextAfterAppending = (unsigned char*) malloc(plaintextAfterAppendingSize + 1);
    if (NULL == plaintextAfterAppending) {
        perror("plaintextAfterAppending malloc unsuccessfully...");
        return 0;
    }

    appendByteToText(plaintext, plaintextSize, plaintextAfterAppending, appendingSize);
    printf("sm4 plain text finishes appending...\n");
    printf("plaintextAfterAppending is %d \n", plaintextAfterAppendingSize);

    /*
     * allocate a block of memory to store cipher text,
     * the length is the same as plain text after appending
     */
    unsigned char *ciphertextTmp = (unsigned char *) malloc(plaintextAfterAppendingSize + 1);
    if (NULL == ciphertextTmp) {
        perror("ciphertextTmp malloc unsuccessfully...");
        return 0;
    }

    //execute sm4-cbc encrypt operation on plain text which is already appended
    sm4Encrypt(plaintextAfterAppending, plaintextAfterAppendingSize, ciphertextTmp);

    //free plaintextAfterAppending unused memory
    free((void *) plaintextAfterAppending);

    /*
     * convert cipher text to hexadecimal type string
     * the size of hex string become twice of original cipher text
     * the end of string is '\0' character
     * the size of ciphertextTmp and plaintextAfterAppending are the same.
     */
    unsigned int ciphertextTmpSize = plaintextAfterAppendingSize;
    printf("sm4 finish encryption and then convert to hex... \n");
    printf("ciphertextTmp size is %d \n", ciphertextTmpSize);

    //Copying size is ciphertextTmpSize
    memcpy((void *) ciphertext, (const void*) ciphertextTmp, ciphertextTmpSize);

    //free nonHexCiphertext unused memory
    free((void *) ciphertextTmp);

    return ciphertextTmpSize;
}

/**
 * Convert cipher text Java string to c string.
 * Convert cipher text ascii encoding byte to hexadecimal encoding byte.
 * Convert cipher text hexadecimal encoding byte to char.
 * Decrypt cipher text.
 * return plain text.
 */
size_t fileSm4Decrypt(const unsigned char * ciphertext, size_t ciphertextSize, unsigned char *plaintext) {

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
    sm4Decrypt((unsigned char*)ciphertext, ciphertextSize, plaintext);

    //remove appending byte from plaintext.
    size_t plaintextSize = ciphertextSize;
    plaintextSize = removeByteFromAppendContent(plaintext, plaintextSize);

    return plaintextSize;
}

size_t fileXorEncrypt(const unsigned char *plaintext, size_t plaintextSize, unsigned char *ciphertext) {
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
size_t fileXorDecrypt(const unsigned char * ciphertext, size_t ciphertextSize, unsigned char *plaintext) {
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