//
// Created by famgy on 18-10-11.
//

#include <jni.h>
#include <android/log.h>
#include <string.h>
#include "util/debug.h"
#include "sm4.h"

#define JNI_API_DEF(f) Java_com_suninfo_msmsdk_activity_GmActivity_##f

extern "C" {

uint8_t ivec[16];
uint8_t key[16];
uint8_t in[128];
uint8_t out[128];
uint8_t len = 64;

JNIEXPORT void JNI_API_DEF(sm4CbcTest)(JNIEnv *env, jobject obj) {
    (void) env;
    (void) obj;

    sm4_context sm4Context;

    __android_log_print(ANDROID_LOG_DEBUG, "===gm_jni===", "sm4Test called.");

    for (int i = 0; i < len; i++) {
        in[i] = i;
    }
    memset(key, 0x88, 16);
    memset(ivec, 0x99, 16);


    //sm4_cbc_encrypt(in, out, len, &stSm4Key, ivec);

    sm4_setkey_enc(&sm4Context, key);
    sm4_crypt_cbc(&sm4Context, SM4_ENCRYPT, len,ivec, in, out);

    printHex("encrypt key ", key, 16);
    printHex("encrypt iv ", ivec, 16);
    printHex("encrypt in ", in, len);
    printHex("encrypt out", out, len);

    sm4_setkey_dec(&sm4Context, key);
    memset(ivec, 0x99, 16);
    sm4_crypt_cbc(&sm4Context, SM4_DECRYPT, len,ivec, out, in);

    printHex("encrypt key ", key, 16);
    printHex("encrypt iv ", ivec, 16);
    printHex("decrypt out", out, len);
    printHex("decrypt in ", in, len);





    return;
}

}


