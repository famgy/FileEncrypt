//
// Created by famgy on 18-9-14.
//

#ifndef FILE_SECURITY_H
#define FILE_SECURITY_H 1

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tagFileFdInfo
{
    int fd;
    int dirFd;
    int flag;
    char szFilePath[2048];
}FILE_FD_INFO_S;

//32
typedef struct tagSecretKeys
{ //SM4
    char szSecretKey[16];
    char szSecretIvec[16];
}SECRET_KEYS_S;

//Match FS_HEADER_LEN
typedef struct tagFileHeaderInfo
{
    char szFileHeaderTag[8];
    char szSdkVersion[8];
    char szVerifyUserKey[16]; //user verify key, strcmp
    SECRET_KEYS_S stSecretKeys; //32
}FILE_HEADER_INFO_S;

//Match FILE_HEADER_INFO_S
#define FS_HEADER_LEN 64

#define FILE_SECURITY_EXPORT __attribute__((visibility("default")))

FILE_SECURITY_EXPORT void startInlineHook();
FILE_SECURITY_EXPORT void testBreak(int va_whence, int tmp_whence);


#ifdef __cplusplus
}
#endif

#endif //FILE_SECURITY_H
