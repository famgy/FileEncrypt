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

#define FILE_SECURITY_EXPORT __attribute__((visibility("default")))

FILE_SECURITY_EXPORT void startInlineHook();
FILE_SECURITY_EXPORT void testBreak(int va_whence, int tmp_whence);


#ifdef __cplusplus
}
#endif

#endif //FILE_SECURITY_H
