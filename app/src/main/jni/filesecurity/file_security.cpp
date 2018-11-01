//
// Created by famgy on 18-9-14.
//

#include <jni.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <android/log.h>
#include <string.h>
#include <malloc.h>
#include <iostream>
#include <set>
#include <sys/syscall.h>
#include <map>
#include <errno.h>
#include <unistd.h>
#include <regex.h>
#include <sys/mman.h>
#include <cstdlib>

#include "../hook/inlinehook/inlineHook.h"

#include "file_security.h"
#include "file_encrypt.h"
#include "file_log.h"

#define _LARGEFILE64_SOURCE


extern "C" int __openat(int, const char*, int, int);

extern const char* inline_originApk;
extern const char* inline_baseApk;
extern int inline_baseApkL;
extern JavaVM * inline_android_vm;

std::map<int, FILE_FD_INFO_S *> g_FileFdMap;

#define BLOCK_SIZE 64
#define FILE_HEADER_TAG "FHT"
#define SDK_VERSION "1.0"
#define VERIFY_USER_KEY "88888888"

int (*old_openat)(int, const char *, int, int) = NULL;
int (*old_fstat)(int fd, struct stat *statbuf) = NULL;
void* (*old_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void* (*old_mmap64)(void* __addr, size_t __size, int __prot, int __flags, int __fd, off64_t __offset) __INTRODUCED_IN(21);
int (*old_rename)(const char* __old_path, const char* __new_path);
int (*old_fprintf)(FILE *stream, const char *format, ...);
int (*old_dprintf)(int fd, const char *format, ...);
int (*old_ftruncate)(int fd, off_t length);


ssize_t (*old_pread)(int fd, void *buf, size_t count, off_t offset) = NULL;
ssize_t (*old_pwrite)(int fd, const void *buf, size_t count, off_t offset) = NULL;
ssize_t (*old_read)(int fd, void *buf, size_t count) = NULL;
ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;
off_t (*old_lseek)(int fd, off_t offset, int whence) = NULL;
off64_t (*old_lseek64)(int fd, off64_t offset, int whence) = NULL;

int (*old_close)(int fd) = NULL;


void testBreak(int va_whence, int tmp_whence) {
/*    int a = 1;

    char *buffer = NULL;

    buffer[0] = 'A';*/

    log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====", "testBreak addr=%p, va_whence = %d, tmp_whence = %d\n\n", testBreak, va_whence, tmp_whence);


    return;
}

//Write encrypt head
static void addFileHeader(int fd, FILE_HEADER_INFO_S *pstFileHeaderInfo) {
    if (pstFileHeaderInfo == NULL) {
        log_print(ANDROID_LOG_DEBUG, "inline======", "addFileHeader failed : %s", "pstFileHeaderInfo == NULL");
        return;
    }

    if (pstFileHeaderInfo->szFileHeaderTag[0] == '\0') {
        FILE_HEADER_INFO_S stFileHeaderInfo;
        memset(&stFileHeaderInfo, 0, sizeof(FILE_HEADER_INFO_S));

        strcpy(stFileHeaderInfo.szFileHeaderTag, FILE_HEADER_TAG);
        strcpy(stFileHeaderInfo.szSdkVersion, SDK_VERSION);
        strcpy(stFileHeaderInfo.szVerifyUserKey, VERIFY_USER_KEY);

        srand((int)time(NULL));
        int randNum = rand();

        char szAppend[12];
        memset(szAppend, 0x88, 12);

        char szSecretKeys[32] = {0};
        memcpy(szSecretKeys, stFileHeaderInfo.szFileHeaderTag, 8);
        memcpy(szSecretKeys + 8, stFileHeaderInfo.szSdkVersion, 8);
        memcpy(szSecretKeys + 16, &randNum , sizeof(int));
        memcpy(szSecretKeys + 20, szAppend, 12);
        for (int i = 0; i < 32; i++) {
            szSecretKeys[i] = szSecretKeys[i] ^ 'f';
        }

        char *pcSecretKeysTmp = szSecretKeys;
        memcpy(stFileHeaderInfo.stSecretKeys.szSecretKey, pcSecretKeysTmp, 16);
        memcpy(stFileHeaderInfo.stSecretKeys.szSecretIvec, pcSecretKeysTmp + 16, 16);

        memcpy(pstFileHeaderInfo, &stFileHeaderInfo, sizeof(FILE_HEADER_INFO_S));
        log_print(ANDROID_LOG_DEBUG, "inline======", "addFileHeader : %s", "FileHeaderInfo update");
    }



    old_lseek(fd, 0, SEEK_SET);
    int wLen = old_write(fd, pstFileHeaderInfo, FS_HEADER_LEN);
    if (wLen != FS_HEADER_LEN) {
        log_print(ANDROID_LOG_DEBUG, "inline======", "addFileHeader failed : %s", strerror(errno));
        return;
    }
    log_print(ANDROID_LOG_DEBUG, "inline======", "addFileHeader successful : FileHeaderTag = %s, version = %s",
              pstFileHeaderInfo->szFileHeaderTag, pstFileHeaderInfo->szSdkVersion);


    return;
}

static int fileEncrypt(int dirFd, const char *srcPathName, FILE_HEADER_INFO_S *pstFileHeaderInfo)
{
    log_print(ANDROID_LOG_INFO, "inlinehook==fileEncrypt===", "init , open: fileName = %s", srcPathName);

    int fd_s = old_openat(dirFd, srcPathName, O_RDWR, 0640);
    if (fd_s == -1) {
        log_print(ANDROID_LOG_DEBUG, "inline======", "open failed : %s", strerror(errno));
        return fd_s;
    }

    char pathNameTmp[2048] = {0};
    strcat(pathNameTmp, srcPathName);
    strcat(pathNameTmp, "_tmp");
    int fd_d = old_openat(dirFd, pathNameTmp, O_CREAT | O_RDWR, 0640);
    if (fd_d == -1) {
        log_print(ANDROID_LOG_DEBUG, "inline======", "open failed : %s", strerror(errno));
        old_close(fd_d);
        return fd_d;
    }

    //Write encrypt head
    addFileHeader(fd_d, pstFileHeaderInfo);

    //Write encrypt body
    unsigned char plaintBuffer[BLOCK_SIZE]={0};
    unsigned char cipherBuffer[BLOCK_SIZE]={0};
    int readBufferLen;
    int cipherBufferSize;

    while ((readBufferLen = old_read(fd_s, plaintBuffer, BLOCK_SIZE)) > 0) {
        if (readBufferLen == BLOCK_SIZE) {
            cipherBufferSize = fileSm4Encrypt(plaintBuffer, readBufferLen, cipherBuffer, pstFileHeaderInfo->stSecretKeys.szSecretKey, pstFileHeaderInfo->stSecretKeys.szSecretIvec);
            log_print(ANDROID_LOG_DEBUG, "===init==", "readlen = %d",readBufferLen);
        } else if (readBufferLen < BLOCK_SIZE) {
            log_print(ANDROID_LOG_DEBUG, "===init==", "readlen = %d",readBufferLen);
            log_print(ANDROID_LOG_DEBUG, "====before==", "read: buffer = %x, %x, len = %d", ((char *) plaintBuffer)[0], ((char *) plaintBuffer)[1], readBufferLen);

            cipherBufferSize = fileXorEncrypt(plaintBuffer, readBufferLen, cipherBuffer);

            log_print(ANDROID_LOG_DEBUG, "====after==", "read: buffer = %x, %x", ((char *) cipherBuffer)[0], ((char *) cipherBuffer)[1]);
        }

        old_write(fd_d, cipherBuffer, cipherBufferSize);
    }

    old_close(fd_s);
    old_close(fd_d);

    // Mv file
    unlink(srcPathName);
    log_print(ANDROID_LOG_DEBUG, "==unlink==", "fileName = %s",srcPathName);

    old_rename(pathNameTmp, srcPathName);
    log_print(ANDROID_LOG_DEBUG, "==rename==", "fileName = %s",srcPathName);

    return 0;
}

static FILE_FD_INFO_S *findFileFdInfo(const int fd) {
    std::map<int, FILE_FD_INFO_S *>::iterator it;
    FILE_FD_INFO_S *pstFileFdInfo = NULL;

    it = g_FileFdMap.find(fd);
    if (it != g_FileFdMap.end()) {
        pstFileFdInfo = it->second;
    }

    return pstFileFdInfo;
}

static bool regMatchFilePath(const char *pathName)
{
    bool result = false;
    regex_t reg;
    regmatch_t pm[1];
    int  status = 0;
    //char pattern[] = "/tencent/QQfile_recv/";
    //char pattern[] = "/storage/emulated/0/Netease/Mail/0/.attachments/docx_test.docx";

    char pattern[] = "(/tencent/QQmail/tmp/|/tencent/QQfile_recv/|/Netease/Mail/0/.attachments/)";

    /*正则表达式：编译-匹配-释放*/
    status = regcomp(&reg, pattern, REG_EXTENDED|REG_NEWLINE);  //扩展正则表达式和识别换行符
    if (status != 0){    //成功返回0
        return false;
    }

    status = regexec(&reg, pathName, 1, pm, 0);
    if (status == 0){
        log_print(ANDROID_LOG_DEBUG, "\n\ninline======", "regMatchFilePath matched");
        result = true;
    }

    regfree(&reg);

    return result;
}

static bool regMatchFileType(const char *pathName)
{
    bool result = false;
    regex_t reg;
    regmatch_t pm[1];
    int  status = 0;
    //char pattern[] = "[.](txt|pdf|docx|pptx|xlsx)$";
    char pattern[] = "(txt_test.txt|pdf_test.pdf|docx_test.docx|pptx_test.pptx|xlsx_test.xlsx|mfi)";

    /*正则表达式：编译-匹配-释放*/
    status = regcomp(&reg, pattern, REG_EXTENDED|REG_NEWLINE);  //扩展正则表达式和识别换行符
    if (status != 0){    //成功返回0
        return false;
    }

    status = regexec(&reg, pathName, 1, pm, 0);
    if (status == 0){
        log_print(ANDROID_LOG_DEBUG, "inline======", "regMatchFileType matched");
        result = true;
    }

    regfree(&reg);

    return result;
}

static void parseHeaderInfo(char *pcHeaderBuffer, FILE_HEADER_INFO_S *pstFileHeaderInfo) {
    memset(pstFileHeaderInfo, 0, sizeof(FILE_HEADER_INFO_S));
    memcpy(pstFileHeaderInfo->szFileHeaderTag, pcHeaderBuffer, 8);
    memcpy(pstFileHeaderInfo->szSdkVersion, pcHeaderBuffer + 8, 8);
    memcpy(pstFileHeaderInfo->szVerifyUserKey, pcHeaderBuffer + 16, 16);

    log_print(ANDROID_LOG_DEBUG, "==inlinehook=====", "parse FileHeaderTag successfull, HeaderTag = %s, SdkVersion = %s, VerifyUserKey = %s",
              pstFileHeaderInfo->szFileHeaderTag, pstFileHeaderInfo->szSdkVersion, pstFileHeaderInfo->szVerifyUserKey);


    memcpy(pstFileHeaderInfo->stSecretKeys.szSecretKey, pcHeaderBuffer + 32, 16);
    memcpy(pstFileHeaderInfo->stSecretKeys.szSecretIvec, pcHeaderBuffer + 48, 16);

    return;
}

static int __nativehook_impl_android_openat(int dirFd, const char *pathName, int flag, int mode) {
    FILE_HEADER_INFO_S stFileHeaderInfo;

    // 破解防打包
//    int lo = strlen(pathName);
//    if (lo == inline_baseApkL && strncmp(inline_baseApk, pathName, lo) == 0) {
//        //log_print(ANDROID_LOG_DEBUG, "xhook", "open : %s replace %s\n", inline_originApk, pathname);
//        return old_openat(dirFd, inline_originApk, flag, mode);
//    }

    // File Security
    if (regMatchFilePath(pathName) == false && regMatchFileType(pathName) == false) {

        int fd = old_openat(dirFd, pathName, flag, mode);
        //log_print(ANDROID_LOG_DEBUG, "inlinehook", "regMatch failed, openat:%s, fd = %d\n", pathName, fd);
        return fd;
    }

    if (flag & O_CREAT) {
        log_print(ANDROID_LOG_INFO, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_CREAT");
    }

    if (flag & O_APPEND) {
        log_print(ANDROID_LOG_INFO, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_APPEND");
    }

    if (flag & O_TRUNC) {
        log_print(ANDROID_LOG_INFO, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_TRUNC");
    }

    if (flag & O_NOATIME) {
        log_print(ANDROID_LOG_INFO, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_NOATIME");
    }

    if (flag & O_CREAT) {
        log_print(ANDROID_LOG_INFO, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_DSYNC");
    }

    if (flag & FASYNC) {
        log_print(ANDROID_LOG_INFO, "inlinehook", "openat:%s, flagV = %s\n", pathName, "FASYNC");
    }

    if (flag & O_DSYNC) {
        log_print(ANDROID_LOG_INFO, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_DSYNC");
    }

    if (access(pathName, F_OK) == 0) {
        int fd_o = old_openat(dirFd, pathName, O_RDWR, 0640);
        if (fd_o == -1) {
            return -1;
        }

        char headerBuffer[FS_HEADER_LEN] = {0};


        int readHeadLen = old_read(fd_o, headerBuffer, FS_HEADER_LEN);
        old_close(fd_o);

        if (readHeadLen < FS_HEADER_LEN) {
            log_print(ANDROID_LOG_DEBUG, "==inlinehook=====", "read %d: FileHeaderTag failed", fd_o);
        } else {
            memset(&stFileHeaderInfo, 0, sizeof(FILE_HEADER_INFO_S));
            parseHeaderInfo(headerBuffer, &stFileHeaderInfo);
        }

        if (0 == strcmp(stFileHeaderInfo.szFileHeaderTag, FILE_HEADER_TAG) &&
            0 == strcmp(stFileHeaderInfo.szSdkVersion, SDK_VERSION) &&
            0 == strcmp(stFileHeaderInfo.szVerifyUserKey, VERIFY_USER_KEY))
        {
            int fdTmp = old_openat(dirFd, pathName, flag, mode);
            if (fdTmp != -1) {
                // Add file-fd-list for matching.
                FILE_FD_INFO_S *pstFileFdInfo = (FILE_FD_INFO_S *) malloc(sizeof(FILE_FD_INFO_S));
                if (pstFileFdInfo == NULL) {
                    return -1;
                }
                memset(pstFileFdInfo, 0, sizeof(FILE_FD_INFO_S));

                pstFileFdInfo->fd = fdTmp;
                pstFileFdInfo->dirFd = dirFd;
                pstFileFdInfo->flag = flag;
                strcpy(pstFileFdInfo->szFilePath, pathName);
                memcpy(&pstFileFdInfo->stFileHeaderInfo, &stFileHeaderInfo, sizeof(FILE_HEADER_INFO_S));
                g_FileFdMap.insert(std::pair<int, FILE_FD_INFO_S *>(fdTmp, pstFileFdInfo));

                if (flag & O_TRUNC) {
                    //Write encrypt head
                    log_print(ANDROID_LOG_INFO, "inlinehook====ggg, O_TRUNC", "openat create : %s", pathName);
                    int fd_g = old_openat(dirFd, pathName, O_RDWR, 0640);
                    if (fd_g == -1) {
                        log_print(ANDROID_LOG_INFO, "inlinehook====ccc", "openat failed : %s, because %s", pathName, strerror(errno));
                        return -1;
                    }

                    addFileHeader(fd_g, &pstFileFdInfo->stFileHeaderInfo);
                    old_close(fd_g);
                }

                old_lseek(fdTmp, FS_HEADER_LEN, SEEK_SET);
                log_print(ANDROID_LOG_INFO, "inlinehook==hasFileHeaderData===", "init , open: fdTmp = %d, curOffset = %d\n", fdTmp, (int) old_lseek(fdTmp, 0, SEEK_CUR));
            }

            return fdTmp;
        }
    }

    //File encrypt
    memset(&stFileHeaderInfo, 0, sizeof(FILE_HEADER_INFO_S));
    if (fileEncrypt(dirFd, pathName, &stFileHeaderInfo) != 0) {
        log_print(ANDROID_LOG_INFO, "inlinehook=====", "file : %s, encrypt failed", pathName);
    }

    //open old way
    int fd = old_openat(dirFd, pathName, flag, mode);
    log_print(ANDROID_LOG_INFO, "inlinehook====sss", "openat:%s, fd = %d", pathName, fd);

    //Save file info
    if (fd != -1) {
        // Add file-fd-list for matching.
        FILE_FD_INFO_S *pstFileFdInfo = (FILE_FD_INFO_S *) malloc(sizeof(FILE_FD_INFO_S));
        if (pstFileFdInfo == NULL) {
            return -1;
        }

        pstFileFdInfo->dirFd = dirFd;
        pstFileFdInfo->fd = fd;
        pstFileFdInfo->flag = flag;
        strcpy(pstFileFdInfo->szFilePath, pathName);
        memcpy(&pstFileFdInfo->stFileHeaderInfo, &stFileHeaderInfo, sizeof(FILE_HEADER_INFO_S));
        g_FileFdMap.insert(std::pair<int, FILE_FD_INFO_S *>(fd, pstFileFdInfo));

//return fd;


        if (flag & O_TRUNC) {
            //Write encrypt head
            log_print(ANDROID_LOG_INFO, "inlinehook====ccc, O_TRUNC", "openat create : %s", pathName);
            int fd_c = old_openat(dirFd, pathName, O_RDWR, 0640);
            if (fd_c == -1) {
                log_print(ANDROID_LOG_INFO, "inlinehook====ccc", "openat failed : %s, because %s", pathName, strerror(errno));
                return -1;
            }

            addFileHeader(fd_c, &pstFileFdInfo->stFileHeaderInfo);
            old_close(fd_c);
        }

        old_lseek(fd, FS_HEADER_LEN, SEEK_SET);
        log_print(ANDROID_LOG_INFO, "inlinehook=====ooo", "end , open: fd = %d, curOffset = %d\n", fd, (int) old_lseek(fd, 0, SEEK_CUR));
    }

    return fd;
}

static int __nativehook_impl_android_close(int fd) {
    std::map<int, FILE_FD_INFO_S *>::iterator it;
    int result = 0;

    it = g_FileFdMap.find(fd);
    if (it != g_FileFdMap.end()) {
        log_print(ANDROID_LOG_INFO, "inlinehook", "close: fd = %d", fd);

        result = old_close(fd);
        if (result == 0) {
            g_FileFdMap.erase(it);
            FILE_FD_INFO_S *fileFdInfoTmp = it->second;
            free(fileFdInfoTmp);

            log_print(ANDROID_LOG_INFO, "inlinehook===end===", "finish close: fd = %d", fd);
        }
    } else {
//        result = syscall(SYS_close, fd);
        result = old_close(fd);
    }

    return result;
}

static size_t findDecryptPoint(off_t curOffset, size_t *DecryptPoint) {
    int i;
    size_t relativeOffset;
    size_t descryptOffset = curOffset - FS_HEADER_LEN;

    for (i = 0;;i = i + BLOCK_SIZE) {
        if (i + BLOCK_SIZE > descryptOffset) {
            break;
        }
    }

    *DecryptPoint = i + FS_HEADER_LEN;


    relativeOffset = descryptOffset - i;
    log_print(ANDROID_LOG_DEBUG, "after==inlinehook=====", "DecryptPoint = %ld, relativeOffset = %ld", *DecryptPoint, relativeOffset);

    return relativeOffset;
}

static int bufferEncrypt(int fd, const void *buf,size_t count, off_t offset, FILE_FD_INFO_S *pstFileFdInfo)
{
    unsigned char *inBuf = (unsigned char *)buf;
    unsigned char *bufferTmp = NULL;
    size_t relativeOffset = 0;
    size_t decryptPoint = 0;
    unsigned char plaintBuffer[BLOCK_SIZE] = {0};
    unsigned char cipherBuffer[BLOCK_SIZE] = {0};
    int plaintBufferSize = 0;
    int cipherBufferSize = 0;
    size_t fdCurOffset = 0;
    size_t fdCurWOffset = 0;

    log_print(ANDROID_LOG_DEBUG, "\n\ninline======", "bufferEncrypt, fd = %d, count = %d", fd, count);


    if (offset != -1) {
        fdCurOffset = old_lseek(fd, offset, SEEK_SET);
    } else {
        fdCurOffset = old_lseek(fd, 0, SEEK_CUR);
    }

    std::map<int, FILE_FD_INFO_S *>::iterator it;
    it = g_FileFdMap.find(fd);
    FILE_FD_INFO_S *fileFdInfoTmp = it->second;
    int fd_r = old_openat(fileFdInfoTmp->dirFd, fileFdInfoTmp->szFilePath, O_RDWR, 0640);
    if (fd_r == -1) {
        return -1;
    }

    // set offset decryptPoint
    relativeOffset = findDecryptPoint(fdCurOffset, &decryptPoint);
    fdCurWOffset = old_lseek(fd_r, decryptPoint, SEEK_SET);

    int ret;
    int readBufferLen;
    size_t hasEffectSize = 0;
    char *pcSecretKey = pstFileFdInfo->stFileHeaderInfo.stSecretKeys.szSecretKey;
    char *pcSecretIvec = pstFileFdInfo->stFileHeaderInfo.stSecretKeys.szSecretIvec;
    while (hasEffectSize < count) {
        readBufferLen = old_read(fd_r, cipherBuffer, BLOCK_SIZE);
        if (readBufferLen == -1) {
            return -1;
        } else if (readBufferLen == 0) {
            ;
        }else if (readBufferLen < relativeOffset) {
            return 0;
        }

        if (readBufferLen == BLOCK_SIZE) {
            log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(readBufferLen == BLOCK_SIZE), fd = %d, hasEffectSize = %d", fd, hasEffectSize);
            plaintBufferSize = fileSm4Decrypt(cipherBuffer, BLOCK_SIZE, plaintBuffer, pcSecretKey, pcSecretIvec);
            log_print(ANDROID_LOG_DEBUG, "inline======", "fileSm4Decrypt finish, plaintBufferSize = %d", plaintBufferSize);
            if (relativeOffset != 0) {
                log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(relativeOffset != 0), fd = %d", fd);
                if (hasEffectSize + (plaintBufferSize - relativeOffset) < count) {
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(hasEffectSize + (plaintBufferSize - relativeOffset) < count), fd = %d", fd);
                    memcpy(plaintBuffer + relativeOffset, inBuf + hasEffectSize, plaintBufferSize - relativeOffset);
                    hasEffectSize += plaintBufferSize - relativeOffset;

                    cipherBufferSize = fileSm4Encrypt(plaintBuffer, BLOCK_SIZE, cipherBuffer, pcSecretKey, pcSecretIvec);
                    old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
                    fdCurWOffset += cipherBufferSize;
                } else if (hasEffectSize + (plaintBufferSize - relativeOffset) == count) {
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(hasEffectSize + (plaintBufferSize - relativeOffset) == count), fd = %d", fd);
                    memcpy(plaintBuffer + relativeOffset, inBuf + hasEffectSize, plaintBufferSize - relativeOffset);
                    hasEffectSize += plaintBufferSize - relativeOffset;

                    cipherBufferSize = fileSm4Encrypt(plaintBuffer, BLOCK_SIZE, cipherBuffer, pcSecretKey, pcSecretIvec);
                    ret = old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
                    if (ret == -1) {
                        log_print(ANDROID_LOG_DEBUG, "inline======", "open failed : %s", strerror(errno));
                        return -1;
                    }
                    fdCurWOffset += cipherBufferSize;
                    break;
                } else {
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(hasEffectSize + (plaintBufferSize - relativeOffset) > count), fd = %d", fd);
                    memcpy(plaintBuffer + relativeOffset, inBuf + hasEffectSize, count - hasEffectSize);
                    hasEffectSize += count - hasEffectSize;

                    cipherBufferSize = fileSm4Encrypt(plaintBuffer, BLOCK_SIZE, cipherBuffer, pcSecretKey, pcSecretIvec);
                    ret = old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
                    if (ret == -1) {
                        log_print(ANDROID_LOG_DEBUG, "inline======", "open failed : %s", strerror(errno));
                        return -1;
                    }
                    fdCurWOffset += cipherBufferSize;
                    break;
                }
                relativeOffset = 0;
            } else {
                log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(relativeOffset == 0), fd = %d", fd);
                if (hasEffectSize + plaintBufferSize < count) {
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(hasEffectSize + plaintBufferSize < count), fd = %d", fd);
                    cipherBufferSize = fileSm4Encrypt(inBuf + hasEffectSize, BLOCK_SIZE, cipherBuffer, pcSecretKey, pcSecretIvec);
                    hasEffectSize += cipherBufferSize;

                    old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
                    fdCurWOffset += cipherBufferSize;
                } else if (hasEffectSize + plaintBufferSize == count) {
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(hasEffectSize + plaintBufferSize == count), fd = %d", fd);
                    cipherBufferSize = fileSm4Encrypt(inBuf + hasEffectSize, BLOCK_SIZE, cipherBuffer, pcSecretKey, pcSecretIvec);
                    hasEffectSize += cipherBufferSize;

                    old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
                    fdCurWOffset += cipherBufferSize;
                    break;
                } else {
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(hasEffectSize + plaintBufferSize > count), fd = %d", fd);
                    memcpy(plaintBuffer, inBuf + hasEffectSize, count - hasEffectSize);
                    hasEffectSize += count - hasEffectSize;

                    cipherBufferSize = fileSm4Encrypt(plaintBuffer, BLOCK_SIZE, cipherBuffer, pcSecretKey, pcSecretIvec);
                    old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
                    fdCurWOffset += cipherBufferSize;
                    log_print(ANDROID_LOG_DEBUG, "inline======", "finish, bufferEncrypt(hasEffectSize + plaintBufferSize > count), fd = %d, hasEffectSize = %d", fd, hasEffectSize);
                    break;
                }
            }
        } else if (readBufferLen < BLOCK_SIZE) {
            log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(readBufferLen < BLOCK_SIZE), fd = %d", fd);
            if (readBufferLen != 0) {
                log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(readBufferLen != 0), fd = %d", fd);
                plaintBufferSize = fileXorDecrypt(cipherBuffer, readBufferLen, plaintBuffer);
                if (fdCurOffset > fdCurWOffset) {
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(fdCurOffset > fdCurWOffset), fd = %d", fd);
                    bufferTmp = (unsigned char *)malloc((fdCurOffset - fdCurWOffset) + (count - hasEffectSize));
                    if (bufferTmp == NULL) {
                        return -1;
                    }
                    memcpy(bufferTmp, plaintBuffer, fdCurOffset - fdCurWOffset);
                    memcpy(bufferTmp + (fdCurOffset - fdCurWOffset), inBuf + hasEffectSize, count - hasEffectSize);
                    count = (fdCurOffset - fdCurWOffset) + count;
                    log_print(ANDROID_LOG_DEBUG, "inline======", "333bufferEncrypt, fd = %d, hasEffectSize = %d, count = %d", fd, hasEffectSize, count);
                } else if(fdCurOffset == fdCurWOffset) {
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(fdCurOffset == fdCurWOffset), fd = %d", fd);
                    bufferTmp = (unsigned char *)malloc(count - hasEffectSize);
                    if (bufferTmp == NULL) {
                        return -1;
                    }
                    memcpy(bufferTmp, inBuf + hasEffectSize, count - hasEffectSize);
                    log_print(ANDROID_LOG_DEBUG, "inline======", "222bufferEncrypt, fd = %d, hasEffectSize = %d, count = %d", fd, hasEffectSize, count);
                } else {
                    //Nerver occur
                    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(fdCurOffset < fdCurWOffset), fd = %d", fd);
                    ;
                }
                log_print(ANDROID_LOG_DEBUG, "inline======", "111bufferEncrypt, fd = %d, hasEffectSize = %d, count = %d", fd, hasEffectSize, count);
            } else {
                log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(readBufferLen == 0), fd = %d", fd);
                //写一个空文件的时候，且写偏移不为0的情况
                bufferTmp = (unsigned char *)malloc(count - hasEffectSize);
                if (bufferTmp == NULL) {
                    return -1;
                }

                memcpy(bufferTmp, inBuf + hasEffectSize, count - hasEffectSize);
                log_print(ANDROID_LOG_DEBUG, "inline======", "00bufferEncrypt, fd = %d, hasEffectSize = %d, count = %d", fd, hasEffectSize, count);
            }

            break;
        }
    }

    log_print(ANDROID_LOG_DEBUG, "inline======", "aaaabufferEncrypt, fd = %d, hasEffectSize = %d, count = %d, curWOffset = %d", fd, hasEffectSize, count,fdCurWOffset);
    while (hasEffectSize < count) {
        //log_print(ANDROID_LOG_DEBUG, "inline======", "\nbufferEncrypt(while (hasEffectSize < count)), fd = %d", fd);
        if (hasEffectSize + BLOCK_SIZE < count) {
            cipherBufferSize = fileSm4Encrypt(bufferTmp + hasEffectSize, BLOCK_SIZE, cipherBuffer, pcSecretKey, pcSecretIvec);
            hasEffectSize += cipherBufferSize;

            old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
            fdCurWOffset += cipherBufferSize;
            log_print(ANDROID_LOG_DEBUG, "inline======", "bbbbbbbufferEncrypt, fd = %d, hasEffectSize = %d, count = %d, curWOffset = %d", fd, hasEffectSize, count,fdCurWOffset);
        } else if (hasEffectSize + BLOCK_SIZE == count){
            log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(hasEffectSize + BLOCK_SIZE == count), fd = %d, hasEffectSize = %d\n", fd, hasEffectSize);
            cipherBufferSize = fileSm4Encrypt(bufferTmp + hasEffectSize, BLOCK_SIZE, cipherBuffer, pcSecretKey, pcSecretIvec);
            hasEffectSize += cipherBufferSize;

            old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
            fdCurWOffset += cipherBufferSize;
            log_print(ANDROID_LOG_DEBUG, "inline======", "cccccbufferEncrypt, fd = %d, hasEffectSize = %d, count = %d, curWOffset = %d", fd, hasEffectSize, count,fdCurWOffset);
            break;
        } else {
            log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt(hasEffectSize + BLOCK_SIZE > count), fd = %d, hasEffectSize = %d", fd, hasEffectSize);
            cipherBufferSize = fileXorEncrypt(bufferTmp + hasEffectSize, count - hasEffectSize, cipherBuffer);
            hasEffectSize += count - hasEffectSize;

            old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
            fdCurWOffset += cipherBufferSize;
            log_print(ANDROID_LOG_DEBUG, "inline======", "ddddddbufferEncrypt, fd = %d, hasEffectSize = %d, count = %d, curWOffset = %d", fd, hasEffectSize, count,fdCurWOffset);
            break;
        }
    }

    if (bufferTmp != NULL) {
        free(bufferTmp);
    }

    old_close(fd_r);

    
    
    // recover offset
    old_lseek(fd, fdCurOffset + hasEffectSize, SEEK_SET);

    log_print(ANDROID_LOG_DEBUG, "inline======", "bufferEncrypt end %d\n\n", fd);

    return hasEffectSize;
}

static int bufferDecrypt(int fd, void *buf, size_t count, off_t offset, FILE_FD_INFO_S *pstFileFdInfo)
{
    char *outBuf = (char *)buf;
    size_t relativeOffset;
    size_t decryptPoint;
    unsigned char plaintBuffer[BLOCK_SIZE];
    unsigned char cipherBuffer[BLOCK_SIZE];
    int plaintBufferSize;
    int readBufferLen;
    size_t fdCurOffset;

    if (offset != -1) {
        fdCurOffset = old_lseek(fd, offset, SEEK_SET);
    } else {
        fdCurOffset = old_lseek(fd, 0, SEEK_CUR);
    }

    // set offset decryptPoint
    relativeOffset = findDecryptPoint(fdCurOffset, &decryptPoint);
    old_lseek(fd, decryptPoint, SEEK_SET);

    size_t hasEffectSize = 0;
    while (hasEffectSize < count) {
        readBufferLen = old_read(fd, cipherBuffer, BLOCK_SIZE);
        if (readBufferLen == -1) {
            return -1;
        } else if (readBufferLen == 0) {
            break;
        } else if (readBufferLen <= relativeOffset) {
            return 0;
        }

        if (readBufferLen == BLOCK_SIZE){
            plaintBufferSize = fileSm4Decrypt(cipherBuffer, readBufferLen, plaintBuffer,
                                              pstFileFdInfo->stFileHeaderInfo.stSecretKeys.szSecretKey,
                                              pstFileFdInfo->stFileHeaderInfo.stSecretKeys.szSecretIvec);
            if (relativeOffset != 0) {
                if (hasEffectSize + (plaintBufferSize - relativeOffset) < count) {
                    memcpy(outBuf + hasEffectSize, plaintBuffer + relativeOffset, plaintBufferSize - relativeOffset);
                    hasEffectSize += plaintBufferSize - relativeOffset;
                } else if (hasEffectSize + (plaintBufferSize - relativeOffset) == count) {
                    memcpy(outBuf + hasEffectSize, plaintBuffer + relativeOffset, plaintBufferSize - relativeOffset);
                    hasEffectSize += plaintBufferSize - relativeOffset;
                    break;
                } else {
                    memcpy(outBuf + hasEffectSize, plaintBuffer + relativeOffset, count - hasEffectSize);
                    hasEffectSize += count - hasEffectSize;
                    break;
                }
                relativeOffset = 0;
            } else {
                if (hasEffectSize + plaintBufferSize < count) {
                    memcpy(outBuf + hasEffectSize, plaintBuffer, plaintBufferSize);
                    hasEffectSize += plaintBufferSize;
                } else if (hasEffectSize + plaintBufferSize == count) {
                    memcpy(outBuf + hasEffectSize, plaintBuffer, plaintBufferSize);
                    hasEffectSize += plaintBufferSize;
                    break;
                } else {
                    memcpy(outBuf + hasEffectSize, plaintBuffer, count - hasEffectSize);
                    hasEffectSize += count - hasEffectSize;
                    break;
                }
            }
        } else if (readBufferLen < BLOCK_SIZE) {

            log_print(ANDROID_LOG_DEBUG, "====before==", "read: buffer = %x, %x, len = %d", ((char *) cipherBuffer)[0], ((char *) cipherBuffer)[1], readBufferLen);

            plaintBufferSize = fileXorDecrypt(cipherBuffer, readBufferLen, plaintBuffer);

            log_print(ANDROID_LOG_DEBUG, "====after==", "read: buffer = %x, %x", ((char *) plaintBuffer)[0], ((char *) plaintBuffer)[1]);

            if (relativeOffset != 0) {
                if (hasEffectSize + (plaintBufferSize - relativeOffset) <= count) {
                    memcpy(outBuf + hasEffectSize, plaintBuffer + relativeOffset, plaintBufferSize - relativeOffset);
                    hasEffectSize += plaintBufferSize - relativeOffset;
                } else {
                    memcpy(outBuf + hasEffectSize, plaintBuffer + relativeOffset, count - hasEffectSize);
                    hasEffectSize += count - hasEffectSize;
                }

                relativeOffset = 0;
            } else {
                if (hasEffectSize + plaintBufferSize <= count) {
                    memcpy(outBuf + hasEffectSize, plaintBuffer, plaintBufferSize);
                    hasEffectSize += plaintBufferSize;
                } else {
                    memcpy(outBuf + hasEffectSize, plaintBuffer, count - hasEffectSize);
                    hasEffectSize += count - hasEffectSize;
                }
            }

            break;
        }
    }

    // recover offset
    old_lseek(fd, fdCurOffset + hasEffectSize, SEEK_SET);

    return hasEffectSize;
}

static ssize_t __nativehook_impl_android_read(int fd, void *buf, size_t count) {
    //log_print(ANDROID_LOG_DEBUG, "inlinehook", "pread: fd = %d, count = %d, offset = %d\n", count);

    ssize_t r_len;
    size_t curOffset = old_lseek(fd, 0, SEEK_CUR);

    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    if (NULL != pstFileFdInfo) {
        log_print(ANDROID_LOG_DEBUG, "\ninlinehook=====", "init , read: fd = %d, count = %d, curOffset = %d", fd, count, curOffset);


//return old_read(fd, buf, count);

        r_len = bufferDecrypt(fd, buf, count, -1, pstFileFdInfo);

        if (r_len > 0) {
            log_print(ANDROID_LOG_DEBUG, "after==inlinehook=====", "read: buffer = %x, %x", ((char *) buf)[0], ((char *) buf)[1]);
        }
    } else {
        r_len = old_read(fd, buf, count);
    }

    return r_len;
}

static ssize_t __nativehook_impl_android_pread(int fd, void *buf, size_t count, off_t offset) {
    //log_print(ANDROID_LOG_DEBUG, "inlinehook", "pread: fd = %d, count = %d, offset = %d\n", fd, count, offset);

    ssize_t r_len;

    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    if (NULL != pstFileFdInfo) {
        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "pread: fd = %d, count = %d, offset = %ld\n", fd, count, offset);

        r_len = bufferDecrypt(fd, buf, count, offset + FS_HEADER_LEN, pstFileFdInfo);
        if (r_len > 0) {
            log_print(ANDROID_LOG_DEBUG, "after==inlinehook=====", "pread: buffer = %x, %x\n",
                                ((char *) buf)[0], ((char *) buf)[1]);
        } else if (r_len > count) {
            size_t curOffset = (int) old_lseek(fd, 0, SEEK_CUR);
            log_print(ANDROID_LOG_DEBUG, "===finish==inlinehook=====", "Failed !!!! : curOffset = %ld, returnLen = %ld\n\n", curOffset, r_len);
            return -1;
        }
    } else {
        r_len = old_pread(fd, buf, count, offset);
    }

    return r_len;
}

static int appendOfOffset(int fd, size_t fileSize, size_t curOffset, FILE_FD_INFO_S *pstFileFdInfo) {
    size_t wLen;
    size_t appendSize;

    wLen = curOffset - fileSize;

    char *buf = (char *)malloc(wLen);
    if (buf == NULL) {
        return -1;
    }
    memset(buf, 0, wLen);

    log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "appendOfOffset, fd = %d, count = %d, curOffset = %d", fd, wLen, curOffset);
    appendSize = bufferEncrypt(fd, buf, wLen, -1, pstFileFdInfo);
    log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "appendOfOffset end, fd = %d, count = %d, curOffset = %d", fd, wLen, curOffset);

    return appendSize;
}

static ssize_t __nativehook_impl_android_write(int fd, const void *buf, size_t count) {
    ssize_t r_len = 0;

    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    if (NULL != pstFileFdInfo) {
        struct stat statbuf;
        old_fstat(fd, &statbuf);
        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "write: filepath = %s, fd = %d, count = %d, curFileSize = %lld, curOffset = %d",
                  pstFileFdInfo->szFilePath, fd, count, statbuf.st_size, old_lseek(fd, 0, SEEK_CUR));

//r_len = old_write(fd, buf, count);
//log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "write: filepath = %s, fd = %d, count = %d, curFileSize = %lld, curOffset = %d, rLen = %d",
//  pstFileFdInfo->szFilePath, fd, count, statbuf.st_size, old_lseek(fd, 0, SEEK_CUR), r_len);
//return r_len;


        if (((pstFileFdInfo->flag & O_TRUNC) != 0) && (old_lseek(fd, 0, SEEK_CUR) == FS_HEADER_LEN)) {
            addFileHeader(fd, &pstFileFdInfo->stFileHeaderInfo);
        }

        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "write, bufferEncrypt: filepath = %s, fd = %d, count = %d, curFileSize = %lld, curOffset = %d",
                  pstFileFdInfo->szFilePath, fd, count, statbuf.st_size, old_lseek(fd, 0, SEEK_CUR));
        r_len = bufferEncrypt(fd, buf, count, -1, pstFileFdInfo);
        log_print(ANDROID_LOG_DEBUG, "inlinehook=====\n", "finish write: filepath = %s, fd = %d, count = %d, curFileSize = %lld, curOffset = %d, rLen = %d",
                  pstFileFdInfo->szFilePath, fd, count, statbuf.st_size, old_lseek(fd, 0, SEEK_CUR), r_len);

        return r_len;
    }

    return old_write(fd, buf, count);
}

static ssize_t __nativehook_impl_android_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    ssize_t r_len;

    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);

    if (NULL != pstFileFdInfo) {
        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "pwrite: filepath = %s, fd = %d, count = %d, offset = %d",
                            pstFileFdInfo->szFilePath, fd, count, offset);

//return old_pwrite(fd, buf, count, offset);

        if ((pstFileFdInfo->flag & O_TRUNC != 0) && (old_lseek(fd, 0, SEEK_CUR) == FS_HEADER_LEN)) {
            addFileHeader(fd, &pstFileFdInfo->stFileHeaderInfo);
        }


        //稀疏文件处理，append content ： 0
        struct stat statbuf;
        old_fstat(fd, &statbuf);

        size_t curOffset = old_lseek(fd, 0, SEEK_CUR);
        if (statbuf.st_size < curOffset) {
            appendOfOffset(fd, statbuf.st_size, curOffset, pstFileFdInfo);
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "failed, pwrite: filepath = %s, fd = %d, count = %d, offset = %d",
                      pstFileFdInfo->szFilePath, fd, count, offset);
        }

        r_len = bufferEncrypt(fd, buf, count, offset + FS_HEADER_LEN, pstFileFdInfo);

        return r_len;
    }

    return old_pwrite(fd, buf, count, offset);
}

static off_t __nativehook_impl_android_lseek(int fd, off_t offset, int whence) {
    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    off_t var_off_t = 0;

    if (NULL != pstFileFdInfo) {
        struct stat statbuf;
        memset(&statbuf, 0, sizeof(struct stat));
        old_fstat(fd, &statbuf);

        size_t curOffset = old_lseek(fd, 0, SEEK_CUR);

        log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====", "lseek: fd = %d, offset = %d, whence = %d, curOffset = %ld, curFileSize = %lld",
                  fd, offset, whence, curOffset, statbuf.st_size);

        // Show stack functions
//        if (2905 == offset) {
//            JNIEnv *env;
//
//            if (inline_android_vm->GetEnv((void **) &env, JNI_VERSION_1_4) == JNI_OK) {
//                env->FindClass(NULL);
//            }
//
//            //testBreak(0, 0);
//        }


        if (whence == SEEK_CUR) {
            var_off_t = old_lseek(fd, 0, SEEK_CUR);
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====00", "lseek(SEEK_CUR): fd = %d, offset = %ld", fd, offset);
        } else if (whence == SEEK_END) {
            var_off_t = old_lseek(fd, offset, whence);
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====00", "lseek(SEEK_END): fd = %d, offset = %ld", fd, offset);
        } else if (whence == SEEK_SET) {
            var_off_t = old_lseek(fd, offset + FS_HEADER_LEN, whence);
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "lseek(SEEK_SET): fd = %d, offset = %ld", fd, offset + FS_HEADER_LEN);
//var_off_t = old_lseek(fd, offset, whence);
//log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "lseek(SEEK_SET): fd = %d, offset = %ld", fd, offset);
        }

        return var_off_t - FS_HEADER_LEN;
//return var_off_t;
    }

    return old_lseek(fd, offset, whence);
}

static off64_t __nativehook_impl_android_lseek64(int fd, off64_t offset, int whence) {
    int var_off64_t = 0;
    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);

    if (NULL != pstFileFdInfo) {

        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "init , lseek64 000: fd = %d, offset = %d, whence = %d", fd, offset, whence);
//return old_lseek64(fd, offset, whence);

        if (whence == SEEK_CUR) {
            var_off64_t = old_lseek64(fd, offset, whence);
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "lseek64(SEEK_CUR): fd = %d, offset = %lld", fd, offset);

        } else if (whence == SEEK_END) {
            var_off64_t = old_lseek64(fd, offset, whence);
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "lseek64(SEEK_END): fd = %d, offset = %lld", fd, offset);

        } else if (whence == SEEK_SET) {
            var_off64_t = old_lseek64(fd, offset + FS_HEADER_LEN, whence);
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "lseek64(SEEK_SET): fd = %d, offset = %lld", fd, offset + FS_HEADER_LEN);
        }

        return var_off64_t - FS_HEADER_LEN;
    }

    return old_lseek64(fd, offset, whence);
}

static int __nativehook_impl_android_fstat(int fd, struct stat *statbuf) {
    int result = 0;

    result = old_fstat(fd, statbuf);

    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    if (NULL != pstFileFdInfo) {
        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "before, fstat: filepath = %s, fd = %d, fileSize = %lld",
                            pstFileFdInfo->szFilePath, pstFileFdInfo->fd, statbuf->st_size);

        if (statbuf->st_size != 0) {
            statbuf->st_size = statbuf->st_size - FS_HEADER_LEN;
//statbuf->st_size = statbuf->st_size;
        }

        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "after, fstat: fd = %d, fileSize = %lld", fd, statbuf->st_size);
    }

    return result;
}

static void *__nativehook_impl_android_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset) {
    struct stat statbuf;

    old_fstat(fd, &statbuf);

    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    if (NULL != pstFileFdInfo) {
        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "mmap: filepath = %s, fd = %d, fileSize = %lld, offset = %d",
                  pstFileFdInfo->szFilePath, pstFileFdInfo->fd, statbuf.st_size, offset);

        return old_mmap(addr, length, prot, flags, fd, offset);
    }

    return old_mmap(addr, length, prot, flags, fd, offset);
}

static void *__nativehook_impl_android_mmap64(void* __addr, size_t __size, int __prot, int __flags, int __fd, off64_t __offset) {
    struct stat statbuf;

    old_fstat(__fd, &statbuf);

    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(__fd);
    if (NULL != pstFileFdInfo) {
        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "mmap64: filepath = %s, fd = %d, fileSize = %lld, offset = %d",
                  pstFileFdInfo->szFilePath, pstFileFdInfo->fd, statbuf.st_size, __offset);

        return old_mmap64(__addr, __size, __prot, __flags, __fd, __offset);
    }

    return old_mmap64(__addr, __size, __prot, __flags, __fd, __offset);
}

static int __nativehook_impl_android_fprintf(FILE *stream, const char *format, ...) {

    log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "fprintf : fd = %d", fileno(stream));

    va_list args;         //定义一个va_list类型的变量，用来储存单个参数
    va_start(args, format);  //使args指向可变参数的第一个参数

    int ret = old_fprintf(stream, format, args);

    va_end(args);         //结束可变参数的获取

    return ret;
}

static int __nativehook_impl_android_dprintf(int fd, const char *format, ...) {
    log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "fprintf : fd = %d", fd);

    va_list args;         //定义一个va_list类型的变量，用来储存单个参数
    va_start(args, format);  //使args指向可变参数的第一个参数

    int ret = old_dprintf(fd, format, args);

    va_end(args);         //结束可变参数的获取

    return ret;
}

static int ftruncateEncrypt(int fd, off_t length, FILE_FD_INFO_S *pstFileFdInfo) {
    struct stat statbuf;
    size_t relativeLen = 0;
    int ret = 0;

    unsigned char plaintBuffer[BLOCK_SIZE];
    unsigned char cipherBuffer[BLOCK_SIZE];
    size_t plaintBufferSize;
    size_t cipherBufferSize;

    size_t curOffset = old_lseek(fd, 0, SEEK_CUR);

    old_fstat(fd, &statbuf);
    if (statbuf.st_size == length + FS_HEADER_LEN) {
        return ret;
    } else if (statbuf.st_size < length + FS_HEADER_LEN) {
        log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "ftruncateEncrypt bufferEncrypt: fd = %d, length = %ld", fd, length + FS_HEADER_LEN);
        relativeLen = length + FS_HEADER_LEN - statbuf.st_size;
        char *appendBuf = (char *)malloc(relativeLen);
        if (appendBuf == NULL) {
            return -1;
        }
        memset(appendBuf, 0, relativeLen);
        bufferEncrypt(fd, appendBuf, relativeLen, statbuf.st_size, pstFileFdInfo);
    } else {
        relativeLen = length + FS_HEADER_LEN;

        // set offset decryptPoint
        size_t decryptPoint;
        size_t relativeOffset = findDecryptPoint(relativeLen, &decryptPoint);
        if (relativeOffset == 0) {
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "ftruncateEncrypt old_ftruncate: fd = %d, length = %ld", fd, length + FS_HEADER_LEN);
            ret = old_ftruncate(fd, length + FS_HEADER_LEN);
        } else {
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "ftruncateEncrypt relativeOffset: fd = %d, length = %ld", fd, length + FS_HEADER_LEN);
            size_t fdCurWOffset = old_lseek(fd, decryptPoint, SEEK_SET);
            size_t readBufferLen = old_read(fd, cipherBuffer, BLOCK_SIZE);
            if (readBufferLen == BLOCK_SIZE) {
                plaintBufferSize = fileSm4Decrypt(cipherBuffer, BLOCK_SIZE, plaintBuffer,
                                                  pstFileFdInfo->stFileHeaderInfo.stSecretKeys.szSecretKey,
                                                  pstFileFdInfo->stFileHeaderInfo.stSecretKeys.szSecretIvec);
                cipherBufferSize = fileXorEncrypt(plaintBuffer, relativeOffset, cipherBuffer);

                old_pwrite(fd, cipherBuffer, cipherBufferSize, fdCurWOffset);
            }

            ret = old_ftruncate(fd, length + FS_HEADER_LEN);

            struct stat statbuf;
            old_fstat(fd, &statbuf);
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "finish ftruncateEncrypt , curFileSize = %lldd", statbuf.st_size);
        }
    }

    //backup curOffset
    old_lseek(fd, curOffset, SEEK_SET);

    return ret;
}

//int ftruncate(int fd, off_t length)
static int __nativehook_impl_android_ftruncate(int fd, off_t length) {
    log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "ftruncate : fd = %d, length = %ld", fd, length);

//    if (131072 == length) {
//        JNIEnv *env;
//
//        if (inline_android_vm->GetEnv((void **) &env, JNI_VERSION_1_4) == JNI_OK) {
//            env->FindClass(NULL);
//        }
//    }

    int ret = -1;
    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    if (NULL != pstFileFdInfo) {
        //log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "match ftruncate : fd = %d, length = %ld", fd, length + FS_HEADER_LEN);

//log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "match ftruncate : fd = %d, length = %ld", fd, length);
//return old_ftruncate(fd, length);

        ret = ftruncateEncrypt(fd, length, pstFileFdInfo);
        if (ret == -1) {
            log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "ftruncateEncrypt failed : fd = %d, length = %ld", fd, length + FS_HEADER_LEN);
        }

        return ret;
    }


    return old_ftruncate(fd, length);;
}

static int __nativehook_impl_android_rename(const char* __old_path, const char* __new_path) {

    log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "old_rename       __old_path : %s, __new_path = %s", __old_path, __new_path);

    return old_rename(__old_path, __new_path);
}

void startInlineHook(void) {
    void *pOpenat = (void *) __openat;

    //lseek
    if (registerInlineHook((uint32_t) lseek, (uint32_t) __nativehook_impl_android_lseek,
                           (uint32_t **) &old_lseek) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==lseek== start %p",
                            lseek);
        inlineHook((uint32_t) lseek);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==lseek== end");
    }

    //lseek64
    if (registerInlineHook((uint32_t) lseek64, (uint32_t) __nativehook_impl_android_lseek64,
                           (uint32_t **) &old_lseek64) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook",
                            "inline hook ==lseek64== start %p",
                            lseek64);
        inlineHook((uint32_t) lseek64);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==lseek64== end");
    }


    //close
    if (registerInlineHook((uint32_t) close, (uint32_t) __nativehook_impl_android_close,
                           (uint32_t **) &old_close) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==close== start %p",
                            close);
        inlineHook((uint32_t) close);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==close== end");
    }

    //pread
    if (registerInlineHook((uint32_t) pread, (uint32_t) __nativehook_impl_android_pread,
                           (uint32_t **) &old_pread) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==pread== start %p",
                            pread);
        inlineHook((uint32_t) pread);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==pread== end");
    }

    //pwrite
    if (registerInlineHook((uint32_t) pwrite, (uint32_t) __nativehook_impl_android_pwrite,
                           (uint32_t **) &old_pwrite) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook",
                            "inline hook ==pwrite== start %p",
                            pwrite);
        inlineHook((uint32_t) pwrite);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==pwrite== end");
    }

    //read
    if (registerInlineHook((uint32_t) read, (uint32_t) __nativehook_impl_android_read,
                           (uint32_t **) &old_read) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==read== start %p",
                            read);
        inlineHook((uint32_t) read);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==read== end");
    }

    //write
    if (registerInlineHook((uint32_t) write, (uint32_t) __nativehook_impl_android_write,
                           (uint32_t **) &old_write) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==write== start %p", write);
        inlineHook((uint32_t) write);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==write== end");
    }


    //__openat
    if (registerInlineHook((uint32_t) pOpenat, (uint32_t) __nativehook_impl_android_openat,
                           (uint32_t **) &old_openat) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==__openat== start %p", pOpenat);
        inlineHook((uint32_t) pOpenat);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==__openat== end");
    }


    //fstat
    if (registerInlineHook((uint32_t) fstat, (uint32_t) __nativehook_impl_android_fstat,
                           (uint32_t **) &old_fstat) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==fstat== start %p",
                            fstat);
        inlineHook((uint32_t) fstat);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==fstat== end");
    }

//    //mmap
//    if (registerInlineHook((uint32_t) mmap, (uint32_t) __nativehook_impl_android_mmap,
//                           (uint32_t **) &old_mmap) != ELE7EN_OK) { ;
//    } else {
//        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==mmap== start %p", mmap);
//        inlineHook((uint32_t) mmap);
//        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==mmap== end");
//    }
//
//    //mmap64
//    if (registerInlineHook((uint32_t) mmap64, (uint32_t) __nativehook_impl_android_mmap64,
//                           (uint32_t **) &old_mmap64) != ELE7EN_OK) { ;
//    } else {
//        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==mmap64== start %p", mmap64);
//        inlineHook((uint32_t) mmap64);
//        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==mmap64== end");
//    }

    //rename
    if (registerInlineHook((uint32_t) rename, (uint32_t) __nativehook_impl_android_rename,
                           (uint32_t **) &old_rename) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==rename== start %p", rename);
        inlineHook((uint32_t) rename);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==rename== end");
    }

//    //fprintf
//    if (registerInlineHook((uint32_t) fprintf, (uint32_t) __nativehook_impl_android_fprintf,
//                           (uint32_t **) &old_fprintf) != ELE7EN_OK) { ;
//    } else {
//        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==fprintf== start %p", fprintf);
//        inlineHook((uint32_t) fprintf);
//        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==fprintf== end");
//    }
//
//    //dprintf
//    if (registerInlineHook((uint32_t) dprintf, (uint32_t) __nativehook_impl_android_dprintf,
//                           (uint32_t **) &old_dprintf) != ELE7EN_OK) { ;
//    } else {
//        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==dprintf== start %p", dprintf);
//        inlineHook((uint32_t) dprintf);
//        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==dprintf== end");
//    }

    //int ftruncate(int fd, off_t length);
    if (registerInlineHook((uint32_t) ftruncate, (uint32_t) __nativehook_impl_android_ftruncate,
                           (uint32_t **) &old_ftruncate) != ELE7EN_OK) { ;
    } else {
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==ftruncate== start %p", ftruncate);
        inlineHook((uint32_t) ftruncate);
        log_print(ANDROID_LOG_INFO, "inlinehook", "inline hook ==ftruncate== end");
    }
}
