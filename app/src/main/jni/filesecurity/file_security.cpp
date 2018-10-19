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

#include "../hook/inlinehook/inlineHook.h"

#include "file_security.h"
#include "file_encrypt.h"

#define _LARGEFILE64_SOURCE


extern "C" int __openat(int, const char*, int, int);

extern const char* inline_originApk;
extern const char* inline_baseApk;
extern int inline_baseApkL;

std::map<int, FILE_FD_INFO_S *> g_FileFdMap;

#define SUNINFO 7
#define BLOCK_SIZE 512

int (*old_openat)(int, const char *, int, int) = NULL;
int (*old_stat)(const char *pathname, struct stat *statbuf) = NULL;
int (*old_fstat)(int fd, struct stat *statbuf) = NULL;

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

    __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====", "testBreak addr=%p, va_whence = %d, tmp_whence = %d\n\n", testBreak, va_whence, tmp_whence);


    return;
}

static int fileEncrypt(int dirFd, const char *srcPathName)
{
    int fd_s = old_openat(dirFd, srcPathName, O_RDWR, 0640);
    FILE *hSource = fdopen(fd_s, "a+");
    if (hSource == NULL) {
        return -1;
    }
    if (srcPathName == NULL) {
        __android_log_print(ANDROID_LOG_DEBUG, "inline======", "srcPathName is NULL");
        return -1;
    }

    int len = strlen(srcPathName);
    char *pathNameTmp = (char *) malloc(len + sizeof("_tmp"));
    if (pathNameTmp == NULL) {
        fclose(hSource);
        return -1;
    }
    pathNameTmp[0] = '\0';
    strcat(pathNameTmp, srcPathName);
    strcat(pathNameTmp, "_tmp");

    FILE *hDestination = fdopen(old_openat(dirFd, pathNameTmp, O_CREAT | O_RDWR, 0640), "a+");
    if (hDestination == NULL) {
        fclose(hSource);
        free(pathNameTmp);
        return -1;
    }

    struct stat statbuf;
    size_t fileSize;
    size_t blockCount;
    size_t blockExtraLen;
    old_fstat(fd_s, &statbuf);
    fileSize = statbuf.st_size;
    blockCount = fileSize / BLOCK_SIZE;
    blockExtraLen = fileSize % BLOCK_SIZE;

    //Write encrypt head
    fwrite("suninfo", SUNINFO, 1, hDestination);

    //Write encrypt body
    unsigned char plaintBuffer[BLOCK_SIZE]={0};
    unsigned char cipherBuffer[BLOCK_SIZE]={0};
    int readBufferLen;
    int ciphierBufferSize;
    for (int i = 0; i < blockCount; i++) {
        readBufferLen = fread(plaintBuffer, 1, BLOCK_SIZE, hSource);
        if (readBufferLen != BLOCK_SIZE) {
            free(pathNameTmp);
            return -1;
        }

        ciphierBufferSize = fileSm4Encrypt(plaintBuffer, readBufferLen, cipherBuffer);
        fwrite(cipherBuffer, 1, ciphierBufferSize, hDestination);
    }

    if (blockExtraLen != 0) {
        readBufferLen = fread(plaintBuffer, 1, blockExtraLen, hSource);
        if (readBufferLen != readBufferLen) {
            free(pathNameTmp);
            return -1;
        }
        ciphierBufferSize = fileXorEncrypt(plaintBuffer, readBufferLen, cipherBuffer);
        fwrite(cipherBuffer, 1, ciphierBufferSize, hDestination);
    }

    fclose(hSource);
    fclose(hDestination);

    unlink(srcPathName);

    // Mv file
    rename(pathNameTmp, srcPathName);

    free(pathNameTmp);

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
        __android_log_print(ANDROID_LOG_DEBUG, "inline======", "regMatchFilePath matched");
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
    char pattern[] = "(txt_test.txt|pdf_test.pdf|docx_test.docx|pptx_test.pptx|xlsx_test.xlsx)";

    /*正则表达式：编译-匹配-释放*/
    status = regcomp(&reg, pattern, REG_EXTENDED|REG_NEWLINE);  //扩展正则表达式和识别换行符
    if (status != 0){    //成功返回0
        return false;
    }

    status = regexec(&reg, pathName, 1, pm, 0);
    if (status == 0){
        __android_log_print(ANDROID_LOG_DEBUG, "inline======", "regMatchFileType matched\n");
        result = true;
    }

    regfree(&reg);

    return result;
}

static int __nativehook_impl_android_openat(int dirFd, const char *pathName, int flag, int mode) {

    // 破解防打包
//    int lo = strlen(pathName);
//    if (lo == inline_baseApkL && strncmp(inline_baseApk, pathName, lo) == 0) {
//        //__android_log_print(ANDROID_LOG_DEBUG, "xhook", "open : %s replace %s\n", inline_originApk, pathname);
//        return old_openat(dirFd, inline_originApk, flag, mode);
//    }

    // File Security
    if (regMatchFilePath(pathName) == false && regMatchFileType(pathName) == false) {

        int fd = old_openat(dirFd, pathName, flag, mode);
        //__android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "regMatch failed, openat:%s, fd = %d\n", pathName, fd);
        return fd;
    }

    if (flag & O_APPEND) {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_APPEND");
    }

    if (flag & O_TRUNC) {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_TRUNC");
    }

    if (flag & O_NOATIME) {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_NOATIME");
    }

    if (access(pathName, F_OK) == 0) {

        int fd_o = old_openat(dirFd, pathName, O_RDWR, 0640);

        FILE *hSource = fdopen(fd_o, "a+");
        if (hSource == NULL) {
            return -1;
        }

        char suninfoBuffer[SUNINFO + 1] = {0};
        fread(suninfoBuffer, SUNINFO, 1, hSource);

        fclose(hSource);

        if (strcmp(suninfoBuffer, "suninfo") == 0) {
            int fdTmp = old_openat(dirFd, pathName, flag, mode);
            if (fdTmp != -1) {
                // Add file-fd-list for matching.
                FILE_FD_INFO_S *pstFileFdInfo = (FILE_FD_INFO_S *) malloc(sizeof(FILE_FD_INFO_S));
                if (pstFileFdInfo == NULL) {
                    return -1;
                }

                pstFileFdInfo->fd = fdTmp;
                pstFileFdInfo->flag = flag;
                g_FileFdMap.insert(std::pair<int, FILE_FD_INFO_S *>(fdTmp, pstFileFdInfo));

                old_lseek(fdTmp, SUNINFO, SEEK_SET);
                __android_log_print(ANDROID_LOG_DEBUG, "inlinehook==hasSuninfo=====",
                                    "init , open: fdTmp = %d, curOffset = %d\n", fdTmp,
                                    (int) old_lseek(fdTmp, 0, SEEK_CUR));
            }

            return fdTmp;
        }

        //File encrypt
        if (fileEncrypt(dirFd, pathName) != 0) {
            __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====", "file : %s, encrypt failed\n\n", pathName);
        }
    }


    int fd = old_openat(dirFd, pathName, flag, mode);

    __android_log_print(ANDROID_LOG_DEBUG, "inlinehook====", "openat:%s, fd = %d\n", pathName, fd);

    //Save file info
    if (fd != -1) {
        // Add file-fd-list for matching.
        FILE_FD_INFO_S *pstFileFdInfo = (FILE_FD_INFO_S *) malloc(sizeof(FILE_FD_INFO_S));
        if (pstFileFdInfo == NULL) {
            return -1;
        }

        pstFileFdInfo->fd = fd;
        pstFileFdInfo->flag = flag;
        g_FileFdMap.insert(std::pair<int, FILE_FD_INFO_S *>(fd, pstFileFdInfo));

        old_lseek(fd, SUNINFO, SEEK_SET);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "end , open: fd = %d, curOffset = %d\n", fd, (int) old_lseek(fd, 0, SEEK_CUR));
    }

    return fd;
}

static int __nativehook_impl_android_close(int fd) {
    std::map<int, FILE_FD_INFO_S *>::iterator it;
    int result = 0;

    it = g_FileFdMap.find(fd);
    if (it != g_FileFdMap.end()) {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "close: fd = %d", fd);
        result = old_close(fd);
//        result = syscall(SYS_close, fd);
        if (result == 0) {
            g_FileFdMap.erase(it);
            FILE_FD_INFO_S *fileFdInfoTmp = it->second;
            free(fileFdInfoTmp);

            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "finish close: fd = %d", fd);
        }
    } else {
//        result = syscall(SYS_close, fd);
        result = old_close(fd);
    }

    return result;
}

static size_t findEncryptPoint(off_t curOffset, size_t *encryptPoint) {
    int i;
    size_t relativeOffset;
    size_t encryptOffset = curOffset - SUNINFO;

    for (i = 0;;i = i + BLOCK_SIZE) {
        if (i + BLOCK_SIZE > encryptOffset) {
            break;
        }
    }

    *encryptPoint = i + SUNINFO;
    relativeOffset = encryptOffset - i;

    return relativeOffset;
}

static size_t findDecryptPoint(off_t curOffset, size_t *DecryptPoint) {
    int i;
    size_t relativeOffset;
    size_t descryptOffset = curOffset - SUNINFO;

    for (i = 0;;i = i + BLOCK_SIZE) {
        if (i + BLOCK_SIZE > descryptOffset) {
            break;
        }
    }

    *DecryptPoint = i + SUNINFO;
    relativeOffset = descryptOffset - i;

    return relativeOffset;
}


size_t calculateDecryptBlockCount(size_t decryptPoint, off_t curOffset, size_t count,
                           size_t fileBlockExtraLenStart, size_t fileBlockExtraLen, size_t *bufferBlockExtraLen) {
    size_t i;
    size_t filePoint = 0;
    size_t blockCount = 0;

    *bufferBlockExtraLen = 0;
    for (i = 0; ; i++) {
        filePoint = decryptPoint + i * BLOCK_SIZE;
        if (filePoint > fileBlockExtraLenStart) {
            blockCount = i - 1;
            *bufferBlockExtraLen = curOffset + count - filePoint;
            break;
        } else if (filePoint == fileBlockExtraLenStart) {
            blockCount = i;
            size_t extraLen = curOffset + count - filePoint;
            if (extraLen < fileBlockExtraLen) {
                *bufferBlockExtraLen = extraLen;
            } else {
                *bufferBlockExtraLen = fileBlockExtraLen;
            }

            break;
        }

        if (filePoint >= curOffset + count) {
            blockCount = i;
            break;
        }
    }

    return blockCount;
}

static int bufferDecrypt(int fd, void *buf, size_t count, off_t offset)
{
    size_t relativeOffset;
    size_t decryptPoint;
    unsigned char plaintBuffer[BLOCK_SIZE];
    unsigned char cipherBuffer[BLOCK_SIZE];
    int plaintBufferSize;
    int bufferBlockCount;


    struct stat statbuf;
    size_t fileSize;
    size_t blockCount;
    size_t bufferBlockExtraLen = 0;
    size_t fileBlockExtraLenStart;
    size_t fileBlockExtraLen = 0;
    int readBufferLen;
    int outBufferLen = 0;
    char *outBuf = (char *)buf;
    size_t fdCurOffset;

    old_fstat(fd, &statbuf);
    fileSize = statbuf.st_size - SUNINFO;
    blockCount = fileSize / BLOCK_SIZE;
    fileBlockExtraLenStart = SUNINFO + (blockCount * BLOCK_SIZE);
    fileBlockExtraLen = fileSize % BLOCK_SIZE;

    if (offset != -1) {
        fdCurOffset = old_lseek(fd, offset, SEEK_SET);
    } else {
        fdCurOffset = old_lseek(fd, 0, SEEK_CUR);
    }

    if (fdCurOffset >= fileBlockExtraLenStart) {
        readBufferLen = old_read(fd, cipherBuffer, count);
        if (readBufferLen < 0) {
            return -1;
        } else if (readBufferLen == 0) {
            return 0;
        }

        plaintBufferSize = fileXorDecrypt(cipherBuffer, readBufferLen, plaintBuffer);
        memcpy(outBuf, plaintBuffer, plaintBufferSize);
        outBufferLen = outBufferLen + plaintBufferSize;
    } else {
        relativeOffset = findDecryptPoint(fdCurOffset, &decryptPoint);
        bufferBlockCount = calculateDecryptBlockCount(decryptPoint, fdCurOffset, count, fileBlockExtraLenStart, fileBlockExtraLen, &bufferBlockExtraLen);

        // set offset decryptPoint
        old_lseek(fd, decryptPoint, SEEK_SET);

        //read encrypt body
        for (int i = 0; i < bufferBlockCount; i++) {
            readBufferLen = old_read(fd, cipherBuffer, BLOCK_SIZE);
            if (readBufferLen != BLOCK_SIZE) {
                return -1;
            }
            plaintBufferSize = fileSm4Decrypt(cipherBuffer, readBufferLen, plaintBuffer);

            if (relativeOffset != 0) {
                memcpy(outBuf + outBufferLen, plaintBuffer + relativeOffset, plaintBufferSize - relativeOffset);
                outBufferLen = outBufferLen + (plaintBufferSize - relativeOffset);
                relativeOffset = 0;
            } else {
                memcpy(outBuf + outBufferLen, plaintBuffer, plaintBufferSize);
                outBufferLen = outBufferLen + plaintBufferSize;
            }
        }

        if (bufferBlockExtraLen != 0) {
            readBufferLen = old_read(fd, cipherBuffer, bufferBlockExtraLen);
            if (readBufferLen != bufferBlockExtraLen) {
                return -1;
            }
            plaintBufferSize = fileXorDecrypt(cipherBuffer, readBufferLen, plaintBuffer);
            memcpy(outBuf + outBufferLen, plaintBuffer, plaintBufferSize);
            outBufferLen = outBufferLen + plaintBufferSize;
        }
    }

    // recover offset
    old_lseek(fd, fdCurOffset + outBufferLen, SEEK_SET);

    return outBufferLen;
}

static ssize_t __nativehook_impl_android_read(int fd, void *buf, size_t count) {
    //__android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "pread: fd = %d, count = %d, offset = %d\n", count);

    ssize_t r_len;

    if (NULL != findFileFdInfo(fd)) {
        __android_log_print(ANDROID_LOG_DEBUG, "\ninlinehook=====",
                            "init , read: fd = %d, count = %d, curOffset = %d\n", fd, count,
                            (int) old_lseek(fd, 0, SEEK_CUR));

        r_len = bufferDecrypt(fd, buf, count, -1);

        if (r_len > 0) {
            __android_log_print(ANDROID_LOG_DEBUG, "after==inlinehook=====", "read: buffer = %x, %x\n",
                                ((char *) buf)[0], ((char *) buf)[1]);

            size_t curOffset = (int) old_lseek(fd, 0, SEEK_CUR);
            __android_log_print(ANDROID_LOG_DEBUG, "finish==inlinehook=====", "read: buffer = %x, %x, %x, %x\n", ((char *) buf)[curOffset-3], ((char *) buf)[curOffset-2],
                                ((char *) buf)[curOffset-1], ((char *) buf)[curOffset]);
        }
    } else {
        r_len = old_read(fd, buf, count);
    }

    return r_len;
}

static ssize_t __nativehook_impl_android_pread(int fd, void *buf, size_t count, off_t offset) {
    //__android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "pread: fd = %d, count = %d, offset = %d\n", fd, count, offset);

    ssize_t r_len;

    if (NULL != findFileFdInfo(fd)) {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "pread: fd = %d, count = %d, offset = %ld\n", fd, count, offset);

        if (offset == 226281) {
            testBreak(0, 0);
        }

        if (offset == 224989) {
            testBreak(0, 0);
        }

        r_len = bufferDecrypt(fd, buf, count, offset + SUNINFO);
        if (r_len > 0) {
            __android_log_print(ANDROID_LOG_DEBUG, "after==inlinehook=====", "pread: buffer = %x, %x\n",
                                ((char *) buf)[0], ((char *) buf)[1]);

            size_t curOffset = (int) old_lseek(fd, 0, SEEK_CUR);
            __android_log_print(ANDROID_LOG_DEBUG, "===finish==inlinehook=====", "curOffset = %ld, returnLen = %ld, pread: buffer = %x, %x\n\n", curOffset, r_len,
                                ((char *) buf)[curOffset-1], ((char *) buf)[curOffset]);
        } else if (r_len > count) {
            size_t curOffset = (int) old_lseek(fd, 0, SEEK_CUR);
            __android_log_print(ANDROID_LOG_DEBUG, "===finish==inlinehook=====", "Failed !!!! : curOffset = %ld, returnLen = %ld, pread: buffer = %x, %x\n\n", curOffset, r_len,
                                ((char *) buf)[curOffset-1], ((char *) buf)[curOffset]);
            return -1;
        }
    } else {
        r_len = old_pread(fd, buf, count, offset);
    }

    return r_len;
}

size_t calculateEncryptBlockCount(size_t count, size_t *bufferBlockExtraLenStart, size_t *bufferBlockExtraLen) {
    size_t blockCount = 0;

    blockCount = count / BLOCK_SIZE;
    *bufferBlockExtraLenStart = blockCount * BLOCK_SIZE;
    *bufferBlockExtraLen = count % BLOCK_SIZE;

    return blockCount;
}

static int bufferEncrypt(int fd, const void *buf,size_t count)
{
    size_t relativeOffset;
    size_t decryptPoint;
    unsigned char plaintBuffer[BLOCK_SIZE];
    unsigned char cipherBuffer[BLOCK_SIZE];
    int plaintBufferSize;
    int cipherBufferSize;
    int bufferBlockCount;


    struct stat statbuf;
    size_t fileSize;
    size_t blockCount;
    size_t fileBlockExtraLenStart;
    size_t fileBlockExtraLen = 0;
    size_t bufferBlockExtraLenStart;
    size_t bufferBlockExtraLen = 0;
    int readBufferLen;
    int outBufferLen = 0;
    unsigned char *outBuf = (unsigned char *)buf;

    old_fstat(fd, &statbuf);
    fileSize = statbuf.st_size - SUNINFO;
    blockCount = fileSize / BLOCK_SIZE;
    fileBlockExtraLenStart = SUNINFO + (blockCount * BLOCK_SIZE);
    fileBlockExtraLen = fileSize % BLOCK_SIZE;

    size_t fdCurOffset = old_lseek(fd, 0,SEEK_CUR);
    if (fdCurOffset == fileBlockExtraLenStart) {
        bufferBlockCount = calculateEncryptBlockCount(count, &bufferBlockExtraLenStart, &bufferBlockExtraLen);

        //write encrypt body
        for (int i = 0; i < bufferBlockCount; i++) {
            cipherBufferSize = fileSm4Encrypt(outBuf + (i * bufferBlockCount), BLOCK_SIZE, cipherBuffer);
            if (cipherBufferSize != BLOCK_SIZE) {
                return -1;
            }

            old_write(fd, cipherBuffer, cipherBufferSize);
            outBufferLen = outBufferLen + cipherBufferSize;
        }

        if (bufferBlockExtraLen != 0) {
            cipherBufferSize = fileXorEncrypt(outBuf + bufferBlockExtraLenStart, bufferBlockExtraLen, cipherBuffer);
            if (cipherBufferSize != bufferBlockExtraLen) {
                return -1;
            }

            old_write(fd, cipherBuffer, cipherBufferSize);
            outBufferLen = outBufferLen + cipherBufferSize;
        }
    }

    return outBufferLen;
}

static ssize_t __nativehook_impl_android_write(int fd, const void *buf, size_t count) {
    ssize_t r_len;
    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);

    if (NULL != pstFileFdInfo) {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "write: fd = %d, count = %d", fd, count);

        if ((pstFileFdInfo->flag & O_TRUNC != 0) && (old_lseek(fd, 0, SEEK_CUR) == SUNINFO)) {
            old_lseek(fd, 0, SEEK_SET);
            old_write(fd, "suninfo", SUNINFO);
        }

        r_len = bufferEncrypt(fd, buf, count);

        return r_len;
    }

    return old_write(fd, buf, count);;
}

static ssize_t __nativehook_impl_android_pwrite(int fd, const void *buf, size_t count, off_t offset) {
    ssize_t r_len;

    if (NULL != findFileFdInfo(fd)) {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====",
                            "pwrite: fd = %d, count = %d, offset = %l\n", fd, count, offset);

        char *bufTmp = (char *) malloc(count);
        if (bufTmp == NULL) {
            return -1;
        }
        memcpy(bufTmp, buf, count);

        char *tmp = (char *) bufTmp;
        for (int i = 0; i < count; i++) {
            tmp[i] = tmp[i] ^ 'f';
        }

        r_len = old_pwrite(fd, bufTmp, count, offset + SUNINFO);

        free(bufTmp);
    } else {
        r_len = old_pwrite(fd, buf, count, offset);
    }

    return r_len;
}

static off_t __nativehook_impl_android_lseek(int fd, off_t offset, int whence) {
    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    off_t var_off_t = 0;

    if (NULL != pstFileFdInfo) {
        __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====",
                            "lseek: fd = %d, offset = %d, whence = %d\n", fd, offset, whence);

        // Show stack functions
//        if (10717 == offset) {
////            JNIEnv *env;
////
////            if (inline_android_vm->GetEnv((void **) &env, JNI_VERSION_1_4) == JNI_OK) {
////                env->FindClass(NULL);
////            }
//
//            testBreak(0, 0);
//        }


        if (whence == SEEK_CUR) {
            var_off_t = old_lseek(fd, 0, SEEK_CUR);
            __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====00",
                                "lseek(SEEK_CUR): fd = %d, offset = %ld\n\n", fd, offset);
        } else if (whence == SEEK_END) {
            var_off_t = old_lseek(fd, offset, whence);
            __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====00",
                                "lseek(SEEK_END): fd = %d, offset = %ld\n\n", fd, offset);
        } else if (whence == SEEK_SET) {
            var_off_t = old_lseek(fd, offset + SUNINFO, whence);
            __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====",
                                "lseek(SEEK_SET): fd = %d, offset = %ld\n\n", fd, offset + SUNINFO);
        }

        return var_off_t - SUNINFO;
    }

    return old_lseek(fd, offset, whence);
}

static off64_t __nativehook_impl_android_lseek64(int fd, off64_t offset, int whence) {
    int var_off64_t = 0;
    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);

    if (NULL != pstFileFdInfo) {
        __android_log_print(ANDROID_LOG_DEBUG, "\ninlinehook=====",
                            "init , lseek64 000: fd = %d, offset = %d, whence = %d\n", fd, offset,
                            whence);


        if (whence == SEEK_CUR) {
            var_off64_t = old_lseek64(fd, offset, whence);
            __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====",
                                "lseek64(SEEK_CUR): fd = %d, offset = %lld\n\n", fd, offset);
        } else if (whence == SEEK_END) {
            var_off64_t = old_lseek64(fd, offset, whence);
            __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====",
                                "lseek64(SEEK_END): fd = %d, offset = %lld\n\n", fd, offset);
        } else if (whence == SEEK_SET) {
            var_off64_t = old_lseek64(fd, offset + SUNINFO, whence);
            __android_log_print(ANDROID_LOG_DEBUG, "\n\ninlinehook=====",
                                "lseek64(SEEK_SET): fd = %d, offset = %lld\n\n", fd,
                                offset + SUNINFO);
        }

        return var_off64_t - SUNINFO;
    }

    return old_lseek64(fd, offset, whence);
}

static int __nativehook_impl_android_fstat(int fd, struct stat *statbuf) {
    int result = 0;

    result = old_fstat(fd, statbuf);

    FILE_FD_INFO_S *pstFileFdInfo = findFileFdInfo(fd);
    if (NULL != pstFileFdInfo) {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====",
                            "before, fstat: fd = %d, fileSize = %lu, \n", fd, statbuf->st_size);

        if (statbuf->st_size != 0) {
            statbuf->st_size = statbuf->st_size - SUNINFO;
        }

        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====",
                            "after, fstat: fd = %d, fileSize = %lu, \n", fd, statbuf->st_size);
    }

    return result;
}

void startInlineHook(void) {
    void *pOpenat = (void *) __openat;

    //lseek
    if (registerInlineHook((uint32_t) lseek, (uint32_t) __nativehook_impl_android_lseek,
                           (uint32_t **) &old_lseek) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==lseek== start %p\n",
                            lseek);
        inlineHook((uint32_t) lseek);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==lseek== end\n");
    }

    //lseek64
    if (registerInlineHook((uint32_t) lseek64, (uint32_t) __nativehook_impl_android_lseek64,
                           (uint32_t **) &old_lseek64) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook",
                            "inline hook ==lseek64== start %p\n",
                            lseek64);
        inlineHook((uint32_t) lseek64);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==lseek64== end\n");
    }


    //close
    if (registerInlineHook((uint32_t) close, (uint32_t) __nativehook_impl_android_close,
                           (uint32_t **) &old_close) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==close== start %p\n",
                            close);
        inlineHook((uint32_t) close);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==close== end\n");
    }

    //pread
    if (registerInlineHook((uint32_t) pread, (uint32_t) __nativehook_impl_android_pread,
                           (uint32_t **) &old_pread) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==pread== start %p\n",
                            pread);
        inlineHook((uint32_t) pread);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==pread== end\n");
    }

    //pwrite
    if (registerInlineHook((uint32_t) pwrite, (uint32_t) __nativehook_impl_android_pwrite,
                           (uint32_t **) &old_pwrite) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook",
                            "inline hook ==pwrite== start %p\n",
                            pwrite);
        inlineHook((uint32_t) pwrite);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==pwrite== end\n");
    }

    //read
    if (registerInlineHook((uint32_t) read, (uint32_t) __nativehook_impl_android_read,
                           (uint32_t **) &old_read) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==read== start %p\n",
                            read);
        inlineHook((uint32_t) read);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==read== end\n");
    }

    //write
    if (registerInlineHook((uint32_t) write, (uint32_t) __nativehook_impl_android_write,
                           (uint32_t **) &old_write) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==write== start %p\n",
                            write);
        inlineHook((uint32_t) write);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==write== end\n");
    }


    //__openat
    if (registerInlineHook((uint32_t) pOpenat, (uint32_t) __nativehook_impl_android_openat,
                           (uint32_t **) &old_openat) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook",
                            "inline hook ==__openat== start %p\n",
                            pOpenat);
        inlineHook((uint32_t) pOpenat);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==__openat== end\n");
    }


    //fstat
    if (registerInlineHook((uint32_t) fstat, (uint32_t) __nativehook_impl_android_fstat,
                           (uint32_t **) &old_fstat) != ELE7EN_OK) { ;
    } else {
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==fstat== start %p\n",
                            fstat);
        inlineHook((uint32_t) fstat);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==fstat== end\n");
    }
}
