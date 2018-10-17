//
// Created by wzl on 8/7/18.
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

#include "inlineHook.h"


typedef struct tagFileFdInfo
{
    int fd;
    int flag;
}FILE_FD_INFO_S;

const char* inline_baseApk = NULL;
int inline_baseApkL = 0;

int g_inlinehook_openat_fd = 0;
std::map<int, FILE_FD_INFO_S *> g_FileFdMap;

extern "C" int __openat(int, const char*, int, int);


extern "C" {
    int (*old_openat)(int, const char *, int, int) = NULL;
    ssize_t (*old_pread)(int fd, void *buf, size_t count, off_t offset) = NULL;
    ssize_t (*old_pwrite)(int fd, const void *buf, size_t count, off_t offset) = NULL;
    ssize_t (*old_read)(int fd, void *buf, size_t count) = NULL;
    ssize_t (*old_write)(int fd, const void *buf, size_t count) = NULL;
    off_t (*old_lseek)(int fd, off_t offset, int whence) = NULL;

    int (*old_close)(int fd) = NULL;

    static FILE_FD_INFO_S * findFileFdInfo(const int fd) {
        std::map<int, FILE_FD_INFO_S *>::iterator it;
        FILE_FD_INFO_S * pstFileFdInfo = NULL;

        it = g_FileFdMap.find(fd);
        if (it != g_FileFdMap.end()) {
            pstFileFdInfo = it->second;
        }

        return pstFileFdInfo;
    }

    static int __nativehook_impl_android_openat(int dirFd, const char *pathName, int flag, int mode) {
        if (strcmp(pathName, "/storage/emulated/0/Download/pdf_test.pdf") != 0 && strcmp(pathName, "/storage/emulated/0/Download/txt_test.txt") != 0) {

            int fd = old_openat(dirFd, pathName, flag, mode);
            //__android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "openat:%s, fd = %d\n", pathName, fd);
            return fd;
        }

        if (flag & O_APPEND) {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_APPEND");
        }

        if (flag & O_TRUNC) {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "openat:%s, flagV = %s\n", pathName, "O_TRUNC");
        }

        if (access(pathName, F_OK) == 0) {

            int fd_o = old_openat(dirFd, pathName, O_RDWR, 0640);

            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "openat:%s, fd = %d\n", pathName, fd_o);

            FILE *hSource = fdopen(fd_o, "a+");
            if (hSource == NULL) {
                return -1;
            }

            char famgyBuffer[6] = {0};
            fread(famgyBuffer, 5, 1, hSource);
            fseek(hSource, 0, SEEK_SET);
            if (strcmp(famgyBuffer, "famgy") == 0) {
                fclose(hSource);

                int fdTmp = old_openat(dirFd, pathName, flag, mode);
                if (fdTmp != -1) {
                    // Add file-fd-list for matching.
                    FILE_FD_INFO_S *pstFileFdInfo = (FILE_FD_INFO_S *)malloc(sizeof(FILE_FD_INFO_S));
                    if (pstFileFdInfo == NULL) {
                        return -1;
                    }

                    pstFileFdInfo->fd = fdTmp;
                    pstFileFdInfo->flag = flag;
                    g_FileFdMap.insert(std::pair<int, FILE_FD_INFO_S *>(fdTmp, pstFileFdInfo));

                    lseek(fdTmp, 5, SEEK_SET);
                }

                return fdTmp;
            }

            int len = strlen(pathName);
            char *pathNameTmp = (char *)malloc(len + sizeof("_tmp"));
            if (pathNameTmp == NULL) {
                fclose(hSource);
                return -1;
            }

            pathNameTmp[0] = '\0';
            strcat(pathNameTmp, pathName);
            strcat(pathNameTmp, "_tmp");
            FILE *hDestination = fdopen(old_openat(dirFd, pathNameTmp, O_CREAT | O_RDWR, 0640), "a+");
            if (hDestination == NULL) {
                fclose(hSource);
                return -1;
            }

            fwrite("famgy", 5, 1, hDestination);
            char buffer[1] = {0};
            while(fread(buffer, 1, 1, hSource) > 0) {
                buffer[0] = buffer[0] ^ 'f';
                fwrite(buffer, 1, 1, hDestination);
            }

            fclose(hSource);
            fclose(hDestination);
            unlink(pathName);

            // Mv file
            rename(pathNameTmp, pathName);

            free(pathNameTmp);
        }

        int fd = old_openat(dirFd, pathName, flag, mode);
        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook====", "openat:%s, fd = %d\n", pathName, fd);
        if (fd != -1) {
            // Add file-fd-list for matching.
            FILE_FD_INFO_S *pstFileFdInfo = (FILE_FD_INFO_S *)malloc(sizeof(FILE_FD_INFO_S));
            if (pstFileFdInfo == NULL) {
                return -1;
            }

            pstFileFdInfo->fd = fd;
            pstFileFdInfo->flag = flag;
            g_FileFdMap.insert(std::pair<int, FILE_FD_INFO_S *>(fd, pstFileFdInfo));

            lseek(fd, 5, SEEK_SET);
        }

        return fd;
    }

    static int __nativehook_impl_android_close(int fd) {
        std::map<int, FILE_FD_INFO_S *>::iterator it;
        int result = 0;

        it = g_FileFdMap.find(fd);
        if (it != g_FileFdMap.end()) {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "close: fd = %d", fd);
            result = syscall(SYS_close, fd);
            if (result == 0) {
                g_FileFdMap.erase(it);
                FILE_FD_INFO_S * fileFdInfoTmp = it->second;
                free(fileFdInfoTmp);
            }
        } else {
            result = syscall(SYS_close, fd);
        }

        return result;
    }

    static ssize_t __nativehook_impl_android_pread(int fd, void *buf, size_t count, off_t offset) {
        //__android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "pread: fd = %d, count = %d, offset = %d\n", fd, count, offset);

        ssize_t r_len;

        if (NULL != findFileFdInfo(fd)) {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "pread: fd = %d, count = %d, offset = %d\n", fd, count, offset);

            r_len = old_pread(fd, buf, count, offset + 5);
            if (r_len == -1) {
                __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "pread failed: fd = %d, count = %d, offset = %d, errno = %s\n", fd, count, offset, strerror(errno));
                return -1;
            }

            char *tmp = (char *)buf;
            for (int i = 0; i < r_len; i++) {
                tmp[i] = tmp[i] ^ 'f';
            }
        } else {
            r_len = old_pread(fd, buf, count, offset);
        }

        return r_len;
    }

    static ssize_t __nativehook_impl_android_pwrite(int fd, const void *buf, size_t count, off_t offset) {
        ssize_t r_len;

        if (NULL != findFileFdInfo(fd)) {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "pwrite: fd = %d, count = %d, offset = %d\n", fd, count, offset);

            char *bufTmp = (char *)malloc(count);
            if (bufTmp == NULL) {
                return -1;
            }
            memcpy(bufTmp, buf, count);

            char *tmp = (char *)bufTmp;
            for (int i = 0; i < count; i++) {
                tmp[i] = tmp[i] ^ 'f';
            }

            r_len = old_pwrite(fd, bufTmp, count, offset + 5);

            free(bufTmp);
        } else {
            r_len = old_pwrite(fd, buf, count, offset);
        }

        return r_len;
    }

    static ssize_t __nativehook_impl_android_read(int fd, void *buf, size_t count) {
        //__android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "pread: fd = %d, count = %d, offset = %d\n", count);

        ssize_t r_len;

        if (NULL != findFileFdInfo(fd)) {
            __android_log_print(ANDROID_LOG_DEBUG, "\ninlinehook=====",
                                "init , read: fd = %d, count = %d, curOffset = %d\n", fd, count,
                                (int) old_lseek(fd, 0, SEEK_CUR));

            r_len = old_read(fd, buf, count);

            char *tmp = (char *)buf;
            for (int i = 0; i < r_len; i++) {
                tmp[i] = tmp[i] ^ 'f';
            }

            __android_log_print(ANDROID_LOG_DEBUG, "after==inlinehook=====", "read: buffer = %x, %x\n",
                                ((char *) buf)[0], ((char *) buf)[1]);
        } else {
            r_len = old_read(fd, buf, count);
        }

        return r_len;
    }

    static ssize_t __nativehook_impl_android_write(int fd, const void *buf, size_t count) {
        ssize_t r_len;
        FILE_FD_INFO_S * pstFileFdInfo = findFileFdInfo(fd);

        if (NULL != pstFileFdInfo) {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "write: fd = %d, count = %d\n", fd, count);

            if ((pstFileFdInfo->flag & O_TRUNC != 0) && (lseek(fd, 0, SEEK_CUR) == 5)) {
                lseek(fd, 0, SEEK_SET);
                old_write(fd, "famgy", 5);
            }

            char *bufTmp = (char *)malloc(count);
            if (bufTmp == NULL) {
                return -1;
            }
            memcpy(bufTmp, buf, count);

            char *tmp = (char *)bufTmp;
            for (int i = 0; i < count; i++) {
                tmp[i] = tmp[i] ^ 'f';
            }

            off_t currpos = lseek(fd, 0, SEEK_CUR);

            r_len = old_write(fd, bufTmp, count);

            free(bufTmp);
        } else {
            r_len = old_write(fd, buf, count);
        }

        return r_len;
    }

    static ssize_t __nativehook_impl_android_lseek(int fd, off_t offset, int whence) {
        ssize_t r_len;
        FILE_FD_INFO_S * pstFileFdInfo = findFileFdInfo(fd);

        if (NULL != pstFileFdInfo) {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook=====", "lseek: fd = %d\n", fd);
        }

        return old_lseek(fd, offset, whence);
    }

    JNIEXPORT void Java_com_famgy_fileencrypt_MainActivity_startInlineHook(JNIEnv *env, jobject obj) {
        void *pOpenat = (void *) __openat;

        //__openat
        if (registerInlineHook((uint32_t) pOpenat, (uint32_t) __nativehook_impl_android_openat,
                               (uint32_t **) &old_openat) != ELE7EN_OK)
        {
            ;
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==__openat== start %p\n", pOpenat);
            inlineHook((uint32_t) pOpenat);
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==__openat== end\n");
        }

        //close
        if (registerInlineHook((uint32_t) close, (uint32_t) __nativehook_impl_android_close,
                               (uint32_t **) &old_close) != ELE7EN_OK)
        {
            ;
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==close== start %p\n", close);
            inlineHook((uint32_t) close);
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==close== end\n");
        }

        //pread
        if (registerInlineHook((uint32_t) pread, (uint32_t) __nativehook_impl_android_pread,
                               (uint32_t **) &old_pread) != ELE7EN_OK)
        {
            ;
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==pread== start %p\n", pread);
            inlineHook((uint32_t) pread);
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==pread== end\n");
        }

        //pwrite
        if (registerInlineHook((uint32_t) pwrite, (uint32_t) __nativehook_impl_android_pwrite,
                               (uint32_t **) &old_pwrite) != ELE7EN_OK)
        {
            ;
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==pwrite== start %p\n", pwrite);
            inlineHook((uint32_t) pwrite);
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==pwrite== end\n");
        }

        //read
        if (registerInlineHook((uint32_t) read, (uint32_t) __nativehook_impl_android_read,
                               (uint32_t **) &old_read) != ELE7EN_OK)
        {
            ;
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==read== start %p\n", read);
            inlineHook((uint32_t) read);
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==read== end\n");
        }

        //write
        if (registerInlineHook((uint32_t) write, (uint32_t) __nativehook_impl_android_write,
                               (uint32_t **) &old_write) != ELE7EN_OK)
        {
            ;
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==write== start %p\n", write);
            inlineHook((uint32_t) write);
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==write== end\n");
        }

        //lseek
        if (registerInlineHook((uint32_t) lseek, (uint32_t) __nativehook_impl_android_lseek,
                               (uint32_t **) &old_lseek) != ELE7EN_OK)
        {
            ;
        } else {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==lseek== start %p\n", lseek);
            inlineHook((uint32_t) lseek);
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==lseek== end\n");
        }
    }

    JNIEXPORT void Java_com_famgy_fileencrypt_MainActivity_startInlineLseek(JNIEnv *env, jobject obj) {
        int fd = open("/storage/emulated/0/Download/txt_test.txt", O_WRONLY);
        if (fd == -1) {
            __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "open failed, error : %s", strerror(errno));
            return;
        }

        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==lseek== before - curOffset = %d, fd = %d\n", lseek(fd, 0, SEEK_CUR), fd);

        lseek(fd, 5, SEEK_SET);

        __android_log_print(ANDROID_LOG_DEBUG, "inlinehook", "inline hook ==lseek== after -  curOffset = %d\n", lseek(fd, 0, SEEK_CUR));
    }

}