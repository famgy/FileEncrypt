#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <jni.h>
#include <android/log.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include "../xhook/xhook.h"

int g_encrypt_fd = 0;
FILE *g_encrypt_file = NULL;

static int  __nativehook_impl_android_open(const char *pathName, int flags, mode_t mode)
{
    __android_log_print(ANDROID_LOG_DEBUG, "mytest", "open file : %s\n", pathName);

    if (strcmp(pathName, "/storage/emulated/0/Download/pdf_test.pdf") != 0) {
        return open(pathName, flags, mode);
    }

    if (access(pathName, F_OK) == 0) {
        FILE *hSource = fopen(pathName, "rb");
        if (hSource == NULL) {
            return -1;
        }

        char famgyBuffer[6] = {0};
        fread(famgyBuffer, 5, 1, hSource);
        if (strcmp(famgyBuffer, "famgy") == 0) {
            fclose(hSource);

            int fdTmp = open(pathName, flags, mode);
            lseek(fdTmp, 5, 0);
            g_encrypt_fd = fdTmp;
            return fdTmp;
        }

        int len = strlen(pathName);
        char *pathNameTmp = malloc(len + sizeof("_tmp"));
        if (pathNameTmp == NULL) {
            fclose(hSource);
            return -1;
        }
        pathNameTmp[0] = '\0';
        strcat(pathNameTmp, pathName);
        strcat(pathNameTmp, "_tmp");
        FILE *hDestination = fopen(pathNameTmp,"wb");
        if (hDestination == NULL) {
            fclose(hSource);
            return -1;
        }

        fwrite("famgy", 5, 1, hDestination);
        char buffer[1];
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

    g_encrypt_fd = open(pathName, flags, mode);
    g_encrypt_file = fdopen(g_encrypt_fd, "a+");

    //lseek(g_encrypt_fd, 5, 0);
    return g_encrypt_fd;
}

static int  __nativehook_impl_android_close(int fd)
{
    //__android_log_print(ANDROID_LOG_DEBUG, "mytest", "close file, fd = %d, g_encrypt_fd = %d\n", fd, g_encrypt_fd);

    if (fd == g_encrypt_fd) {
        g_encrypt_fd = 0;
    }

    return close(fd);
}

static ssize_t  __nativehook_impl_android_read(int fd, void *buf, size_t count)
{
    //__android_log_print(ANDROID_LOG_DEBUG, "mytest", "read file, fd = %d, g_encrypt_fd = %d\n", fd, g_encrypt_fd);

    if (g_encrypt_fd != fd) {
        return read(fd, buf, count);
    }

    char *buffTmp = buf;
    int len = read(fd, buf, count);
    for (int i = 0; i < len; i++) {
        buffTmp[i] = buffTmp[i] ^ 'f';
    }

    return len;
}

static ssize_t  __nativehook_impl_android_pread(int fd, void *buf, size_t count, off_t offset)
{
    __android_log_print(ANDROID_LOG_DEBUG, "mytest", "pread file, fd = %d, g_encrypt_fd = %d\n", fd, g_encrypt_fd);


    return pread(fd, buf, count, offset);
}


void Java_com_famgy_fileencrypt_hook_xhookapply_NativeHandler_start(JNIEnv* env, jobject obj) {
    (void) env;
    (void) obj;

    xhook_register("^/system/.*\\.so$", "open", __nativehook_impl_android_open, NULL);
    xhook_register("^/system/.*\\.so$", "close", __nativehook_impl_android_close, NULL);
    //xhook_register("^/system/.*\\.so$", "read", __nativehook_impl_android_read, NULL);

    xhook_register("^/system/.*\\.so$", "pread", __nativehook_impl_android_pread, NULL);
}

//int fstat(int fd, struct stat *statbuf);
//int stat(const char *pathname, struct stat *statbuf);
//int lstat(const char *pathname, struct stat *statbuf);