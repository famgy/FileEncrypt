//
// Created by famgy on 18-10-24.
//

#include <android/log.h>
#include "file_log.h"


void log_print(int prio, const char* tag, const char* fmt, ...) {
    if (prio >= ANDROID_LOG_DEBUG) {
        va_list args;         //定义一个va_list类型的变量，用来储存单个参数
        va_start(args, fmt);  //使args指向可变参数的第一个参数

        __android_log_vprint(prio, tag, fmt, args);

        va_end(args);         //结束可变参数的获取
    }
}