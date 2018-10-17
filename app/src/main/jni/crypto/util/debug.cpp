//
// Created by famgy on 18-10-11.
//

#include <android/log.h>
#include <cstdio>
#include "debug.h"

#define DEBUG_FLAG "===debug==="


void printHex(const char *name, unsigned char *c, int n) {
    int i;
    char szPrintBuff[40960] = {0};

    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_FLAG,
                        "---------------------[%s, len = %d, start ]----------------------", name,
                        n);

    for (i = 0; i < n; i++) {
        sprintf(szPrintBuff, "%s0x%02X, ", szPrintBuff, c[i]);
        //__android_log_print(ANDROID_LOG_DEBUG, DEBUG_FLAG, "0x%02X, ", c[i]);

        if ((i % 4) == 3) {
            //__android_log_print(ANDROID_LOG_DEBUG, DEBUG_FLAG, " ");
            sprintf(szPrintBuff, "%s%s", szPrintBuff, " ");
        }

        if ((i % 16) == 15) {
            sprintf(szPrintBuff, "%s%s", szPrintBuff, "\n");
            //__android_log_print(ANDROID_LOG_DEBUG, DEBUG_FLAG, "\n");
        }
    }
    if ((i % 16) != 0) {
        //__android_log_print(ANDROID_LOG_DEBUG, DEBUG_FLAG, "\n");
        sprintf(szPrintBuff, "%s%s", szPrintBuff, "\n");
    }

    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_FLAG, "%s", szPrintBuff);

    __android_log_print(ANDROID_LOG_DEBUG, DEBUG_FLAG,
                        "----------------------[%s       end        ]----------------------\n\n",
                        name);
}

