
#include <jni.h>
#include <string.h>
#include <cstdio>
#include <unistd.h>
#include "file_security.h"

const char* inline_baseApk = NULL;
int inline_baseApkL = 0;
const char* inline_originApk = NULL;
JavaVM * inline_android_vm = NULL;

#define JNI_API_DEF(f) Java_com_famgy_fileencrypt_filesecurity_NativeHandler_##f

extern "C" {

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    JNIEnv *env;
    jint result = -1;

    inline_android_vm = vm;

    if (vm->GetEnv((void **) &env, JNI_VERSION_1_4) == JNI_OK) {

        //save mainapp env
//        jclass mainApp = env->FindClass("com/suninfo/msm/apkshield/MainApp");
//        jfieldID idBaseApk = env->GetStaticFieldID(mainApp, "m_baseApkPath", "Ljava/lang/String;");
//        jstring jBaseApk = (jstring) env->GetStaticObjectField(mainApp, idBaseApk);
//        jfieldID idOriginApk = env->GetStaticFieldID(mainApp, "m_libPath", "Ljava/lang/String;");
//        jstring jOriginApk = (jstring) env->GetStaticObjectField(mainApp, idOriginApk);
//        jboolean bCopy = JNI_TRUE;
//        inline_baseApk = env->GetStringUTFChars(jBaseApk, &bCopy);
//        inline_baseApkL = strlen(inline_baseApk);
//        inline_originApk = env->GetStringUTFChars(jOriginApk, &bCopy);


        /* success -- return valid version number */
        result = JNI_VERSION_1_4;
    }

    return result;
}

JNIEXPORT void JNI_API_DEF(startFileSecurity)(JNIEnv *env, jobject obj) {
    (void) env;
    (void) obj;

    startInlineHook();

    return;
}

}