
add_library( # Sets the name of the library.
             crypto

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             gm_jni.cpp
             sm3.c
             sm4.c
             util/debug.cpp)

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

target_link_libraries( # Specifies the target library.
                       crypto

                       # Links the target library to the log library
                       # included in the NDK.
                       log )