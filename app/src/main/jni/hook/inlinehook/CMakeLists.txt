add_library( # Sets the name of the library.
             inlinehook

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             inlineHook.c
             relocate.c
             main.cpp
              )

target_link_libraries( # Specifies the target library.
                       inlinehook

                       # Links the target library to the log library
                       # included in the NDK.
                       log
                       )