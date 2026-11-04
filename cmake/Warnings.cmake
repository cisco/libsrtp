function(target_set_warnings)
    set(oneValueArgs TARGET ENABLE AS_ERRORS)
    cmake_parse_arguments(
        TARGET_SET_WARNINGS
        "${options}"
        "${oneValueArgs}"
        "${multiValueArgs}"
        ${ARGN})

    if(NOT ${TARGET_SET_WARNINGS_ENABLE})
        message(STATUS "Warnings Disabled for: ${TARGET_SET_WARNINGS_TARGET}")
        return()
    endif()
    message(STATUS "Warnings Active for: ${TARGET_SET_WARNINGS_TARGET}")
    message(STATUS "Warnings as Errors: ${TARGET_SET_WARNINGS_AS_ERRORS}")

    set(MSVC_WARNINGS
        # Baseline
        /W4 # Baseline reasonable warnings
        /permissive- # standards conformance mode for MSVC compiler
        # C and C++ Warnings
 #       /w14242 # conversion from 'type1' to 'type1', possible loss of data
 #       /w14254 # 'operator': conversion from 't1:field_bits' to 't2:field_bits'
 #       /w14287 # unsigned/negative constant mismatch
 #       /w14296 # expression is always 'boolean_value'
 #       /w14311 # pointer truncation from 'type1' to 'type2'
        /w44062 # enumerator in a switch of enum 'enumeration' is not handled
 #       /w44242 # conversion from 'type1' to 'type2', possible loss of data
 #       /w14826 # Conversion from 'type1' to 'type_2' is sign-extended
 #       /w14905 # wide string literal cast to 'LPSTR'
 #       /w14906 # string literal cast to 'LPWSTR'
    )

    set(COMMON_WARNINGS
        # Baseline
        -Wall
        -Wextra # reasonable and standard
        -Wshadow # if a variable declaration shadows one from a parent context
        -Wpedantic # warn if non-standard is used
        # C and C++ Warnings
        -Wunused # warn on anything being unused
#        -Wformat=2 # warn on security issues around functions that format output
#        -Wcast-align # warn for potential performance problem casts
#        -Wconversion # warn on type conversions that may lose data
#        -Wsign-conversion # warn on sign conversions
        -Wnull-dereference # warn if a null dereference is detected
        -Wdouble-promotion # warn if float is implicit promoted to double
        -Wcast-qual
    )

    set(CLANG_WARNINGS
        ${COMMON_WARNINGS}
        -Wshorten-64-to-32
    )

    set(GCC_WARNINGS
        ${COMMON_WARNINGS}
        -Wduplicated-cond # warn if if / else chain has duplicated conditions
        -Wduplicated-branches # warn if if / else branches have duplicated code
        -Wlogical-op # warn about logical operations being used where bitwise were probably wanted
    )

    if(${TARGET_SET_WARNINGS_AS_ERRORS})
        set(CLANG_WARNINGS ${CLANG_WARNINGS} -Werror)
        set(GCC_WARNINGS ${GCC_WARNINGS} -Werror)
        set(MSVC_WARNINGS ${MSVC_WARNINGS} /WX)
    endif()

    if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
        set(WARNINGS ${MSVC_WARNINGS})
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(WARNINGS ${CLANG_WARNINGS})
    elseif(CMAKE_C_COMPILER_ID MATCHES "GNU")
        set(WARNINGS ${GCC_WARNINGS})
    endif()

    target_compile_options(${TARGET_SET_WARNINGS_TARGET} PRIVATE ${WARNINGS})

endfunction(target_set_warnings)
