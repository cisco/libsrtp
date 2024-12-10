if (WOLFSSL_ROOT_DIR)
    set(_WOLFSSL_ROOT_HINTS_AND_PATHS HINTS ${WOLFSSL_ROOT_DIR} PATH_SUFFIXES include lib NO_DEFAULT_PATH)
endif()

find_path(WOLFSSL_INCLUDE_DIR wolfssl/ssl.h ${_WOLFSSL_ROOT_HINTS_AND_PATHS})

find_library(WOLFSSL_LIBRARY wolfssl ${_WOLFSSL_ROOT_HINTS_AND_PATHS})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(wolfSSL DEFAULT_MSG
    WOLFSSL_LIBRARY WOLFSSL_INCLUDE_DIR)

mark_as_advanced(WOLFSSL_INCLUDE_DIR WOLFSSL_LIBRARY)

if(NOT TARGET wolfSSL)
    add_library(wolfSSL UNKNOWN IMPORTED)
    set_target_properties(wolfSSL PROPERTIES
                          INTERFACE_INCLUDE_DIRECTORIES "${WOLFSSL_INCLUDE_DIR}"
                          IMPORTED_LINK_INTERFACE_LANGUAGES "C"
                          IMPORTED_LOCATION "${WOLFSSL_LIBRARY}")
endif()

