find_path(WOLFSSL_INCLUDE_DIR wolfssl/ssl.h)

find_library(WOLFSSL_LIBRARY wolfssl)

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

