cmake_minimum_required (VERSION 2.8)

project(srtp2)

set(SOURCES_C
	srtp/ekt.c
	srtp/srtp.c
)

set(CIPHERS_SOURCES_C
	crypto/cipher/aes.c
	crypto/cipher/aes_icm.c
	crypto/cipher/cipher.c
	crypto/cipher/null_cipher.c
)

set(HASHES_SOURCES_C
	crypto/hash/auth.c
	crypto/hash/hmac.c
	crypto/hash/null_auth.c
	crypto/hash/sha1.c
)

set(KERNEL_SOURCES_C
	crypto/kernel/alloc.c
	crypto/kernel/crypto_kernel.c
	crypto/kernel/err.c
	crypto/kernel/key.c
)

set(MATH_SOURCES_C
	crypto/math/datatypes.c
	crypto/math/stat.c
)

set(REPLAY_SOURCES_C
	crypto/replay/rdb.c
	crypto/replay/rdbx.c
	crypto/replay/ut_sim.c
)

set(SOURCES_H
	crypto/include/aes.h
	crypto/include/aes_icm.h
	crypto/include/alloc.h
	crypto/include/auth.h
	crypto/include/cipher.h
	crypto/include/cipher_types.h
	crypto/include/config.h
	crypto/include/crypto_kernel.h
	crypto/include/crypto_types.h
	crypto/include/datatypes.h
	crypto/include/err.h
	crypto/include/hmac.h
	crypto/include/integers.h
	crypto/include/key.h
	crypto/include/null_auth.h
	crypto/include/null_cipher.h
	crypto/include/rdb.h
	crypto/include/rdbx.h
	crypto/include/sha1.h
	crypto/include/stat.h
	include/ekt.h
	include/srtp.h
	include/srtp_priv.h
	include/ut_sim.h
)

source_group("src" FILES ${SOURCES_C})
source_group("src\\Ciphers" FILES ${CIPHERS_SOURCES_C})
source_group("src\\Hashes" FILES ${HASHES_SOURCES_C})
source_group("src\\Kernel" FILES ${KERNEL_SOURCES_C})
source_group("src\\Math" FILES ${MATH_SOURCES_C})
source_group("src\\Replay" FILES ${REPLAY_SOURCES_C})
source_group("include" FILES ${SOURCES_H})

add_library(srtp2 STATIC
	${SOURCES_C}
	${CIPHERS_SOURCES_C}
	${HASHES_SOURCES_C}
	${KERNEL_SOURCES_C}
	${MATH_SOURCES_C}
	${REPLAY_SOURCES_C}
	${SOURCES_H}
)

target_include_directories(srtp2 PUBLIC crypto/include include)
configure_file(config.hw ${CMAKE_CURRENT_SOURCE_DIR}/crypto/include/config.h COPYONLY)
add_definitions(-D_LIB -DHAVE_CONFIG_H)
