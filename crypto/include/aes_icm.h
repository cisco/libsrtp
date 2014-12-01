/*
 * aes_icm.h
 *
 * Header for AES Integer Counter Mode.
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 *
 */

#ifndef AES_ICM_H
#define AES_ICM_H

#include "aes.h"
#include "cipher.h"

typedef struct {
    v128_t counter;                       /* holds the counter value          */
    v128_t offset;                        /* initial offset value             */
    v128_t keystream_buffer;              /* buffers bytes of keystream       */
    srtp_aes_expanded_key_t expanded_key; /* the cipher key                   */
    int bytes_in_buffer;                  /* number of unused bytes in buffer */
    int key_size;                         /* AES key size + 14 byte SALT */
} srtp_aes_icm_ctx_t;

#endif /* AES_ICM_H */

