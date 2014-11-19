/*
 * aes_cbc.h
 *
 * Header for AES Cipher Blobk Chaining Mode.
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 *
 */

#ifndef AES_CBC_H
#define AES_CBC_H

#include "aes.h"
#include "cipher.h"

typedef struct {
    v128_t state;                  /* cipher chaining state            */
    v128_t previous;               /* previous ciphertext block        */
    uint8_t key[32];
    int key_len;
    srtp_aes_expanded_key_t expanded_key; /* the cipher key                   */
} srtp_aes_cbc_ctx_t;

srtp_err_status_t srtp_aes_cbc_encrypt(srtp_aes_cbc_ctx_t *c, unsigned char *buf, unsigned int  *bytes_in_data);

srtp_err_status_t srtp_aes_cbc_context_init(srtp_aes_cbc_ctx_t *c, const uint8_t *key, int key_len);

srtp_err_status_t srtp_aes_cbc_set_iv(srtp_aes_cbc_ctx_t *c, void *iv, int direction);

srtp_err_status_t srtp_aes_cbc_nist_encrypt(srtp_aes_cbc_ctx_t *c, unsigned char *data, unsigned int *bytes_in_data);

srtp_err_status_t srtp_aes_cbc_nist_decrypt(srtp_aes_cbc_ctx_t *c, unsigned char *data, unsigned int *bytes_in_data);

#endif /* AES_CBC_H */

