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
  v128_t   counter;                /* holds the counter value          */
  v128_t   offset;                 /* initial offset value             */
  v128_t   keystream_buffer;       /* buffers bytes of keystream       */
  srtp_aes_expanded_key_t expanded_key; /* the cipher key                   */
  int      bytes_in_buffer;        /* number of unused bytes in buffer */
} aes_icm_ctx_t;


srtp_err_status_t aes_icm_context_init(aes_icm_ctx_t *c,
	const unsigned char *key,
	int key_len); 

srtp_err_status_t aes_icm_set_iv(aes_icm_ctx_t *c, void *iv, int direction);

srtp_err_status_t aes_icm_encrypt(aes_icm_ctx_t *c, unsigned char *buf, unsigned int *bytes_to_encr);

srtp_err_status_t aes_icm_output(aes_icm_ctx_t *c, unsigned char *buf, unsigned int bytes_to_output);

srtp_err_status_t aes_icm_dealloc(cipher_t *c);
 
srtp_err_status_t aes_icm_encrypt_ismacryp(aes_icm_ctx_t *c, 
	unsigned char *buf, 
	unsigned int *enc_len, 
	int forIsmacryp);
 
srtp_err_status_t aes_icm_alloc_ismacryp(cipher_t **c, int key_len, int forIsmacryp);

uint16_t aes_icm_bytes_encrypted(aes_icm_ctx_t *c);

#endif /* AES_ICM_H */

