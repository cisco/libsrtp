/*
 * aes_gcm_nss.c
 *
 * AES Galois Counter Mode
 *
 * Richard L. Barnes
 * Cisco
 *
 */

/*
 *
 * Copyright (c) 2013-2017, Cisco Systems, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following
 *   disclaimer in the documentation and/or other materials provided
 *   with the distribution.
 *
 *   Neither the name of the Cisco Systems, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <nss/nss.h>
#include <nss/pk11pub.h>
#include <nss/secerr.h>
#include "prerror.h"

///// <replacement-srtp> /////

// XXX Ersatz things from libsrtp
#define srtp_cipher_direction_t int
#define srtp_direction_any 0
#define srtp_direction_encrypt 1
#define srtp_direction_decrypt 2

#define srtp_err_status_t int
#define srtp_err_status_ok 0
#define srtp_err_status_bad_param 2
#define srtp_err_status_alloc_fail 3
#define srtp_err_status_init_fail 4
#define srtp_err_status_algo_fail 5
#define srtp_err_status_auth_fail 6

#define srtp_crypto_alloc malloc
#define srtp_crypto_free free
#define octet_string_set_to_zero(p, l)

#define debug_print(module, fmt, val) { printf(fmt "\n", val); }
#define srtp_octet_string_hex_string(str, len) "fnord"
#define v128_hex_string(val) "fnord"

typedef int srtp_cipher_type_t;
srtp_cipher_type_t srtp_aes_gcm_128_nss = 0;
srtp_cipher_type_t srtp_aes_gcm_256_nss = 1;

typedef struct {
  srtp_cipher_type_t *type;
  int algorithm;
  void *state;
} srtp_cipher_t;

typedef struct {
  srtp_cipher_direction_t dir;
  int key_size;
  int tag_len;
  PK11SlotInfo *slot;
  PK11SymKey *key;
  CK_GCM_PARAMS params;
  uint8_t tag[16];
} srtp_aes_gcm_ctx_t;

typedef struct {
  int debug;
  const char *name;
} srtp_debug_module_t;

#define SRTP_AES_GCM_128      0
#define SRTP_AES_GCM_256      0
#define SRTP_AES_128_KEY_LEN  16
#define SRTP_AES_256_KEY_LEN  32
#define SRTP_AES_GCM_128_KEY_LEN_WSALT  28
#define SRTP_AES_GCM_256_KEY_LEN_WSALT  44
///// </replacement-srtp> /////

srtp_debug_module_t srtp_mod_aes_gcm = {
    0,               /* debugging is off by default */
    "aes gcm"        /* printable module name       */
};

/*
 * The following are the global singleton instances for the
 * 128-bit and 256-bit GCM ciphers.
 */
/*
extern const srtp_cipher_type_t srtp_aes_gcm_128_nss;
extern const srtp_cipher_type_t srtp_aes_gcm_256_nss;
*/

/*
 * For now we only support 8 and 16 octet tags.  The spec allows for
 * optional 12 byte tag, which may be supported in the future.
 */
#define GCM_AUTH_TAG_LEN    16
#define GCM_AUTH_TAG_LEN_8  8


/*
 * This function allocates a new instance of this crypto engine.
 * The key_len parameter should be one of 28 or 44 for
 * AES-128-GCM or AES-256-GCM respectively.  Note that the
 * key length includes the 14 byte salt value that is used when
 * initializing the KDF.
 */
static srtp_err_status_t srtp_aes_gcm_nss_alloc (srtp_cipher_t **c, int key_len, int tlen)
{
  srtp_aes_gcm_ctx_t *gcm;

  debug_print(srtp_mod_aes_gcm, "allocating cipher with key length %d", key_len);
  debug_print(srtp_mod_aes_gcm, "allocating cipher with tag length %d", tlen);

  /*
   * Verify the key_len is valid for one of: AES-128/256
   */
  if (key_len != SRTP_AES_GCM_128_KEY_LEN_WSALT &&
      key_len != SRTP_AES_GCM_256_KEY_LEN_WSALT) {
      return (srtp_err_status_bad_param);
  }

  if (tlen != GCM_AUTH_TAG_LEN &&
      tlen != GCM_AUTH_TAG_LEN_8) {
      return (srtp_err_status_bad_param);
  }

  /* allocate memory a cipher of type aes_gcm */
  *c = (srtp_cipher_t *) srtp_crypto_alloc(sizeof(srtp_cipher_t));
  if (*c == NULL) {
    return srtp_err_status_alloc_fail;
  }
  memset(*c, 0x0, sizeof(srtp_cipher_t));

  gcm = (srtp_aes_gcm_ctx_t*) srtp_crypto_alloc(sizeof(srtp_aes_gcm_ctx_t));
  if (gcm == NULL) {
    return srtp_err_status_alloc_fail;
  }
  memset(gcm, 0x0, sizeof(srtp_aes_gcm_ctx_t));

  /* Initialize NSS and get a slot */
  if (!NSS_IsInitialized()) {
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
      return srtp_err_status_alloc_fail;
    }
  }

  gcm->slot = PK11_GetInternalSlot();
  if (gcm->slot == NULL) {
    return srtp_err_status_alloc_fail;
  }

  /* set pointers */
  (*c)->state = gcm;

  /* setup cipher attributes */
  switch (key_len) {
  case SRTP_AES_GCM_128_KEY_LEN_WSALT:
    (*c)->type = &srtp_aes_gcm_128_nss;
    (*c)->algorithm = SRTP_AES_GCM_128;
    gcm->key_size = SRTP_AES_128_KEY_LEN;
    break;
  case SRTP_AES_GCM_256_KEY_LEN_WSALT:
    (*c)->type = &srtp_aes_gcm_256_nss;
    (*c)->algorithm = SRTP_AES_GCM_256;
    gcm->key_size = SRTP_AES_256_KEY_LEN;
    break;
  }

  gcm->tag_len = tlen;
  gcm->params.ulIvLen = 12;
  gcm->params.ulTagBits = 8 * tlen;

  return srtp_err_status_ok;
}

/*
 * This function deallocates a GCM session
 */
static srtp_err_status_t srtp_aes_gcm_nss_dealloc (srtp_cipher_t *c)
{
  srtp_aes_gcm_ctx_t *ctx;

  ctx = (srtp_aes_gcm_ctx_t *)(c->state);
  if (ctx) {
    if (ctx->key) {
      PK11_FreeSymKey(ctx->key);
    }

    if (ctx->slot) {
      PK11_FreeSlot(ctx->slot);
    }

    octet_string_set_to_zero(ctx, sizeof(srtp_aes_gcm_ctx_t));
    srtp_crypto_free(ctx);
  }

  /* free memory */
  srtp_crypto_free(c);

  return srtp_err_status_ok;
}

/*
 * aes_gcm_nss_context_init(...) initializes the aes_gcm_context
 * using the value in key[].
 *
 * the key is the secret key
 */
static srtp_err_status_t srtp_aes_gcm_nss_context_init (void* cv, const uint8_t *key)
{
  srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;

  c->dir = srtp_direction_any;

  debug_print(srtp_mod_aes_gcm, "key:  %s", srtp_octet_string_hex_string(key, c->key_size));

  SECItem keyItem = {siBuffer, key, c->key_size};
  switch (c->key_size) {
  case SRTP_AES_128_KEY_LEN:
  case SRTP_AES_256_KEY_LEN:
    c->key = PK11_ImportSymKey(c->slot, CKM_AES_GCM, PK11_OriginUnwrap,
                               CKA_ENCRYPT, &keyItem, NULL);
    if (c->key == NULL) {
      return srtp_err_status_init_fail;
    }

    break;

  default:
    return srtp_err_status_bad_param;
  }

  return srtp_err_status_ok;
}

/*
 * aes_gcm_nss_set_iv(c, iv) sets the counter value to the exor of iv with
 * the offset
 */
static srtp_err_status_t srtp_aes_gcm_nss_set_iv (void *cv, uint8_t *iv, srtp_cipher_direction_t direction)
{
  srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;

  if (direction != srtp_direction_encrypt && direction != srtp_direction_decrypt) {
    return (srtp_err_status_bad_param);
  }
  c->dir = direction;

  debug_print(srtp_mod_aes_gcm, "setting iv: %s", v128_hex_string((v128_t*)iv));

  c->params.pIv = iv;
  return srtp_err_status_ok;
}

/*
 * This function processes the AAD
 *
 * Parameters:
 *	c	Crypto context
 *	aad	Additional data to process for AEAD cipher suites
 *	aad_len	length of aad buffer
 */
static srtp_err_status_t srtp_aes_gcm_nss_set_aad (void *cv, const uint8_t *aad, uint32_t aad_len)
{
  srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;

  debug_print(srtp_mod_aes_gcm, "setting AAD: %s", srtp_octet_string_hex_string(aad, aad_len));

  c->params.pAAD = aad;
  c->params.ulAADLen = aad_len;
  return srtp_err_status_ok;
}

/*
 * This function encrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_nss_encrypt (void *cv, unsigned char *buf, unsigned int *enc_len)
{
  srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;
  if (c->dir != srtp_direction_encrypt && c->dir != srtp_direction_decrypt) {
    return (srtp_err_status_bad_param);
  }

  SECStatus rv;
  unsigned int original_enc_len = *enc_len;
  SECItem param = {siBuffer, (unsigned char*) &(c->params), sizeof(c->params)};

  /* Encrypt the data */
  rv = PK11_Encrypt(c->key, CKM_AES_GCM, &param,
                    buf, enc_len, *enc_len + c->tag_len,
                    buf, *enc_len);
  if (rv != SECSuccess) {
    return srtp_err_status_algo_fail;
  }

  /* Buffer the tag for a later call to srtp_aes_gcm_nss_get_tag() */
  memcpy(c->tag, buf + original_enc_len, c->tag_len);

  /* Truncate the buffer to remove the tag */
  *enc_len = original_enc_len;

  return srtp_err_status_ok;
}

/*
 * This function returns the GCM tag for a given context.  This should be
 * called after encrypting the data.  The *len value is increased by the tag
 * size.  The caller must ensure that *buf has enough room to accept the
 * appended tag.
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_nss_get_tag (void *cv, uint8_t *buf, uint32_t *len)
{
  srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;

  /* Retreive the tag */
  memcpy(buf, c->tag, c->tag_len);

  /* Increase encryption length by the tag size */
  *len += c->tag_len;

  return srtp_err_status_ok;
}

/*
 * This function decrypts a buffer using AES GCM mode
 *
 * Parameters:
 *	c	Crypto context
 *	buf	data to encrypt
 *	enc_len	length of encrypt buffer
 */
static srtp_err_status_t srtp_aes_gcm_nss_decrypt (void *cv, unsigned char *buf, unsigned int *enc_len)
{
  srtp_aes_gcm_ctx_t *c = (srtp_aes_gcm_ctx_t *)cv;
  if (c->dir != srtp_direction_encrypt && c->dir != srtp_direction_decrypt) {
    return (srtp_err_status_bad_param);
  }

  SECStatus rv;
  SECItem param = {siBuffer, (unsigned char*) &(c->params), sizeof(c->params)};

  /* Decrypt the data */
  rv = PK11_Decrypt(c->key, CKM_AES_GCM, &param,
                    buf, enc_len, *enc_len + c->tag_len,
                    buf, *enc_len);
  if (rv != SECSuccess) {
    PRErrorCode err = PORT_GetError();
    if (err == SEC_ERROR_BAD_DATA) {
      return srtp_err_status_auth_fail;
    }

    return srtp_err_status_algo_fail;
  }

  return srtp_err_status_ok;
}


/*
 * Name of this crypto engine
 */
static const char srtp_aes_gcm_128_nss_description[] = "AES-128 GCM using NSS";
static const char srtp_aes_gcm_256_nss_description[] = "AES-256 GCM using NSS";

/* TODO: Test cases */



/**********/

/*
RICHBARN-M-616C:double-ideas richbarn$ gcc -I /Users/richbarn/Projects/nss/dist/public/ -I/Users/richbarn/Projects/nss/dist/Debug/include/nspr/ -L/Users/richbarn/Projects/nss/dist/Debug/lib/ -lnss3 -lnspr4 gcm.c
RICHBARN-M-616C:double-ideas richbarn$ DYLD_LIBRARY_PATH=/Users/richbarn/Projects/nss/dist/Debug/lib/ ./a.out
*/

#include <stdio.h>

#define DIE(msg, rv) { \
  PRErrorCode err = PR_GetError(); \
  printf("%s [%08x] [%08x] [%08x]\n", msg, rv, err, SEC_ERROR_INVALID_KEY); \
  return 1; }

void print_buf(const char* label, uint8_t *buf, int len) {
  printf("%15s [%2d] = ", label, len);
  for (int i=0; i < len; ++i) {
    printf("%02x", buf[i]);
  }
  printf("\n");
}

int main() {
  SECStatus rv;
  CK_MECHANISM_TYPE mechanism = CKM_AES_GCM;

  uint8_t key[16]   = {0x13, 0x8d, 0xea, 0x88, 0x18, 0xc8, 0x58, 0x0c,
                       0xb2, 0xbc, 0xfd, 0x46, 0x03, 0x4f, 0xbb, 0xfb};
  uint8_t nonce[12] = {0xfa, 0xf8, 0x3a, 0x3f, 0xa3, 0xa9,
                       0x3a, 0xee, 0xb4, 0xe2, 0xd7, 0x98};
  uint8_t aad[4]    = {0x00, 0x01, 0x02, 0x03};
  uint8_t data[20]  = {0xf1, 0xf2, 0xf3, 0xf4};

  srtp_cipher_t *c;
  srtp_err_status_t err;

  // Alloc
  err = srtp_aes_gcm_nss_alloc(&c, 28, 16);
  if (err != srtp_err_status_ok) {
    DIE("couldn't alloc", err);
  }

  // Init
  err = srtp_aes_gcm_nss_context_init(c->state, key);
  if (err != srtp_err_status_ok) {
    DIE("couldn't init", 0);
  }

  // Set IV
  err = srtp_aes_gcm_nss_set_iv(c->state, nonce, srtp_direction_encrypt);
  if (err != srtp_err_status_ok) {
    DIE("couldn't set iv", 0);
  }

  // Set AAD
  err = srtp_aes_gcm_nss_set_aad(c->state, aad, 4);
  if (err != srtp_err_status_ok) {
    DIE("couldn't set aad", 0);
  }

  uint32_t enc_len = 4;
  print_buf("original", data, enc_len);

  // Encrypt
  err = srtp_aes_gcm_nss_encrypt(c->state, data, &enc_len);
  if (err != srtp_err_status_ok) {
    DIE("couldn't encrypt", 0);
  }

  print_buf("ciphertext", data, enc_len);

  // Read tag into the end of the encryption buffer
  uint32_t tag_len = 0;
  err = srtp_aes_gcm_nss_get_tag(c->state, data + enc_len, &tag_len);
  if (err != srtp_err_status_ok) {
    DIE("couldn't get tag", 0);
  }

  print_buf("ciphertext+tag", data, enc_len + tag_len);

  // Decrypt
  uint32_t dec_len = enc_len + tag_len;
  err = srtp_aes_gcm_nss_decrypt(c->state, data, &dec_len);
  if (err != srtp_err_status_ok) {
    DIE("couldn't decrypt", 0);
  }

  print_buf("plaintext", data, dec_len);

  // Dealloc
  err = srtp_aes_gcm_nss_dealloc(c);
  if (err != srtp_err_status_ok) {
    DIE("couldn't dealloc", 0);
  }

  return 0;
}
