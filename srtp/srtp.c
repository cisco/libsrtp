/*
 * srtp.c
 *
 * the secure real-time transport protocol
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 *
 */
/*
 *	
 * Copyright (c) 2001-2006, Cisco Systems, Inc.
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

#include "srtp.h"
#include "srtp_priv.h"
#include "crypto_types.h"
#include "err.h"
#include "ekt.h"             /* for SRTP Encrypted Key Transport */
#include "alloc.h"           /* for srtp_crypto_alloc()          */
#ifdef OPENSSL
#include "aes_gcm_ossl.h"    /* for AES GCM mode  */
# ifdef OPENSSL_KDF
# include <openssl/kdf.h>
# include "aes_icm_ossl.h"    /* for AES GCM mode  */
# endif
#endif

#include <limits.h>
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#elif defined(HAVE_WINSOCK2_H)
# include <winsock2.h>
#endif

/* the debug module for srtp */

srtp_debug_module_t mod_srtp = {
  0,                  /* debugging is off by default */
  "srtp"              /* printable name for module   */
};

#define octets_in_rtp_header   12
#define uint32s_in_rtp_header  3
#define octets_in_rtcp_header  8
#define uint32s_in_rtcp_header 2
#define octets_in_rtp_extn_hdr 4

static srtp_err_status_t
srtp_validate_rtp_header(void *rtp_hdr, int *pkt_octet_len) {
  srtp_hdr_t *hdr = (srtp_hdr_t *)rtp_hdr;
  srtp_hdr_xtnd_t *xtn_hdr = NULL;

  /* Check to ensure minimal header length */
  if (*pkt_octet_len < octets_in_rtp_header)
    return srtp_err_status_bad_param;

  /* Check RTP header length */
  int rtp_header_len = octets_in_rtp_header + 4 * hdr->cc;
  if (hdr->x == 1)
    rtp_header_len += octets_in_rtp_extn_hdr;

  /* Verifing profile length. */
  if (hdr->x == 1) {
    xtn_hdr =
      (srtp_hdr_xtnd_t *)((uint32_t *)hdr + uint32s_in_rtp_header + hdr->cc);
    int profile_len = ntohs(xtn_hdr->length);
    rtp_header_len += profile_len * 4;
    /* profile length counts the number of 32-bit words */
    if (*pkt_octet_len < rtp_header_len)
      return srtp_err_status_bad_param;
  }
  return srtp_err_status_ok;
}

const char *srtp_get_version_string ()
{
    /*
     * Simply return the autotools generated string
     */
    return SRTP_VER_STRING;
}

unsigned int srtp_get_version ()
{
    unsigned int major = 0, minor = 0, micro = 0;
    unsigned int rv = 0;
    int parse_rv;

    /*
     * Parse the autotools generated version 
     */
    parse_rv = sscanf(SRTP_VERSION, "%u.%u.%u", &major, &minor, &micro);
    if (parse_rv != 3) {
	/*
	 * We're expected to parse all 3 version levels.
	 * If not, then this must not be an official release.
	 * Return all zeros on the version
	 */
	return (0);
    }

    /* 
     * We allow 8 bits for the major and minor, while
     * allowing 16 bits for the micro.  16 bits for the micro
     * may be beneficial for a continuous delivery model 
     * in the future.
     */
    rv |= (major & 0xFF) << 24;
    rv |= (minor & 0xFF) << 16;
    rv |= micro & 0xFF;
    return rv;
}

/* Release (maybe partially allocated) stream. */
static void
srtp_stream_free(srtp_stream_ctx_t *str) {
  if (str->rtp_xtn_hdr_cipher) {
    srtp_cipher_dealloc(str->rtp_xtn_hdr_cipher);
  }
  if (str->enc_xtn_hdr) {
    srtp_crypto_free(str->enc_xtn_hdr);
  }
  if (str->rtcp_auth) {
    auth_dealloc(str->rtcp_auth);
  }
  if (str->rtcp_cipher) {
    srtp_cipher_dealloc(str->rtcp_cipher);
  }
  if (str->limit) {
    srtp_crypto_free(str->limit);
  }
  if (str->rtp_auth) {
    auth_dealloc(str->rtp_auth);
  }
  if (str->rtp_cipher) {
    srtp_cipher_dealloc(str->rtp_cipher);
  }
  srtp_crypto_free(str);
}

srtp_err_status_t
srtp_stream_alloc(srtp_stream_ctx_t **str_ptr,
                  const srtp_policy_t *p,
                  const srtp_ekt_mode_t ekt_mode) {
  srtp_stream_ctx_t *str;
  srtp_err_status_t stat;
  const srtp_crypto_policy_t *rtp, *rtcp;

  /*
   * This function allocates the stream context, rtp and rtcp ciphers
   * and auth functions, and key limit structure.  If there is a
   * failure during allocation, we free all previously allocated
   * memory and return a failure code.  The code could probably 
   * be improved, but it works and should be clear.
   */

  /* allocate srtp stream and set str_ptr */
  str = (srtp_stream_ctx_t *) srtp_crypto_alloc(sizeof(srtp_stream_ctx_t));
  if (str == NULL)
    return srtp_err_status_alloc_fail;

  memset(str, 0, sizeof(srtp_stream_ctx_t));
  *str_ptr = str;

  /* Initialize the ekt mode for the stream */
  str->ektMode = ekt_mode;

  /* Set RTP and RTCP ciphers to crypto config inside the ekt_policy */
  if (ekt_mode == ekt_mode_prime_end_to_end) {
    rtp = &(p->ekt_policy.prime_end_to_end_rtp_crypto);
    rtcp = &(p->ekt_policy.prime_end_to_end_rtcp_crypto);
  }
  else {
    rtp = &(p->rtp);
    rtcp = &(p->rtcp);
  }
  
  /* allocate cipher */
  stat = srtp_crypto_kernel_alloc_cipher(rtp->cipher_type,
                                         &str->rtp_cipher,
                                         rtp->cipher_key_len,
                                         rtp->auth_tag_len);

  if (stat) {
    srtp_stream_free(str);
    return stat;
  }

  /* allocate auth function */
  stat = srtp_crypto_kernel_alloc_auth(rtp->auth_type,
                                       &str->rtp_auth,
                                       rtp->auth_key_len,
                                       rtp->auth_tag_len);

  if (stat) {
    srtp_stream_free(str);
    return stat;
  }
  
  /* allocate key limit structure */
  str->limit = (srtp_key_limit_ctx_t*) srtp_crypto_alloc(sizeof(srtp_key_limit_ctx_t));
  if (str->limit == NULL) {
    srtp_stream_free(str);
    return srtp_err_status_alloc_fail;
  }

  /*
   * ...and now the RTCP-specific initialization - first, allocate
   * the cipher 
   */
  stat = srtp_crypto_kernel_alloc_cipher(rtcp->cipher_type,
                                         &str->rtcp_cipher,
                                         rtcp->cipher_key_len,
                                         rtcp->auth_tag_len);

  if (stat) {
    srtp_stream_free(str);
    return stat;
  }

  /* allocate auth function */
  stat = srtp_crypto_kernel_alloc_auth(rtcp->auth_type,
                                       &str->rtcp_auth,
                                       rtcp->auth_key_len,
                                       rtcp->auth_tag_len);
  if (stat) {
    srtp_stream_free(str);
    return stat;
  }  

  if (p->enc_xtn_hdr && p->enc_xtn_hdr_count > 0) {
    srtp_cipher_type_id_t enc_xtn_hdr_cipher_type;
    int enc_xtn_hdr_cipher_key_len;

    str->enc_xtn_hdr = (int*) srtp_crypto_alloc(p->enc_xtn_hdr_count * sizeof(p->enc_xtn_hdr[0]));
    if (!str->enc_xtn_hdr) {
      srtp_stream_free(str);
      return srtp_err_status_alloc_fail;
    }
    memcpy(str->enc_xtn_hdr, p->enc_xtn_hdr, p->enc_xtn_hdr_count * sizeof(p->enc_xtn_hdr[0]));
    str->enc_xtn_hdr_count = p->enc_xtn_hdr_count;

    /*
     * For GCM ciphers, the corresponding ICM cipher is used for header
     * extensions encryption.
     */
    switch (p->rtp.cipher_type) {
    case SRTP_AES_128_GCM:
      enc_xtn_hdr_cipher_type = SRTP_AES_128_ICM;
      enc_xtn_hdr_cipher_key_len = 30;
      break;
    case SRTP_AES_256_GCM:
      enc_xtn_hdr_cipher_type = SRTP_AES_256_ICM;
      enc_xtn_hdr_cipher_key_len = 46;
      break;
    default:
      enc_xtn_hdr_cipher_type = p->rtp.cipher_type;
      enc_xtn_hdr_cipher_key_len = p->rtp.cipher_key_len;
      break;
    }

    /* allocate cipher for extension header encryption */
    stat = srtp_crypto_kernel_alloc_cipher(enc_xtn_hdr_cipher_type,
              &str->rtp_xtn_hdr_cipher,
              enc_xtn_hdr_cipher_key_len,
              0);
    if (stat) {
      srtp_stream_free(str);
      return stat;
    }
  } else {
    str->rtp_xtn_hdr_cipher = NULL;
    str->enc_xtn_hdr = NULL;
    str->enc_xtn_hdr_count = 0;
  }

  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_stream_dealloc(srtp_stream_ctx_t *stream, srtp_stream_ctx_t *stream_template) {
  srtp_err_status_t status;
  
  /*
   * we use a conservative deallocation strategy - if any deallocation
   * fails, then we report that fact without trying to deallocate
   * anything else
   */

  /* deallocate cipher, if it is not the same as that in template */
  if (stream_template
      && stream->rtp_cipher == stream_template->rtp_cipher) {
    /* do nothing */
  } else {
    status = srtp_cipher_dealloc(stream->rtp_cipher); 
    if (status) 
      return status;
  }

  /* deallocate auth function, if it is not the same as that in template */
  if (stream_template
      && stream->rtp_auth == stream_template->rtp_auth) {
    /* do nothing */
  } else {
    status = auth_dealloc(stream->rtp_auth);
    if (status)
      return status;
  }

  /* deallocate key usage limit, if it is not the same as that in template */
  if (stream_template
      && stream->limit == stream_template->limit) {
    /* do nothing */
  } else {
    srtp_crypto_free(stream->limit);
  }   

  if (stream_template
      && stream->rtp_xtn_hdr_cipher == stream_template->rtp_xtn_hdr_cipher) {
    /* do nothing */
  } else if (stream->rtp_xtn_hdr_cipher) {
    status = srtp_cipher_dealloc(stream->rtp_xtn_hdr_cipher);
    if (status)
      return status;
  }

  /* 
   * deallocate rtcp cipher, if it is not the same as that in
   * template 
   */
  if (stream_template
      && stream->rtcp_cipher == stream_template->rtcp_cipher) {
    /* do nothing */
  } else {
    status = srtp_cipher_dealloc(stream->rtcp_cipher); 
    if (status) 
      return status;
  }

  /*
   * deallocate rtcp auth function, if it is not the same as that in
   * template 
   */
  if (stream_template
      && stream->rtcp_auth == stream_template->rtcp_auth) {
    /* do nothing */
  } else {
    status = auth_dealloc(stream->rtcp_auth);
    if (status)
      return status;
  }

  status = srtp_rdbx_dealloc(&stream->rtp_rdbx);
  if (status)
    return status;

  /* DAM - need to deallocate EKT here */

  if (stream_template
      && stream->enc_xtn_hdr == stream_template->enc_xtn_hdr) {
    /* do nothing */
  } else if (stream->enc_xtn_hdr) {
    srtp_crypto_free(stream->enc_xtn_hdr);
  }

  /*
   * zeroize the salt value
   */
  memset(stream->salt, 0, SRTP_AEAD_SALT_LEN);
  memset(stream->c_salt, 0, SRTP_AEAD_SALT_LEN);

  
  /* deallocate srtp stream context */
  srtp_crypto_free(stream);

  return srtp_err_status_ok;
}


/*
 * srtp_stream_clone(stream_template, new) allocates a new stream and
 * initializes it using the cipher and auth of the stream_template
 * 
 * the only unique data in a cloned stream is the replay database and
 * the SSRC
 */

srtp_err_status_t
srtp_stream_clone(const srtp_stream_ctx_t *stream_template, 
		  uint32_t ssrc, 
		  srtp_stream_ctx_t **str_ptr) {
  srtp_err_status_t status;
  srtp_stream_ctx_t *str;
  int key_len;

  debug_print(mod_srtp, "cloning stream (SSRC: 0x%08x)", ssrc);

  /* allocate srtp stream and set str_ptr */
  str = (srtp_stream_ctx_t *) srtp_crypto_alloc(sizeof(srtp_stream_ctx_t));
  if (str == NULL)
    return srtp_err_status_alloc_fail;
  *str_ptr = str;  

  /* set cipher and auth pointers to those of the template */
  str->rtp_cipher = stream_template->rtp_cipher;
  str->rtp_auth = stream_template->rtp_auth;
  str->rtp_xtn_hdr_cipher = stream_template->rtp_xtn_hdr_cipher;
  str->rtcp_cipher = stream_template->rtcp_cipher;
  str->rtcp_auth = stream_template->rtcp_auth;

  /* copy the salt values */
  memcpy(str->salt, stream_template->salt, SRTP_AEAD_SALT_LEN);
  memcpy(str->c_salt, stream_template->c_salt, SRTP_AEAD_SALT_LEN);

  /* copy master key copy as provided by the application */
  key_len = srtp_cipher_get_key_length(str->rtp_cipher);
  memcpy(str->master_key, stream_template->master_key, key_len);

  /* set key limit to point to that of the template */
  status = srtp_key_limit_clone(stream_template->limit, &str->limit);
  if (status) {
      srtp_crypto_free(*str_ptr);
      *str_ptr = NULL;
      return status;
  }

  /* initialize replay databases */
  status = srtp_rdbx_init(&str->rtp_rdbx,
		     srtp_rdbx_get_window_size(&stream_template->rtp_rdbx));
  if (status) {
    srtp_crypto_free(*str_ptr);
    *str_ptr = NULL;
    return status;
  }
  srtp_rdb_init(&str->rtcp_rdb);
  str->allow_repeat_tx = stream_template->allow_repeat_tx;
  str->ektMode = stream_template->ektMode;
  
  /* set ssrc to that provided */
  str->ssrc = ssrc;

  /* set direction and security services */
  str->direction     = stream_template->direction;
  str->rtp_services  = stream_template->rtp_services;
  str->rtcp_services = stream_template->rtcp_services;

  /* set pointer to EKT data associated with stream */
  str->ekt_data = stream_template->ekt_data;
  str->prime_end_to_end_stream_ctx = NULL;

  if (stream_template->ektMode == ekt_mode_prime_hop_by_hop &&
      stream_template->prime_end_to_end_stream_ctx != NULL) {
    /* clone end-to-end data for stream */
    status = srtp_stream_clone(stream_template->prime_end_to_end_stream_ctx,
                               ssrc,
                               &str->prime_end_to_end_stream_ctx);
    if (status) {
      return status;
    }
    /* Assign the replay database for EKT tag generation */
    str->prime_end_to_end_stream_ctx->rtp_rdbx_prime = &str->rtp_rdbx;
  }

  /* copy information about extension header encryption */
  str->enc_xtn_hdr = stream_template->enc_xtn_hdr;
  str->enc_xtn_hdr_count = stream_template->enc_xtn_hdr_count;

  /* defensive coding */
  str->next = NULL;

  return srtp_err_status_ok;
}


/*
 * key derivation functions, internal to libSRTP
 *
 * srtp_kdf_t is a key derivation context
 *
 * srtp_kdf_init(&kdf, cipher_id, k, keylen) initializes kdf to use cipher
 * described by cipher_id, with the master key k with length in octets keylen.
 * 
 * srtp_kdf_generate(&kdf, l, kl, keylen) derives the key
 * corresponding to label l and puts it into kl; the length
 * of the key in octets is provided as keylen.  this function
 * should be called once for each subkey that is derived.
 *
 * srtp_kdf_clear(&kdf) zeroizes and deallocates the kdf state
 */

typedef enum {
  label_rtp_encryption  = 0x00,
  label_rtp_msg_auth    = 0x01,
  label_rtp_salt        = 0x02,
  label_rtcp_encryption = 0x03,
  label_rtcp_msg_auth   = 0x04,
  label_rtcp_salt       = 0x05,
  label_rtp_header_encryption = 0x06,
  label_rtp_header_salt = 0x07
} srtp_prf_label;

#if defined(OPENSSL) && defined(OPENSSL_KDF)
#define MAX_SRTP_AESKEY_LEN 32
#define MAX_SRTP_SALT_LEN 14 

/*
 * srtp_kdf_t represents a key derivation function.  The SRTP
 * default KDF is the only one implemented at present.
 */
typedef struct { 
    uint8_t master_key[MAX_SRTP_AESKEY_LEN];
    uint8_t master_salt[MAX_SRTP_SALT_LEN];
    const EVP_CIPHER *evp;
} srtp_kdf_t;


static srtp_err_status_t srtp_kdf_init(srtp_kdf_t *kdf, const uint8_t *key, int key_len, int salt_len) 
{
    memset(kdf, 0x0, sizeof(srtp_kdf_t));

    /* The NULL cipher has zero key length */
    if (key_len == 0) return srtp_err_status_ok;

    if ((key_len > MAX_SRTP_AESKEY_LEN) || (salt_len > MAX_SRTP_SALT_LEN)) {
        return srtp_err_status_bad_param;
    }
    switch (key_len) {
    case SRTP_AES_256_KEYSIZE:
        kdf->evp = EVP_aes_256_ctr();
        break;
    case SRTP_AES_192_KEYSIZE:
        kdf->evp = EVP_aes_192_ctr();
        break;
    case SRTP_AES_128_KEYSIZE:
        kdf->evp = EVP_aes_128_ctr();
        break;
    default:
        return srtp_err_status_bad_param;
        break;
    }
    memcpy(kdf->master_key, key, key_len); 
    memcpy(kdf->master_salt, key+key_len, salt_len); 
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_generate(srtp_kdf_t *kdf, srtp_prf_label label, uint8_t *key, unsigned int length) 
{
    int ret;

    /* The NULL cipher will not have an EVP */
    if (!kdf->evp) return srtp_err_status_ok;

    octet_string_set_to_zero(key, length);

    /*
     * Invoke the OpenSSL SRTP KDF function
     * This is useful if OpenSSL is in FIPS mode and FIP
     * compliance is required for SRTP.
     */
    ret = kdf_srtp(kdf->evp, (char *)&kdf->master_key, (char *)&kdf->master_salt, NULL, NULL, label, (char *)key);
    if (ret == -1) {
        return (srtp_err_status_algo_fail);
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_clear(srtp_kdf_t *kdf) {
    memset(kdf->master_key, 0x0, MAX_SRTP_AESKEY_LEN);
    memset(kdf->master_salt, 0x0, MAX_SRTP_SALT_LEN);
    kdf->evp = NULL;

    return srtp_err_status_ok;  
}

#else /* if OPENSSL_KDF */

/*
 * srtp_kdf_t represents a key derivation function.  The SRTP
 * default KDF is the only one implemented at present.
 */
typedef struct { 
    srtp_cipher_t *cipher;    /* cipher used for key derivation  */  
} srtp_kdf_t;

static srtp_err_status_t srtp_kdf_init(srtp_kdf_t *kdf, srtp_cipher_type_id_t cipher_id, const uint8_t *key, int length) 
{
    srtp_err_status_t stat;
    stat = srtp_crypto_kernel_alloc_cipher(cipher_id, &kdf->cipher, length, 0);
    if (stat) return stat;

    stat = srtp_cipher_init(kdf->cipher, key);
    if (stat) {
        srtp_cipher_dealloc(kdf->cipher);
        return stat;
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_generate(srtp_kdf_t *kdf, srtp_prf_label label, uint8_t *key, unsigned int length) 
{
    srtp_err_status_t status;
    v128_t nonce;
  
    /* set eigth octet of nonce to <label>, set the rest of it to zero */
    v128_set_to_zero(&nonce);
    nonce.v8[7] = label;
 
    status = srtp_cipher_set_iv(kdf->cipher, (uint8_t*)&nonce, direction_encrypt);
    if (status) return status;
  
    /* generate keystream output */
    octet_string_set_to_zero(key, length);
    status = srtp_cipher_encrypt(kdf->cipher, key, &length);
    if (status) return status;

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_clear(srtp_kdf_t *kdf) {
    srtp_err_status_t status;
    status = srtp_cipher_dealloc(kdf->cipher);
    if (status) return status;
    kdf->cipher = NULL;
    return srtp_err_status_ok;  
}
#endif /* else OPENSSL_KDF */

/*
 *  end of key derivation functions 
 */



/* Get the base key length corresponding to a given combined key+salt
 * length for the given cipher.
 * Assumption is that for AES-ICM a key length < 30 is Ismacryp using
 * AES-128 and short salts; everything else uses a salt length of 14.
 * TODO: key and salt lengths should be separate fields in the policy.  */
inline int base_key_length(const srtp_cipher_type_t *cipher, int key_length)
{
  switch (cipher->id) {
  case SRTP_AES_128_ICM:
  case SRTP_AES_192_ICM:
  case SRTP_AES_256_ICM:
    /* The legacy modes are derived from
     * the configured key length on the policy */
    return key_length - 14;
    break;
  case SRTP_AES_128_GCM:
    return 16;
    break;
  case SRTP_AES_256_GCM:
    return 32;
    break;
  default:
    return key_length;
    break;
  }
}

srtp_err_status_t
srtp_stream_init_keys(srtp_stream_ctx_t *srtp, const void *key) {
  srtp_err_status_t stat;
  srtp_kdf_t kdf;
  uint8_t tmp_key[MAX_SRTP_KEY_LEN];
  int kdf_keylen = 30, rtp_keylen, rtcp_keylen;
  int rtp_base_key_len, rtp_salt_len;
  int rtcp_base_key_len, rtcp_salt_len;

  /* If RTP or RTCP have a key length > AES-128, assume matching kdf. */
  /* TODO: kdf algorithm, master key length, and master salt length should
   * be part of srtp_policy_t. */
  rtp_keylen = srtp_cipher_get_key_length(srtp->rtp_cipher);
  rtcp_keylen = srtp_cipher_get_key_length(srtp->rtcp_cipher);
  rtp_base_key_len = base_key_length(srtp->rtp_cipher->type, rtp_keylen);
  rtp_salt_len = rtp_keylen - rtp_base_key_len;

  if (rtp_keylen > kdf_keylen) {
    kdf_keylen = 46;  /* AES-CTR mode is always used for KDF */
  }

  if (rtcp_keylen > kdf_keylen) {
    kdf_keylen = 46;  /* AES-CTR mode is always used for KDF */
  }

  debug_print(mod_srtp, "srtp key len: %d", rtp_keylen);
  debug_print(mod_srtp, "srtcp key len: %d", rtcp_keylen);
  debug_print(mod_srtp, "base key len: %d", rtp_base_key_len);
  debug_print(mod_srtp, "kdf key len: %d", kdf_keylen);
  debug_print(mod_srtp, "rtp salt len: %d", rtp_salt_len);

  /* 
   * Make sure the key given to us is 'zero' appended.  GCM
   * mode uses a shorter master SALT (96 bits), but still relies on 
   * the legacy CTR mode KDF, which uses a 112 bit master SALT.
   */
  memset(tmp_key, 0x0, MAX_SRTP_KEY_LEN);
  memcpy(tmp_key, key, (rtp_base_key_len + rtp_salt_len));

  /* initialize KDF state     */
#if defined(OPENSSL) && defined(OPENSSL_KDF)
  stat = srtp_kdf_init(&kdf, (const uint8_t *)tmp_key, rtp_base_key_len, rtp_salt_len); 
#else
  stat = srtp_kdf_init(&kdf, SRTP_AES_ICM, (const uint8_t *)tmp_key, kdf_keylen);
#endif
  if (stat) {
    return srtp_err_status_init_fail;
  }
  
  /* generate encryption key  */
  stat = srtp_kdf_generate(&kdf, label_rtp_encryption, 
			   tmp_key, rtp_base_key_len);
  if (stat) {
    /* zeroize temp buffer */
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    return srtp_err_status_init_fail;
  }
  debug_print(mod_srtp, "cipher key: %s", 
	      srtp_octet_string_hex_string(tmp_key, rtp_base_key_len));

  /* 
   * if the cipher in the srtp context uses a salt, then we need
   * to generate the salt value
   */
  if (rtp_salt_len > 0) {
    debug_print(mod_srtp, "found rtp_salt_len > 0, generating salt", NULL);

    /* generate encryption salt, put after encryption key */
    stat = srtp_kdf_generate(&kdf, label_rtp_salt, 
			     tmp_key + rtp_base_key_len, rtp_salt_len);
    if (stat) {
      /* zeroize temp buffer */
      octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
      return srtp_err_status_init_fail;
    }
    memcpy(srtp->salt, tmp_key + rtp_base_key_len, SRTP_AEAD_SALT_LEN);
  }
  if (rtp_salt_len > 0) {
    debug_print(mod_srtp, "cipher salt: %s",
		srtp_octet_string_hex_string(tmp_key + rtp_base_key_len, rtp_salt_len));
  }

  /* initialize cipher */
  stat = srtp_cipher_init(srtp->rtp_cipher, tmp_key);
  if (stat) {
    /* zeroize temp buffer */
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    return srtp_err_status_init_fail;
  }

  if (srtp->rtp_xtn_hdr_cipher) {
    /* generate extension header encryption key  */
    int rtp_xtn_hdr_keylen;
    int rtp_xtn_hdr_base_key_len;
    int rtp_xtn_hdr_salt_len;
    srtp_kdf_t tmp_kdf;
    srtp_kdf_t *xtn_hdr_kdf;

    if (srtp->rtp_xtn_hdr_cipher->type != srtp->rtp_cipher->type) {
      /*
       * With GCM ciphers, the header extensions are still encrypted using the
       * corresponding ICM cipher as per RFC 7714.  Specifically, see:
       * https://tools.ietf.org/html/rfc7714#section-8.3
       */
      uint8_t tmp_xtn_hdr_key[MAX_SRTP_KEY_LEN];
      rtp_xtn_hdr_keylen = srtp_cipher_get_key_length(srtp->rtp_xtn_hdr_cipher);
      rtp_xtn_hdr_base_key_len = base_key_length(srtp->rtp_xtn_hdr_cipher->type, rtp_xtn_hdr_keylen);
      rtp_xtn_hdr_salt_len = rtp_xtn_hdr_keylen - rtp_xtn_hdr_base_key_len;
      memset(tmp_xtn_hdr_key, 0x0, MAX_SRTP_KEY_LEN);
      memcpy(tmp_xtn_hdr_key, key, (rtp_xtn_hdr_base_key_len + rtp_xtn_hdr_salt_len));
      xtn_hdr_kdf = &tmp_kdf;

      /* initialize KDF state     */
#if defined(OPENSSL) && defined(OPENSSL_KDF)
      stat = srtp_kdf_init(xtn_hdr_kdf, (const uint8_t *)tmp_xtn_hdr_key, rtp_xtn_hdr_base_key_len, rtp_xtn_hdr_salt_len);
#else
      stat = srtp_kdf_init(xtn_hdr_kdf, SRTP_AES_ICM, (const uint8_t *)tmp_xtn_hdr_key, kdf_keylen);
#endif
      octet_string_set_to_zero(tmp_xtn_hdr_key, MAX_SRTP_KEY_LEN);
      if (stat) {
        return srtp_err_status_init_fail;
      }
    } else {
      /* Reuse main KDF. */
      rtp_xtn_hdr_keylen = rtp_keylen;
      rtp_xtn_hdr_base_key_len = rtp_base_key_len;
      rtp_xtn_hdr_salt_len = rtp_salt_len;
      xtn_hdr_kdf = &kdf;
    }

    stat = srtp_kdf_generate(xtn_hdr_kdf, label_rtp_header_encryption,
           tmp_key, rtp_xtn_hdr_base_key_len);
    if (stat) {
      /* zeroize temp buffer */
      octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
      return srtp_err_status_init_fail;
    }
    debug_print(mod_srtp, "extensions cipher key: %s",
          srtp_octet_string_hex_string(tmp_key, rtp_xtn_hdr_base_key_len));

    /*
     * if the cipher in the srtp context uses a salt, then we need
     * to generate the salt value
     */
    if (rtp_xtn_hdr_salt_len > 0) {
      debug_print(mod_srtp, "found rtp_xtn_hdr_salt_len > 0, generating salt", NULL);

      /* generate encryption salt, put after encryption key */
      stat = srtp_kdf_generate(xtn_hdr_kdf, label_rtp_header_salt,
             tmp_key + rtp_xtn_hdr_base_key_len, rtp_xtn_hdr_salt_len);
      if (stat) {
        /* zeroize temp buffer */
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
      }
    }
    if (rtp_xtn_hdr_salt_len > 0) {
      debug_print(mod_srtp, "extensions cipher salt: %s",
      srtp_octet_string_hex_string(tmp_key + rtp_xtn_hdr_base_key_len, rtp_xtn_hdr_salt_len));
    }

    /* initialize extension header cipher */
    stat = srtp_cipher_init(srtp->rtp_xtn_hdr_cipher, tmp_key);
    if (stat) {
      /* zeroize temp buffer */
      octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
      return srtp_err_status_init_fail;
    }

    if (xtn_hdr_kdf != &kdf) {
      /* release memory for custom header extension encryption kdf */
      stat = srtp_kdf_clear(xtn_hdr_kdf);
      if (stat) {
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
      }
    }
  }

  /* generate authentication key */
  stat = srtp_kdf_generate(&kdf, label_rtp_msg_auth,
			   tmp_key, srtp_auth_get_key_length(srtp->rtp_auth));
  if (stat) {
    /* zeroize temp buffer */
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    return srtp_err_status_init_fail;
  }
  debug_print(mod_srtp, "auth key:   %s",
	      srtp_octet_string_hex_string(tmp_key, 
				      srtp_auth_get_key_length(srtp->rtp_auth))); 

  /* initialize auth function */
  stat = auth_init(srtp->rtp_auth, tmp_key);
  if (stat) {
    /* zeroize temp buffer */
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    return srtp_err_status_init_fail;
  }

  /*
   * ...now initialize SRTCP keys
   */

  rtcp_base_key_len = base_key_length(srtp->rtcp_cipher->type, rtcp_keylen);
  rtcp_salt_len = rtcp_keylen - rtcp_base_key_len;
  debug_print(mod_srtp, "rtcp salt len: %d", rtcp_salt_len);
  
  /* generate encryption key  */
  stat = srtp_kdf_generate(&kdf, label_rtcp_encryption, 
			   tmp_key, rtcp_base_key_len);
  if (stat) {
    /* zeroize temp buffer */
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    return srtp_err_status_init_fail;
  }

  /* 
   * if the cipher in the srtp context uses a salt, then we need
   * to generate the salt value
   */
  if (rtcp_salt_len > 0) {
    debug_print(mod_srtp, "found rtcp_salt_len > 0, generating rtcp salt",
		NULL);

    /* generate encryption salt, put after encryption key */
    stat = srtp_kdf_generate(&kdf, label_rtcp_salt, 
			     tmp_key + rtcp_base_key_len, rtcp_salt_len);
    if (stat) {
      /* zeroize temp buffer */
      octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
      return srtp_err_status_init_fail;
    }
    memcpy(srtp->c_salt, tmp_key + rtcp_base_key_len, SRTP_AEAD_SALT_LEN);
  }
  debug_print(mod_srtp, "rtcp cipher key: %s", 
	      srtp_octet_string_hex_string(tmp_key, rtcp_base_key_len));  
  if (rtcp_salt_len > 0) {
    debug_print(mod_srtp, "rtcp cipher salt: %s",
		srtp_octet_string_hex_string(tmp_key + rtcp_base_key_len, rtcp_salt_len));
  }

  /* initialize cipher */
  stat = srtp_cipher_init(srtp->rtcp_cipher, tmp_key);
  if (stat) {
    /* zeroize temp buffer */
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    return srtp_err_status_init_fail;
  }

  /* generate authentication key */
  stat = srtp_kdf_generate(&kdf, label_rtcp_msg_auth,
			   tmp_key, srtp_auth_get_key_length(srtp->rtcp_auth));
  if (stat) {
    /* zeroize temp buffer */
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    return srtp_err_status_init_fail;
  }

  debug_print(mod_srtp, "rtcp auth key:   %s",
	      srtp_octet_string_hex_string(tmp_key, 
		     srtp_auth_get_key_length(srtp->rtcp_auth))); 

  /* initialize auth function */
  stat = auth_init(srtp->rtcp_auth, tmp_key);
  if (stat) {
    /* zeroize temp buffer */
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    return srtp_err_status_init_fail;
  }

  /* clear memory then return */
  stat = srtp_kdf_clear(&kdf);
  octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);  
  if (stat)
    return srtp_err_status_init_fail;

  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_set_iv(void *hdr,
            srtp_cipher_t *cipher,
            srtp_xtd_seq_num_t est,
            direction_t direction,
            srtp_packet_type_t packetType)
{
    v128_t iv;

    if (cipher == NULL)
        return srtp_err_status_cipher_fail;

    /*
     * if we're using rindael counter mode, set nonce and seq
     */
    if (cipher->type->id == SRTP_AES_ICM ||
        cipher->type->id == SRTP_AES_256_ICM) {

        iv.v32[0] = 0;
        if (packetType == srtp_packet_rtcp)
        {
            srtcp_hdr_t *srtcp_hdr = (srtcp_hdr_t *)hdr;
            iv.v32[1] = srtcp_hdr->ssrc;

            uint32_t seq_num = (uint32_t)est;
            iv.v32[2] = htonl(seq_num >> 16);
            iv.v32[3] = htonl(seq_num << 16);
        }
        else {
            srtp_hdr_t *srtp_hdr = (srtp_hdr_t*)hdr;
            iv.v32[1] = srtp_hdr->ssrc;

#ifdef NO_64BIT_MATH
            iv.v64[1] = be64_to_cpu(
                            make64((high32(est) << 16) | (low32(est) >> 16),
                            low32(est) << 16));
#else
            iv.v64[1] = be64_to_cpu(est << 16);
#endif

        }
    }
    else {
        iv.v32[0] = 0;
        iv.v32[1] = 0;
        iv.v32[2] = 0;
        if (packetType == srtp_packet_rtcp)
        {
            uint32_t seq_num = (uint32_t)est;
            iv.v32[3] = htonl(seq_num);
        }
        else
        {
            /* otherwise, set the index to est */
            iv.v64[1] = be64_to_cpu(est);
        }
    }

    return (srtp_cipher_set_iv(cipher, (uint8_t*)&iv, direction));
}

srtp_err_status_t
srtp_generate_authentication_tag(srtp_stream_ctx_t *stream,
                                 uint8_t *hdr,
                                 int* pkt_octet_len,
                                 srtp_xtd_seq_num_t est,
                                 srtp_packet_type_t packetType)
{
    uint8_t *auth_start;        /* pointer to start of auth. portion      */
    int tag_len;
    uint32_t prefix_len;
    uint8_t *auth_tag = NULL;   /* location of auth_tag within packet     */
    srtp_cipher_t  *cipher;
    srtp_auth_t    *auth;
    srtp_sec_serv_t services;
    srtp_err_status_t status;

    if (packetType == srtp_packet_rtp) {
        cipher = stream->rtp_cipher;
        services = stream->rtp_services;
        auth = stream->rtp_auth;
        auth_tag = (uint8_t *)hdr + *pkt_octet_len;
    }
    else
    {
        cipher = stream->rtcp_cipher;
        services = stream->rtcp_services;
        auth = stream->rtcp_auth;
        auth_tag = (uint8_t *)hdr + *pkt_octet_len;
    }

    /* get tag length from stream */
    tag_len = srtp_auth_get_tag_length(auth);

    /*
     * If we're providing authentication, set the auth_start and auth_tag
     * pointers to the proper locations; otherwise, set auth_start to NULL
     * to indicate that no authentication is needed
     */
    if (services & sec_serv_auth) {
        auth_start = hdr;
    }
    else {
        return srtp_err_status_ok;
    }

    /*
     * if we're authenticating using a universal hash, put the keystream
     * prefix into the authentication tag
     */
    prefix_len = srtp_auth_get_prefix_length(auth);
    if (prefix_len) {
        status = srtp_cipher_output(cipher, auth_tag, &prefix_len);
        if (status)
            return srtp_err_status_cipher_fail;
        debug_print(mod_srtp, "keystream prefix: %s",
                    srtp_octet_string_hex_string(auth_tag, prefix_len));
    }

    /*
     *  if we're authenticating, run authentication function and put result
     *  into the auth_tag
     */

    /* First initialize auth func context */
    status = auth_start(auth);
    if (status) return status;

    /*
     * If RTP then authenticate the packet concatenated with ROC
     * If RTCP then just authenticate the entire packet
     */
    if (packetType == srtp_packet_rtp) {
        /* run auth func over packet */
        status = auth_update(auth, (uint8_t *)auth_start, *pkt_octet_len);
        if (status) return status;

        /* run auth func over ROC, put result into auth_tag */
        debug_print(mod_srtp, "estimated packet index: %016llx", est);
        status = auth_compute(auth, (uint8_t *)&est, 4, auth_tag);
        debug_print(mod_srtp, "srtp auth tag:    %s",
                    srtp_octet_string_hex_string(auth_tag, tag_len));
    }
    else {
        status = auth_compute(auth,
                              (uint8_t *)auth_start,
                              *pkt_octet_len, auth_tag);
    }

    if (status)
        return srtp_err_status_auth_fail;

    /* increase the packet length by the length of the auth tag */
    *pkt_octet_len += tag_len;

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_estimate_index(srtp_rdbx_t *rdbx,
                    uint32_t roc,
                    srtp_xtd_seq_num_t *est,
                    srtp_sequence_number_t seq,
                    int *delta)
{
#ifdef NO_64BIT_MATH
    uint32_t internal_pkt_idx_reduced;
    uint32_t external_pkt_idx_reduced;
    uint32_t internal_roc;
    uint32_t roc_difference;
#endif

#ifdef NO_64BIT_MATH
    *est = (srtp_xtd_seq_num_t)make64(roc >> 16, (roc << 16) | seq);
    *delta = low32(est) - rdbx->index;
#else
    *est = (srtp_xtd_seq_num_t)(((uint64_t)roc) << 16) | seq;
    *delta = (int)(*est - rdbx->index);
#endif

    if (*est > rdbx->index) {
#ifdef NO_64BIT_MATH
        internal_roc = (uint32_t)(rdbx->index >> 16);
        roc_difference = roc - internal_roc;
        if (roc_difference > 1)
        {
            *delta = 0;
            return srtp_err_status_pkt_idx_adv;
        }

        internal_pkt_idx_reduced = (uint32_t)(rdbx->index & 0xFFFF);
        external_pkt_idx_reduced = (uint32_t)((roc_difference << 16) | seq);

        if (external_pkt_idx_reduced - internal_pkt_idx_reduced >
                                                        seq_num_median) {
            *delta = 0;
            return srtp_err_status_pkt_idx_adv;
        }
#else
        if (*est - rdbx->index > seq_num_median) {
            *delta = 0;
            return srtp_err_status_pkt_idx_adv;
        }
#endif
    }
    else if (*est < rdbx->index) {
#ifdef NO_64BIT_MATH

        internal_roc = (uint32_t)(rdbx->index >> 16);
        roc_difference = internal_roc - roc;
        if (roc_difference > 1)
        {
            *delta = 0;
            return srtp_err_status_pkt_idx_adv;
        }

        internal_pkt_idx_reduced =
                    (uint32_t)((roc_difference << 16) | rdbx->index & 0xFFFF);
        external_pkt_idx_reduced = (uint32_t)(seq);

        if (internal_pkt_idx_reduced - external_pkt_idx_reduced >
                                                        seq_num_median) {
            *delta = 0;
            return srtp_err_status_pkt_idx_old;
        }
#else
        if (rdbx->index - *est > seq_num_median) {
            *delta = 0;
            return srtp_err_status_pkt_idx_old;
        }
#endif
    }

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_get_est_pkt_index(srtp_hdr_t *hdr,
                       int *pkt_octet_len,
                       srtp_stream_ctx_t *stream,
                       srtp_xtd_seq_num_t *est,
                       int *delta,
                       ekt_tag_contents_t *ekt_tag_contents,
                       srtp_service_flags_t flags)
{
    uint32_t roc;
    int primeEKTTagPresent = 0;
    srtp_ekt_spi_t spi = 0;
    int auth_tag_length;
    srtp_err_status_t result = srtp_err_status_ok;

    roc = 0;

    /*
     * If the stream is configured to use PRIME then the far end could have
     * sent an updated ROC in the packet which needs to be used. Therefore
     * extract ROC from the packet.
     */
    if (stream->ektMode == ekt_mode_prime_hop_by_hop) {
        if (flags & srtp_service_prime_hbh) {
            /* Get the auth tag length and sanity check length */
            auth_tag_length = srtp_auth_get_tag_length(stream->rtp_auth);
            if ((*pkt_octet_len - auth_tag_length - sizeof(srtp_ekt_spi_t)) <=
                octets_in_rtp_header) {
                return srtp_err_status_bad_param;
            }
        } else {
            /*
             * If not performing PRIME HBH operations, the auth tag must
             * be removed already, so set the auth tag length to 0.
             */
            auth_tag_length = 0;
        }

        /* Retrieve the SPI */
        spi = srtp_packet_get_ekt_spi((const uint8_t *)hdr,
                                      (*pkt_octet_len-auth_tag_length));

        /* Check if full EKT tag is present */
        primeEKTTagPresent = spi & 0x0001;

        /* If full EKT tag is present then retrieve the ROC */
        if (primeEKTTagPresent) {
            roc = srtp_packet_get_roc((void *)hdr,
                (unsigned int)(*pkt_octet_len - auth_tag_length -
                               sizeof(srtp_ekt_spi_t)));
        }
    }
    else if (stream->ektMode == ekt_mode_regular) {
        if (ekt_tag_contents->present) {
            roc = ekt_tag_contents->roc;
        }
    }

    /*
     * If ROC is present in the packet then use it estimate the index
     * regardless of whether we have seen this SSRC before or not.
     * If it's a new SSRC never seen and there is no ROC in the pkt
     * then estimate index with ROC set to zero.
     */
    if (primeEKTTagPresent || ekt_tag_contents->present) {
        result = srtp_estimate_index(&stream->rtp_rdbx,
                                     roc,
                                     est,
                                     ntohs(hdr->seq),
                                     delta);
    }
    else {
        /* estimate packet index from seq. num. in header */
        *delta = srtp_rdbx_estimate_index(&stream->rtp_rdbx,
                                          est,
                                          ntohs(hdr->seq));
    }

#ifdef NO_64BIT_MATH
    debug_print2(mod_srtp, "estimated u_packet index: %08x%08x", high32(*est), low32(*est));
#else
    debug_print(mod_srtp, "estimated u_packet index: %016llx", *est);
#endif
    return result;
}

/*
 * Check if the given extension header id is / should be encrypted.
 * Returns 1 if yes, otherwise 0.
 */
static int
srtp_protect_extension_header(srtp_stream_ctx_t *stream, int id) {
  int* enc_xtn_hdr = stream->enc_xtn_hdr;
  int count = stream->enc_xtn_hdr_count;

  if (!enc_xtn_hdr || count <= 0) {
    return 0;
  }

  while (count > 0) {
    if (*enc_xtn_hdr == id) {
      return 1;
    }

    enc_xtn_hdr++;
    count--;
  }
  return 0;
}

/*
 * extension header encryption RFC 6904
 */
static srtp_err_status_t
srtp_process_header_encryption(srtp_stream_ctx_t *stream, srtp_hdr_xtnd_t *xtn_hdr) {
  srtp_err_status_t status;
  uint8_t keystream[257];  /* Maximum 2 bytes header + 255 bytes data. */
  int keystream_pos;
  uint8_t* xtn_hdr_data = ((uint8_t *)xtn_hdr) + octets_in_rtp_extn_hdr;
  uint8_t* xtn_hdr_end = xtn_hdr_data + (ntohs(xtn_hdr->length) * sizeof(uint32_t));

  if (ntohs(xtn_hdr->profile_specific) == 0xbede) {
    /* RFC 5285, section 4.2. One-Byte Header */
    while (xtn_hdr_data < xtn_hdr_end) {
      uint8_t xid = (*xtn_hdr_data & 0xf0) >> 4;
      unsigned int xlen = (*xtn_hdr_data & 0x0f) + 1;
      uint32_t xlen_with_header = 1+xlen;
      xtn_hdr_data++;

      if (xtn_hdr_data + xlen > xtn_hdr_end)
        return srtp_err_status_parse_err;

      if (xid == 15) {
        /* found header 15, stop further processing. */
        break;
      }

      status = srtp_cipher_output(stream->rtp_xtn_hdr_cipher, keystream, &xlen_with_header);
      if (status)
        return srtp_err_status_cipher_fail;

      if (srtp_protect_extension_header(stream, xid)) {
        keystream_pos = 1;
        while (xlen > 0) {
          *xtn_hdr_data ^= keystream[keystream_pos++];
          xtn_hdr_data++;
          xlen--;
        }
      } else {
        xtn_hdr_data += xlen;
      }

      /* skip padding bytes. */
      while (xtn_hdr_data < xtn_hdr_end && *xtn_hdr_data == 0) {
        xtn_hdr_data++;
      }
    }
  } else if ((ntohs(xtn_hdr->profile_specific) & 0x1fff) == 0x100) {
    /* RFC 5285, section 4.3. Two-Byte Header */
    while (xtn_hdr_data + 1 < xtn_hdr_end) {
      uint8_t xid = *xtn_hdr_data;
      unsigned int xlen = *(xtn_hdr_data+1);
      uint32_t xlen_with_header = 2+xlen;
      xtn_hdr_data += 2;

      if (xtn_hdr_data + xlen > xtn_hdr_end)
        return srtp_err_status_parse_err;

      status = srtp_cipher_output(stream->rtp_xtn_hdr_cipher, keystream, &xlen_with_header);
      if (status)
        return srtp_err_status_cipher_fail;

      if (xlen > 0 && srtp_protect_extension_header(stream, xid)) {
        keystream_pos = 2;
        while (xlen > 0) {
          *xtn_hdr_data ^= keystream[keystream_pos++];
          xtn_hdr_data++;
          xlen--;
        }
      } else {
        xtn_hdr_data += xlen;
      }

      /* skip padding bytes. */
      while (xtn_hdr_data < xtn_hdr_end && *xtn_hdr_data == 0) {
        xtn_hdr_data++;
      }
    }
  } else {
    /* unsupported extension header format. */
    return srtp_err_status_parse_err;
  }

  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_encrypt(srtp_stream_ctx_t *stream,
             void *hdr,
             int pkt_octet_len,
             srtp_packet_type_t packetType)
{
    uint32_t *enc_start = NULL;     /* pointer to start of encrypted portion  */
    int enc_octet_len = 0;          /* number of octets in encrypted portion  */
    srtp_cipher_t *cipher;
    srtp_hdr_xtnd_t *xtn_hdr = NULL;
    srtp_err_status_t status;

    /*
     * find starting point for encryption and length of data to be encrypted
     * if we're not providing confidentiality, set enc_start to NULL
     */
    if (packetType == srtp_packet_rtp && stream->rtp_services & sec_serv_conf) {

        srtp_hdr_t *rtp_hdr = (srtp_hdr_t*)hdr;

        /*
         * the encrypted portion starts after the rtp header
         * extension, if present; otherwise, it starts after the last csrc,
         * if any are present
         */
        enc_start = (uint32_t *)hdr + uint32s_in_rtp_header + rtp_hdr->cc;
        if (rtp_hdr->x == 1) {
            xtn_hdr = (srtp_hdr_xtnd_t *)enc_start;
            enc_start += (ntohs(xtn_hdr->length) + 1);
        }

        /* note: the passed size is without the auth tag */
        if (!((uint8_t*)enc_start <= (uint8_t*)hdr + pkt_octet_len))
            return srtp_err_status_parse_err;

        enc_octet_len = (int)(pkt_octet_len -
                             ((uint8_t*)enc_start - (uint8_t*)hdr));

        if (enc_octet_len < 0) return srtp_err_status_parse_err;

        /* extension header encryption RFC 6904 */
        if (xtn_hdr && stream->rtp_xtn_hdr_cipher) {
            status = srtp_process_header_encryption(stream, xtn_hdr);
            if (status) {
                return status;
            }
        }

        cipher = stream->rtp_cipher;
    }
    else if (packetType == srtp_packet_rtcp &&
             stream->rtcp_services & sec_serv_conf) {

        enc_start = (uint32_t *)hdr + uint32s_in_rtcp_header;
        enc_octet_len = pkt_octet_len - octets_in_rtcp_header;

        cipher = stream->rtcp_cipher;
    }
    else {
        return srtp_err_status_ok;
    }

    /* if we're encrypting, exor keystream into the message */
    if (enc_start) {
        status = srtp_cipher_encrypt(cipher,
                                     (uint8_t *)enc_start,
                                     (unsigned int *)&enc_octet_len);
        if (status)
            return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_ekt_set_spi_info(srtp_t srtp_ctx,
                      srtp_ekt_spi_policy_t *spi_info)
{
    srtp_ekt_spi_info_t *prevSpi, *nextSpi, *currSpi;
    
    /*
     * allocate memory for spi info and initialize it.
     */
    currSpi =
        (srtp_ekt_spi_info_t *) srtp_crypto_alloc(sizeof(srtp_ekt_spi_info_t));
    if (currSpi == NULL)
        return srtp_err_status_alloc_fail;

    currSpi->ekt_cipher = spi_info->ekt_cipher;

    memcpy(currSpi->ekt_key, spi_info->ekt_key, srtp_get_ekt_cipher_key_length(spi_info->ekt_cipher));
    memcpy((currSpi->ekt_key) + srtp_get_ekt_cipher_key_length(spi_info->ekt_cipher), spi_info->ekt_master_salt, spi_info->ekt_master_salt_length);
    memcpy(currSpi->ekt_salt, spi_info->ekt_master_salt, spi_info->ekt_master_salt_length);
    currSpi->ekt_salt_length = spi_info->ekt_master_salt_length;
    currSpi->spi = spi_info->spi;
    currSpi->next = NULL;

    /*
     * Find the position in the list to insert the node.
     */
    prevSpi = srtp_ctx->spi_info;
    nextSpi = srtp_ctx->spi_info;

    while (nextSpi != NULL) {
        if (nextSpi->spi >= currSpi->spi)
            break;
        prevSpi = nextSpi;
        nextSpi = nextSpi->next;
    }

    /* If we need to insert before the first node or the list is empty */
    if (nextSpi == prevSpi) {
        currSpi->next = srtp_ctx->spi_info;
        srtp_ctx->spi_info = currSpi;
        return srtp_err_status_ok;
    }

    currSpi->next = prevSpi->next;
    prevSpi->next = currSpi;

    /*
     * If we are trying to change info for spi which already exists
     * then we overwrite the node and delete existing entry.
     */
    if (currSpi->spi == nextSpi->spi) {
        currSpi->next = nextSpi->next;
        srtp_crypto_free(nextSpi);
    }

    return srtp_err_status_ok;
}

void srtp_ekt_init_from_policy(srtp_ekt_policy_t *policy,
                               srtp_ekt_data_t *ekt_data)
{
    ekt_data->auto_ekt_packet_interval =
        policy->packet_interval_for_auto_ekt;
    ekt_data->packets_left_to_generate_auto_ekt =
        ekt_data->auto_ekt_packet_interval;
    ekt_data->spi =
        policy->spi;
    ekt_data->total_ekt_tags_to_generate_after_rollover =
        policy->total_auto_ekt_tags_at_roc_change;
    ekt_data->auto_ekt_pkts_left =
        policy->total_auto_ekt_tags_at_roc_change;
}

srtp_err_status_t
srtp_stream_init(srtp_stream_t srtp,
                 const srtp_policy_t *p) {
  srtp_err_status_t err;

  debug_print(mod_srtp, "initializing stream (SSRC: 0x%08x)",
              p->ssrc.value);

  /* initialize replay database */
  /* window size MUST be at least 64.  MAY be larger.  Values more than
   * 2^15 aren't meaningful due to how extended sequence numbers are
   * calculated.   Let a window size of 0 imply the default value. */

  if (p->window_size != 0 && (p->window_size < 64 || p->window_size >= 0x8000))
      return srtp_err_status_bad_param;

  if (p->window_size != 0)
      err = srtp_rdbx_init(&srtp->rtp_rdbx, p->window_size);
  else
      err = srtp_rdbx_init(&srtp->rtp_rdbx, 128);
  if (err) return err;

  /* initialize key limit to maximum value */
#ifdef NO_64BIT_MATH
  {
    uint64_t temp;
    temp = make64(UINT_MAX,UINT_MAX);
    srtp_key_limit_set(srtp->limit, temp);
  }
#else
  srtp_key_limit_set(srtp->limit, 0xffffffffffffLL);
#endif

  /* set the SSRC value */
  srtp->ssrc = htonl(p->ssrc.value);
  srtp->next = NULL;

  /* set the security service flags */
  if (srtp->ektMode == ekt_mode_prime_end_to_end) {
    srtp->rtp_services = p->ekt_policy.prime_end_to_end_rtp_crypto.sec_serv;
    srtp->rtcp_services = p->ekt_policy.prime_end_to_end_rtcp_crypto.sec_serv;
  }
  else {
    srtp->rtp_services = p->rtp.sec_serv;
    srtp->rtcp_services = p->rtcp.sec_serv;
  }

  /*
   * set direction to unknown - this flag gets checked in srtp_protect(),
   * srtp_unprotect(), srtp_protect_rtcp(), and srtp_unprotect_rtcp(), and
   * gets set appropriately if it is set to unknown.
   */
  srtp->direction = dir_unknown;

  /* initialize SRTCP replay database */
  srtp_rdb_init(&srtp->rtcp_rdb);

  /* initialize allow_repeat_tx */
  /* guard against uninitialized memory: allow only 0 or 1 here */
  if (p->allow_repeat_tx != 0 && p->allow_repeat_tx != 1) {
    srtp_rdbx_dealloc(&srtp->rtp_rdbx);
    return srtp_err_status_bad_param;
  }
  srtp->allow_repeat_tx = p->allow_repeat_tx;

  /* DAM - no RTCP key limit at present */

  /* Initialize the EKT data */
  if (srtp->ektMode == ekt_mode_prime_end_to_end ||
      srtp->ektMode == ekt_mode_regular)
      srtp_ekt_init_from_policy((srtp_ekt_policy_t *)(&(p->ekt_policy)),
                                &srtp->ekt_data);

  /* Initialize the keys.*/
  err = srtp_stream_init_keys(srtp, srtp->master_key);
  if (err) {
    srtp_rdbx_dealloc(&srtp->rtp_rdbx);
    return err;
  }

  return srtp_err_status_ok;
}


 /*
  * srtp_event_reporter is an event handler function that merely
  * reports the events that are reported by the callbacks
  */
 void
 srtp_event_reporter(srtp_event_data_t *data) {

   srtp_err_report(srtp_err_level_warning, "srtp: in stream 0x%x: ", 
	      data->stream->ssrc);

   switch(data->event) {
   case event_ssrc_collision:
     srtp_err_report(srtp_err_level_warning, "\tSSRC collision\n");
     break;
   case event_key_soft_limit:
     srtp_err_report(srtp_err_level_warning, "\tkey usage soft limit reached\n");
     break;
   case event_key_hard_limit:
     srtp_err_report(srtp_err_level_warning, "\tkey usage hard limit reached\n");
     break;
   case event_packet_index_limit:
     srtp_err_report(srtp_err_level_warning, "\tpacket index limit reached\n");
     break;
   default:
     srtp_err_report(srtp_err_level_warning, "\tunknown event reported to handler\n");
   }
 }

 /*
  * srtp_event_handler is a global variable holding a pointer to the
  * event handler function; this function is called for any unexpected
  * event that needs to be handled out of the SRTP data path.  see
  * srtp_event_t in srtp.h for more info
  *
  * it is okay to set srtp_event_handler to NULL, but we set 
  * it to the srtp_event_reporter.
  */

 static srtp_event_handler_func_t *srtp_event_handler = srtp_event_reporter;

 srtp_err_status_t
 srtp_install_event_handler(srtp_event_handler_func_t func) {

   /* 
    * note that we accept NULL arguments intentionally - calling this
    * function with a NULL arguments removes an event handler that's
    * been previously installed
    */

   /* set global event handling function */
   srtp_event_handler = func;
   return srtp_err_status_ok;
 }


/*
 * AEAD uses a new IV formation method.  This function implements
 * section 9.1 from draft-ietf-avtcore-srtp-aes-gcm-07.txt.  The
 * calculation is defined as, where (+) is the xor operation:
 *
 *
 *              0  0  0  0  0  0  0  0  0  0  1  1
 *              0  1  2  3  4  5  6  7  8  9  0  1
 *            +--+--+--+--+--+--+--+--+--+--+--+--+
 *            |00|00|    SSRC   |     ROC   | SEQ |---+
 *            +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *                                                    |
 *            +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *            |         Encryption Salt           |->(+)
 *            +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *                                                    |
 *            +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *            |       Initialization Vector       |<--+
 *            +--+--+--+--+--+--+--+--+--+--+--+--+*
 *
 * Input:  *stream - pointer to SRTP stream context, used to retrieve
 *                   the SALT 
 *         *iv     - Pointer to receive the calculated IV
 *         *seq    - The ROC and SEQ value to use for the
 *                   IV calculation.
 *         *hdr    - The RTP header, used to get the SSRC value
 *
 */
static void srtp_calc_aead_iv(srtp_stream_ctx_t *stream, v128_t *iv, 
	                      srtp_xtd_seq_num_t *seq, srtp_hdr_t *hdr)
{
    v128_t	in;
    v128_t	salt;

#ifdef NO_64BIT_MATH
    uint32_t local_roc = ((high32(*seq) << 16) |
                         (low32(*seq) >> 16));
    uint16_t local_seq = (uint16_t) (low32(*seq));
#else
    uint32_t local_roc = (uint32_t)(*seq >> 16);
    uint16_t local_seq = (uint16_t) *seq;
#endif

    memset(&in, 0, sizeof(v128_t));
    memset(&salt, 0, sizeof(v128_t));

    in.v16[5] = htons(local_seq);
    local_roc = htonl(local_roc);
    memcpy(&in.v16[3], &local_roc, sizeof(local_roc));

    /*
     * Copy in the RTP SSRC value
     */
    memcpy(&in.v8[2], &hdr->ssrc, 4);
    debug_print(mod_srtp, "Pre-salted RTP IV = %s\n", v128_hex_string(&in));

    /*
     * Get the SALT value from the context
     */
    memcpy(salt.v8, stream->salt, SRTP_AEAD_SALT_LEN);
    debug_print(mod_srtp, "RTP SALT = %s\n", v128_hex_string(&salt));

    /*
     * Finally, apply tyhe SALT to the input
     */
    v128_xor(iv, &in, &salt);
}


/*
 * This function handles outgoing SRTP packets while in AEAD mode,
 * which currently supports AES-GCM encryption.  All packets are
 * encrypted and authenticated.
 */
static srtp_err_status_t
srtp_protect_aead (srtp_ctx_t *ctx, srtp_stream_ctx_t *stream, void *rtp_hdr,
                   srtp_xtd_seq_num_t est, unsigned int *pkt_octet_len)
{
    srtp_hdr_t *hdr = (srtp_hdr_t*)rtp_hdr;
    uint32_t *enc_start;        /* pointer to start of encrypted portion  */
    int enc_octet_len = 0; /* number of octets in encrypted portion  */
    srtp_err_status_t status;
    uint32_t tag_len;
    v128_t iv;
    unsigned int aad_len;
    srtp_hdr_xtnd_t *xtn_hdr = NULL;

    debug_print(mod_srtp, "function srtp_protect_aead", NULL);

    /*
     * update the key usage limit, and check it to make sure that we
     * didn't just hit either the soft limit or the hard limit, and call
     * the event handler if we hit either.
     */
    switch (srtp_key_limit_update(stream->limit)) {
    case srtp_key_event_normal:
        break;
    case srtp_key_event_hard_limit:
        srtp_handle_event(ctx, stream, event_key_hard_limit);
        return srtp_err_status_key_expired;
    case srtp_key_event_soft_limit:
    default:
        srtp_handle_event(ctx, stream, event_key_soft_limit);
        break;
    }

    /* get tag length from stream */
    tag_len = srtp_auth_get_tag_length(stream->rtp_auth);

    /*
     * find starting point for encryption and length of data to be
     * encrypted - the encrypted portion starts after the rtp header
     * extension, if present; otherwise, it starts after the last csrc,
     * if any are present
     */
     enc_start = (uint32_t*)hdr + uint32s_in_rtp_header + hdr->cc;
     if (hdr->x == 1) {
         xtn_hdr = (srtp_hdr_xtnd_t*)enc_start;
         enc_start += (ntohs(xtn_hdr->length) + 1);
     }

     /* note: the passed size is without the auth tag */
     if (!((uint8_t*)enc_start <= (uint8_t*)hdr + *pkt_octet_len))
         return srtp_err_status_parse_err;
     enc_octet_len = (int)(*pkt_octet_len -
                                    ((uint8_t*)enc_start - (uint8_t*)hdr));
     if (enc_octet_len < 0) return srtp_err_status_parse_err;

    /*
     * AEAD uses a new IV formation method
     */
    srtp_calc_aead_iv(stream, &iv, &est, hdr);

    status = srtp_cipher_set_iv(stream->rtp_cipher, (uint8_t*)&iv, direction_encrypt);
    if (!status && stream->rtp_xtn_hdr_cipher) {
        status = srtp_set_iv(hdr,
                             stream->rtp_xtn_hdr_cipher,
                             est,
                             direction_encrypt,
                             srtp_packet_rtp);
    }
    if (status)
        return srtp_err_status_cipher_fail;

    if (xtn_hdr && stream->rtp_xtn_hdr_cipher) {
        /*
         * extension header encryption RFC 6904
         */
        status = srtp_process_header_encryption(stream, xtn_hdr);
        if (status)
            return status;
    }

    /*
     * Set the AAD over the RTP header 
     */
    aad_len = (uint8_t *)enc_start - (uint8_t *)hdr;

    /* Depending on PRIME mode or not, set the AAD accordingly */
    if (stream->ektMode == ekt_mode_prime_end_to_end)
    {
        unsigned int rtp_header_aad_len = octets_in_rtp_header;
        uint8_t prime_hdr[octets_in_rtp_header];
        srtp_hdr_t *prime_hdr_ptr;

        /*
        * Set the AAD over the RTP header (12 octets), but only authenticate
        * include a subset of the header fields (with the rest set to zero).
        * This is a deviation from draft-ietf-avtcore-srtp-aes-gcm to
        * allow intermediaries to modify select fields.
        */
        if (aad_len >= rtp_header_aad_len) {
            aad_len = rtp_header_aad_len;
        }
        else {
            return srtp_err_status_cipher_fail;
        }

        /* Zero out the header we will use as AAD */
        memset(prime_hdr, 0, aad_len);

        /* Assign the fields we want to authenticate */
        prime_hdr_ptr = (srtp_hdr_t *)prime_hdr;
        prime_hdr_ptr->version = hdr->version;
        prime_hdr_ptr->ssrc = hdr->ssrc;
        prime_hdr_ptr->seq = hdr->seq;

        status = srtp_cipher_set_aad(stream->rtp_cipher,
                                     prime_hdr,
                                     aad_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    }
    else
    {
        status = srtp_cipher_set_aad(stream->rtp_cipher,
                                     (uint8_t*)hdr,
                                     aad_len);
        if (status) {
            return (srtp_err_status_cipher_fail);
        }
    }

    /* Encrypt the payload  */
    status = srtp_cipher_encrypt(stream->rtp_cipher,
                            (uint8_t*)enc_start, (unsigned int *)&enc_octet_len);
    if (status) {
        return srtp_err_status_cipher_fail;
    }
    /*
     * If we're doing GCM, we need to get the tag
     * and append that to the output
     */
    status = srtp_cipher_get_tag(stream->rtp_cipher, 
                            (uint8_t*)enc_start+enc_octet_len, &tag_len);
    if (status) {
	return ( srtp_err_status_cipher_fail);
    }

    /* increase the packet length by the length of the auth tag */
    *pkt_octet_len += tag_len;

    return srtp_err_status_ok;
}


/*
 * This function handles incoming SRTP packets while in AEAD mode,
 * which currently supports AES-GCM encryption.  All packets are
 * encrypted and authenticated.  Note, the auth tag is at the end
 * of the packet stream and is automatically checked by GCM
 * when decrypting the payload.
 */
static srtp_err_status_t
srtp_unprotect_aead (srtp_ctx_t *ctx, srtp_stream_ctx_t *stream,
                     srtp_xtd_seq_num_t est, void *srtp_hdr,
                     unsigned int *pkt_octet_len)
{
    srtp_hdr_t *hdr = (srtp_hdr_t*)srtp_hdr;
    uint32_t *enc_start;        /* pointer to start of encrypted portion  */
    int enc_octet_len = 0;      /* number of octets in encrypted portion */
    v128_t iv;
    srtp_err_status_t status;
    int tag_len;
    unsigned int aad_len;
    srtp_hdr_xtnd_t *xtn_hdr = NULL;

    debug_print(mod_srtp, "function srtp_unprotect_aead", NULL);

#ifdef NO_64BIT_MATH
    debug_print2(mod_srtp, "estimated u_packet index: %08x%08x", high32(est), low32(est));
#else
    debug_print(mod_srtp, "estimated u_packet index: %016llx", est);
#endif

    /* get tag length from stream */
    tag_len = srtp_auth_get_tag_length(stream->rtp_auth);

    /*
     * AEAD uses a new IV formation method 
     */
    srtp_calc_aead_iv(stream, &iv, &est, hdr);
    status = srtp_cipher_set_iv(stream->rtp_cipher, (uint8_t*)&iv, direction_decrypt);
    if (!status && stream->rtp_xtn_hdr_cipher) {
        status = srtp_set_iv(hdr,
                             stream->rtp_xtn_hdr_cipher,
                             est,
                             direction_encrypt,
                             srtp_packet_rtp);
    }
    if (status)
        return srtp_err_status_cipher_fail;

    /*
     * find starting point for decryption and length of data to be
     * decrypted - the encrypted portion starts after the rtp header
     * extension, if present; otherwise, it starts after the last csrc,
     * if any are present
     */
    enc_start = (uint32_t*)hdr + uint32s_in_rtp_header + hdr->cc;
    if (hdr->x == 1) {
        xtn_hdr = (srtp_hdr_xtnd_t*)enc_start;
        enc_start += (ntohs(xtn_hdr->length) + 1);
    }

    /* note: the passed size is with the auth tag */
    if (!((uint8_t*)enc_start <= (uint8_t*)hdr + (*pkt_octet_len - tag_len)))
        return srtp_err_status_parse_err;
    /*
     * We pass the tag down to the cipher when doing GCM mode 
     */
    enc_octet_len = (unsigned int)(*pkt_octet_len - 
                                   ((uint8_t*)enc_start - (uint8_t*)hdr));

    /*
     * Sanity check the encrypted payload length against
     * the tag size.  It must always be at least as large
     * as the tag length.
     */
    if (enc_octet_len < (unsigned int) tag_len) {
        return srtp_err_status_cipher_fail;
    }

    /*
     * update the key usage limit, and check it to make sure that we
     * didn't just hit either the soft limit or the hard limit, and call
     * the event handler if we hit either.
     */
    switch (srtp_key_limit_update(stream->limit)) {
    case srtp_key_event_normal:
        break;
    case srtp_key_event_soft_limit:
        srtp_handle_event(ctx, stream, event_key_soft_limit);
        break;
    case srtp_key_event_hard_limit:
        srtp_handle_event(ctx, stream, event_key_hard_limit);
        return srtp_err_status_key_expired;
    default:
        break;
    }

    /*
     * Set the AAD for AES-GCM, which is the RTP header
     */
    aad_len = (uint8_t *)enc_start - (uint8_t *)hdr;

    /* Depending on PRIME mode or not, set the AAD accordingly */
    if (stream->ektMode == ekt_mode_prime_end_to_end)
    {
        unsigned int rtp_header_aad_len = octets_in_rtp_header;
        uint8_t prime_hdr[octets_in_rtp_header];
        srtp_hdr_t *prime_hdr_ptr;

        /*
        * Set the AAD over the RTP header (12 octets), but only authenticate
        * include a subset of the header fields (with the rest set to zero).
        * This is a deviation from draft-ietf-avtcore-srtp-aes-gcm to
        * allow intermediaries to modify select fields.
        */
        if (aad_len >= rtp_header_aad_len) {
            aad_len = rtp_header_aad_len;
        }
        else {
            return srtp_err_status_cipher_fail;
        }

        /* Zero out the header we will use as AAD */
        memset(prime_hdr, 0, aad_len);

        /* Assign the fields we want to authenticate E2E */
        prime_hdr_ptr = (srtp_hdr_t *)prime_hdr;
        prime_hdr_ptr->version = hdr->version;
        prime_hdr_ptr->ssrc = hdr->ssrc;
        prime_hdr_ptr->seq = hdr->seq;

        status = srtp_cipher_set_aad(stream->rtp_cipher,
                                     prime_hdr,
                                     aad_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    }
    else
    {
        status = srtp_cipher_set_aad(stream->rtp_cipher,
                                     (uint8_t*)hdr,
                                     aad_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    }

    /* Decrypt the ciphertext.  This also checks the auth tag based
     * on the AAD we just specified above */
    status = srtp_cipher_decrypt(stream->rtp_cipher,
                                 (uint8_t*)enc_start,
                                 (uint32_t *)&enc_octet_len);
    if (status) {
        return status;
    }

    if (xtn_hdr && stream->rtp_xtn_hdr_cipher) {
      /*
       * extension header encryption RFC 6904
       */
      status = srtp_process_header_encryption(stream, xtn_hdr);
      if (status) {
        return status;
      }
    }

    /*
     * verify that stream is for received traffic - this check will
     * detect SSRC collisions, since a stream that appears in both
     * srtp_protect() and srtp_unprotect() will fail this test in one of
     * those functions.
     *
     * we do this check *after* the authentication check, so that the
     * latter check will catch any attempts to fool us into thinking
     * that we've got a collision
     */
    if (stream->direction != dir_srtp_receiver) {
        if (stream->direction == dir_unknown) {
            stream->direction = dir_srtp_receiver;
        } else {
            srtp_handle_event(ctx, stream, event_ssrc_collision);
        }
    }

    /* decrease the packet length by the length of the auth tag */
    *pkt_octet_len -= tag_len;

    return srtp_err_status_ok;
}


srtp_err_status_t
srtp_process_protect(srtp_ctx_t *ctx,
                     void *hdr,
                     int *pkt_octet_len,
                     srtp_stream_ctx_t *stream,
                     srtp_xtd_seq_num_t est,
                     srtp_service_flags_t flags) {
    uint8_t *ektp;
    unsigned int ekt_tag_len = 0;
    srtp_err_status_t status;

    debug_print(mod_srtp, "function srtp_protect", NULL);

    /*
     * Check if this is an AEAD stream (GCM mode).  If so, then dispatch
     * the request to our AEAD handler.
     */
    if (stream->rtp_cipher->algorithm == SRTP_AES_128_GCM ||
        stream->rtp_cipher->algorithm == SRTP_AES_256_GCM) {
        status = srtp_protect_aead(ctx,
                                   stream,
                                   hdr,
                                   est,
                                   (unsigned int*) pkt_octet_len);
        if (status != srtp_err_status_ok)
            return status;
        /*
         * Set EKT pointer to the end of the packet.
         * Add EKT tag to the packet if EKT mode is regular or end-to-end
         */
        ektp = (uint8_t *)hdr + *pkt_octet_len;
        if (stream->ektMode == ekt_mode_regular ||
            stream->ektMode == ekt_mode_prime_end_to_end) {
            status = ekt_generate_tag(stream,
                                      ctx,
                                      hdr,
                                      ektp,
                                      &ekt_tag_len,
                                      flags);
            if (status != srtp_err_status_ok)
                return status;
            *pkt_octet_len += ekt_tag_len;
        }
        return srtp_err_status_ok;
    }

    /*
     * update the key usage limit, and check it to make sure that we
     * didn't just hit either the soft limit or the hard limit, and call
     * the event handler if we hit either.
     */
    switch (srtp_key_limit_update(stream->limit)) {
    case srtp_key_event_normal:
        break;
    case srtp_key_event_soft_limit:
        srtp_handle_event(ctx, stream, event_key_soft_limit);
        break;
    case srtp_key_event_hard_limit:
        srtp_handle_event(ctx, stream, event_key_hard_limit);
        return srtp_err_status_key_expired;
    default:
        break;
    }

    /*
     * Set the iv in the cipher before we encrypt and/or generate
     * authentication tag.
     */
    status = srtp_set_iv(hdr,
                         stream->rtp_cipher,
                         est,
                         direction_encrypt,
                         srtp_packet_rtp);
    if (!status && stream->rtp_xtn_hdr_cipher) {
        status = srtp_set_iv(hdr,
                             stream->rtp_xtn_hdr_cipher,
                             est,
                             direction_encrypt,
                             srtp_packet_rtp);
    }
    if (status)
        return srtp_err_status_cipher_fail;

    /* shift est, put into network byte order */
#ifdef NO_64BIT_MATH
    est = be64_to_cpu(make64((high32(*est) << 16) |
                             (low32(est) >> 16),
                             low32(est) << 16));
#else
    est = be64_to_cpu(est << 16);
#endif

    /* Encrypt the packet */
    status = srtp_encrypt(stream, hdr, *pkt_octet_len, srtp_packet_rtp);
    if (status != srtp_err_status_ok)
        return status;

    /*
     * Generate authentication tag. For PRIME end-to-end this function will
     * result in no-op because the end-to-end ctx is setup only for
     * confidentiality.
     */
    status = srtp_generate_authentication_tag(stream,
                                              hdr,
                                              pkt_octet_len,
                                              est,
                                              srtp_packet_rtp);
    if (status != srtp_err_status_ok)
        return status;

    /*
     * If this stream uses EKT, insert the EKT Tag if required
     */
    if (stream->ektMode == ekt_mode_regular ||
        stream->ektMode == ekt_mode_prime_end_to_end) {
        ektp = (uint8_t *)hdr + *pkt_octet_len;
        status = ekt_generate_tag(stream, ctx, hdr, ektp, &ekt_tag_len, flags);
        if (status != srtp_err_status_ok)
            return status;
        *pkt_octet_len += ekt_tag_len;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_protect_with_flags(srtp_ctx_t *ctx,
                        void *rtp_hdr,
                        int *pkt_octet_len,
                        srtp_service_flags_t flags) {
    srtp_hdr_t *hdr = (srtp_hdr_t *)rtp_hdr;
    srtp_xtd_seq_num_t est;     /* estimated xtd_seq_num_t of *hdr        */
    int delta;                  /* delta of local pkt idx and that in hdr */
    srtp_err_status_t status;
    srtp_stream_ctx_t *stream;

    debug_print(mod_srtp, "function srtp_protect_with_flags", NULL);

    /* we assume the hdr is 32-bit aligned to start */

    /* Verify RTP header */
    status = srtp_validate_rtp_header(rtp_hdr, pkt_octet_len);
    if (status)
        return status;

    /*
     * look up ssrc in srtp_stream list, and process the packet with
     * the appropriate stream.  if we haven't seen this stream before,
     * there's a template key for this srtp_session, and the cipher
     * supports key-sharing, then we assume that a new stream using
     * that key has just started up
     */
    stream = srtp_get_stream(ctx, hdr->ssrc);
    if (stream == NULL) {
        if (ctx->stream_template != NULL) {
            srtp_stream_ctx_t *new_stream;
            /*
             * If EKT is on then the first packet should have EKT tag.
             * So force generate the EKT tag regardless of what application
             * requested.
             */
            flags |= srtp_service_ekt_tag;

            /* allocate and initialize a new stream */
            status = srtp_stream_clone(ctx->stream_template,
                                       hdr->ssrc, &new_stream);
            if (status)
                return status;

            /* add new stream to the head of the stream_list */
            new_stream->next = ctx->stream_list;
            ctx->stream_list = new_stream;

            /* set direction to outbound */
            new_stream->direction = dir_srtp_sender;

            /* set stream (the pointer used in this function) */
            stream = new_stream;
        }
        else {
            /* no template stream, so we return an error */
            return srtp_err_status_no_ctx;
        }
    }

    /*
     * verify that stream is for sending traffic - this check will
     * detect SSRC collisions, since a stream that appears in both
     * srtp_protect() and srtp_unprotect() will fail this test in one of
     * those functions.
     */
    if (stream->direction != dir_srtp_sender) {
        if (stream->direction == dir_unknown) {
            stream->direction = dir_srtp_sender;
        }
        else {
            srtp_handle_event(ctx, stream, event_ssrc_collision);
        }
    }

    /*
     * estimate the packet index using the start of the replay window
     * and the sequence number from the header
     */
    delta = srtp_rdbx_estimate_index(&stream->rtp_rdbx, &est, ntohs(hdr->seq));

    /* Check for replay if user has requested replay check */
    if (flags & srtp_service_chk_replay) {
        status = srtp_rdbx_check(&stream->rtp_rdbx, delta);
        if (status) {
            if (status != srtp_err_status_replay_fail ||
                !stream->allow_repeat_tx)
                return status;
        } /* We've been asked to reuse an index */
#ifdef NO_64BIT_MATH
        debug_print2(mod_srtp, "estimated packet index: %08x%08x",
                     high32(est), low32(est));
#else
        debug_print(mod_srtp, "estimated packet index: %016llx", est);
#endif
        srtp_rdbx_add_index(&stream->rtp_rdbx, delta);
    }

    /*
     * if the pkt looks good then authenticate and encrypt the packet
     * For PRIME endpoints -  We first encrypt the packet using end-to-end ctx
     * and then we authenticate the packet with hop-by-hop ctx.
     */
    if (stream->ektMode == ekt_mode_prime_hop_by_hop)
    {
        /* Process using end-to-end ctx */
        if (flags & srtp_service_prime_e2e) {
            if (stream->prime_end_to_end_stream_ctx == NULL)
                return srtp_err_status_bad_param;
            status = srtp_process_protect(
                                ctx,
                                rtp_hdr,
                                pkt_octet_len,
                                stream->prime_end_to_end_stream_ctx,
                                est,
                                flags);
            if (status)
                return status;
        }

        /* Process using hop-by-hop ctx */
        if (flags & srtp_service_prime_hbh) {
                status = srtp_process_protect(
                                    ctx,
                                    rtp_hdr,
                                    pkt_octet_len,
                                    stream,
                                    est,
                                    flags);
            if (status)
                return status;
        }
    }
    else
    {
        status = srtp_process_protect(ctx,
                                      rtp_hdr,
                                      pkt_octet_len,
                                      stream,
                                      est,
                                      flags);
        if (status)
            return status;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_protect(srtp_ctx_t *ctx, void *rtp_hdr, int *pkt_octet_len) {

    /*
     * Call the new function which allows users to select operations to be
     * performed during protect
     */
    debug_print(mod_srtp, "function srtp_protect", NULL);

    return (srtp_protect_with_flags(
                            ctx,
                            rtp_hdr,
                            pkt_octet_len,
                            srtp_service_default));

}

srtp_err_status_t
srtp_decrypt(srtp_stream_ctx_t *stream,
             void* pkt_hdr,
             int* pkt_octet_len,
             srtp_packet_type_t packet_type) {
    uint32_t *enc_start = NULL;     /* pointer to start of encrypted portion */
    unsigned int enc_octet_len = 0; /* number of octets in encrypted portion */
    int e_bit_in_packet;        /* whether the E-bit was found in the packet */
    int sec_serv_confidentiality;   /* whether confidentiality was requested */
    uint32_t *trailer;              /* pointer to start of trailer           */
    srtp_err_status_t status;
    srtp_cipher_t *cipher;
    srtp_hdr_xtnd_t *xtn_hdr = NULL;

    if (packet_type == srtp_packet_rtcp) {

        srtcp_hdr_t *hdr = (srtcp_hdr_t *)pkt_hdr;

        /*
         * find starting point for decryption and length of data to be
         * decrypted - the encrypted portion starts after the rtp header
         * extension, if present; otherwise, it starts after the last csrc,
         * if any are present
         *
         * if we're not providing confidentiality, set enc_start to NULL
         */
        sec_serv_confidentiality =
            stream->rtcp_services == sec_serv_conf ||
            stream->rtcp_services == sec_serv_conf_and_auth;
        /*
         * set encryption start, encryption length, and trailer
         */
        enc_octet_len = *pkt_octet_len -
                        (octets_in_rtcp_header + sizeof(srtcp_trailer_t));

        /* index & E (encryption) bit follow normal data.  hdr->len
           is the number of words (32-bit) in the normal packet minus 1 */
        /* This should point trailer to the word past the end of the
           normal data. */
        /* This would need to be modified for optional mikey data */
        /*
         * NOTE: trailer is 32-bit aligned because RTCP 'packets' are always
         *    multiples of 32-bits (RFC 3550 6.1)
         */
        trailer = (uint32_t *)((char *)hdr +
                               *pkt_octet_len - sizeof(srtcp_trailer_t));
        e_bit_in_packet =
            (*((unsigned char *)trailer) & SRTCP_E_BYTE_BIT) == SRTCP_E_BYTE_BIT;
        if (e_bit_in_packet != sec_serv_confidentiality) {
            return srtp_err_status_cant_check;
        }
        if (sec_serv_confidentiality) {
            enc_start = (uint32_t *)hdr + uint32s_in_rtcp_header;
            cipher = stream->rtcp_cipher;
        }
        else {
            return srtp_err_status_ok;
        }
    }
    else if (packet_type == srtp_packet_rtp &&
             (stream->rtp_services & sec_serv_conf)) {
        srtp_hdr_t *hdr = (srtp_hdr_t *)pkt_hdr;
        enc_start = (uint32_t *)hdr + uint32s_in_rtp_header + hdr->cc;
        if (hdr->x == 1) {
            xtn_hdr = (srtp_hdr_xtnd_t *)enc_start;
            enc_start += (ntohs(xtn_hdr->length) + 1);
        }

        /* note: the passed size is without the auth tag */
        if (!((uint8_t*)enc_start <= (uint8_t*)hdr + *pkt_octet_len))
            return srtp_err_status_parse_err;
        enc_octet_len =
            (uint32_t)(*pkt_octet_len - ((uint8_t*)enc_start - (uint8_t*)hdr));
        cipher = stream->rtp_cipher;

        /*
         * extension header encryption RFC 6904
         */
        if (xtn_hdr && stream->rtp_xtn_hdr_cipher) {
            status = srtp_process_header_encryption(stream, xtn_hdr);
            if (status) {
                return status;
            }
        }
    }
    else {
        return srtp_err_status_ok;
    }

    /* if we're decrypting, add keystream into ciphertext */
    if (enc_start) {
        status = srtp_cipher_decrypt(cipher,
                                     (uint8_t *) enc_start,
                                     &enc_octet_len);
        if (status)
            return srtp_err_status_cipher_fail;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_authenticate(srtp_stream_ctx_t *stream,
                  void* hdr,
                  unsigned int* pkt_octet_len,
                  srtp_xtd_seq_num_t est,
                  srtp_packet_type_t packetType)
{
    uint8_t *auth_start;     /* pointer to start of auth. portion      */
    uint8_t *auth_tag = NULL; /* location of auth_tag within packet     */
    unsigned int auth_len;
    srtp_err_status_t status;
    uint32_t tag_len, prefix_len;
    uint8_t tmp_tag[SRTP_MAX_TAG_LEN];
    srtp_cipher_t  *cipher;
    srtp_auth_t    *auth;
    srtp_sec_serv_t services;

    /*
     * Initialize cipher, authentication function, services to be performed etc.
     * if we're providing authentication, set the auth_start and auth_tag
     * pointers to the proper locations; otherwise return without authenticating
     */
    if (packetType == srtp_packet_rtp) {
        cipher = stream->rtp_cipher;
        services = stream->rtp_services;
        auth = stream->rtp_auth;
        tag_len = srtp_auth_get_tag_length(auth);
        auth_tag = (uint8_t *)hdr + *pkt_octet_len - tag_len;
    }
    else
    {
        cipher = stream->rtcp_cipher;
        services = stream->rtcp_services;
        auth = stream->rtcp_auth;
        tag_len = srtp_auth_get_tag_length(auth);
        auth_tag = (uint8_t *)hdr + *pkt_octet_len - tag_len;
    }

    /*
     * If authentication is not requested then return without authenticating.
     */
    if (services & sec_serv_auth) {
        auth_start = (uint8_t *) hdr;
    }
    else {
        return srtp_err_status_ok;
    }

    /* get tag length from stream */
    auth_len = *pkt_octet_len - tag_len;

    /*
     * if we expect message authentication, run the authentication
     * function and compare the result with the value of the auth_tag
     */

    /* initialize auth func context */
    status = auth_start(auth);
    if (status) return status;

    if (packetType == srtp_packet_rtp) {

        /*
         * if we're using a universal hash, then we need to compute the
         * keystream prefix for encrypting the universal hash output
         *
         * if the keystream prefix length is zero, then we know that
         * the authenticator isn't using a universal hash function
         */
        if (auth->prefix_len != 0) {
            prefix_len = srtp_auth_get_prefix_length(auth);
            status = srtp_cipher_output(cipher, tmp_tag, &prefix_len);
            debug_print(mod_srtp,
                        "keystream prefix: %s",
                        srtp_octet_string_hex_string(tmp_tag, prefix_len));
            if (status)
                return srtp_err_status_cipher_fail;
        }

        /* now compute auth function over packet */
        status = auth_update(auth, (uint8_t *)auth_start,
                             *pkt_octet_len - tag_len);

        /* run auth func over ROC, then write tmp tag */
        status = auth_compute(auth, (uint8_t *)&est, 4, tmp_tag);
        debug_print(mod_srtp, "computed auth tag:    %s",
                    srtp_octet_string_hex_string(tmp_tag, tag_len));
        debug_print(mod_srtp, "packet auth tag:      %s",
                    srtp_octet_string_hex_string(auth_tag, tag_len));
        if (status)
            return srtp_err_status_auth_fail;
    }
    else {

        /* run auth func over packet, put result into tmp_tag */
        status = auth_compute(auth, (uint8_t *)auth_start,
                              auth_len, tmp_tag);
        debug_print(mod_srtp, "srtcp computed tag:       %s",
                    srtp_octet_string_hex_string(tmp_tag, tag_len));
        if (status)
            return srtp_err_status_auth_fail;

        /*
         * if we're authenticating using a universal hash, put the keystream
         * prefix into the authentication tag
         */
        prefix_len = srtp_auth_get_prefix_length(stream->rtcp_auth);
        if (prefix_len) {
            status = srtp_cipher_output(stream->rtcp_cipher,
                                        auth_tag,
                                        &prefix_len);
            debug_print(mod_srtp, "keystream prefix: %s",
                        srtp_octet_string_hex_string(auth_tag, prefix_len));
            if (status)
                return srtp_err_status_cipher_fail;
        }
    }

    /* compare the tag just computed with the one in the packet */
    if (octet_string_is_eq(tmp_tag, auth_tag, tag_len))
        return srtp_err_status_auth_fail;

    *pkt_octet_len -= tag_len;

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_process_unprotect(void *srtp_hdr,
                       int *pkt_octet_len,
                       srtp_ctx_t *ctx,
                       srtp_stream_ctx_t *stream,
                       srtp_xtd_seq_num_t est,
                       ekt_tag_contents_t *ekt_tag_contents) {
    uint8_t master_key_in_stream[MAX_SRTP_KEY_LEN];
    int base_key_len = 0;
    int replaced_stream_key;
    srtp_err_status_t status;

    /* Update the key in the context if a new key is received in the EKT tag */
    if (ekt_tag_contents->present) {
        base_key_len =
            base_key_length(stream->rtp_cipher->type,
                            srtp_cipher_get_key_length(stream->rtp_cipher));
        if (memcmp(ekt_tag_contents->master_key,
                   stream->master_key,
                   base_key_len)) {
            status = srtp_stream_init_keys(stream,ekt_tag_contents->master_key);
            if (status != srtp_err_status_ok) {
                srtp_stream_init_keys(stream, stream->master_key);
                return status;
            }
            memcpy(master_key_in_stream, stream->master_key, base_key_len);
            memcpy(stream->master_key,
                   ekt_tag_contents->master_key,
                   base_key_len);
            replaced_stream_key = 1;
        }
        else {
            replaced_stream_key = 0;
            debug_print(mod_srtp,
                "Key update is not needed since same key received in EKT tag\n",
                NULL);
        }
    }
    else {
        replaced_stream_key = 0;
        debug_print(mod_srtp,
                "Key update is not needed since EKT tag is not present\n",
                NULL);
    }

    /*
     * Check if this is an AEAD stream (GCM mode).  If so, then dispatch
     * the request to our AEAD handler. Decryption and authentication will be
     * done simultaneously.
     */
    if (stream->rtp_cipher->algorithm == SRTP_AES_128_GCM ||
        stream->rtp_cipher->algorithm == SRTP_AES_256_GCM) {
        status = srtp_unprotect_aead(ctx,
                                     stream,
                                     est,
                                     srtp_hdr,
                                     (unsigned int*) pkt_octet_len);
        if (status != srtp_err_status_ok) {
            if (replaced_stream_key) {
                memcpy(stream->master_key, master_key_in_stream, base_key_len);
                srtp_stream_init_keys(stream, stream->master_key);
            }
            return status;
        }
    }
    else {

        /*
         * set the cipher's IV properly, depending on whatever cipher we
         * happen to be using
         */
        status = srtp_set_iv(srtp_hdr,
                             stream->rtp_cipher,
                             est,
                             direction_decrypt,
                             srtp_packet_rtp);

        if (!status && stream->rtp_xtn_hdr_cipher) {
            status = srtp_set_iv(srtp_hdr,
                                 stream->rtp_xtn_hdr_cipher,
                                 est,
                                 direction_encrypt,
                                 srtp_packet_rtp);
        }
        if (status) {
            if (replaced_stream_key) {
                memcpy(stream->master_key, master_key_in_stream, base_key_len);
                srtp_stream_init_keys(stream, stream->master_key);
            }
            return srtp_err_status_cipher_fail;
        }

        /* shift est, put into network byte order */
#ifdef NO_64BIT_MATH
        est = be64_to_cpu(make64((high32(est) << 16) |
                                 (low32(est) >> 16),
                                 low32(est) << 16));
#else
        est = be64_to_cpu(est << 16);
#endif

        /* Authenticate the RTP packet */
        status = srtp_authenticate(stream,
                                    srtp_hdr,
                                    (unsigned int*) pkt_octet_len,
                                    est,
                                    srtp_packet_rtp);

        /* If failed authentication then return error */
        if (status != srtp_err_status_ok) {
            if (replaced_stream_key) {
                memcpy(stream->master_key, master_key_in_stream, base_key_len);
                srtp_stream_init_keys(stream, stream->master_key);
            }
            return status;
        }

        /*
         * update the key usage limit, and check it to make sure that we
         * didn't just hit either the soft limit or the hard limit, and call
         * the event handler if we hit either.
         */
        switch (srtp_key_limit_update(stream->limit)) {
        case srtp_key_event_normal:
            break;
        case srtp_key_event_soft_limit:
            srtp_handle_event(ctx, stream, event_key_soft_limit);
            break;
        case srtp_key_event_hard_limit:
            srtp_handle_event(ctx, stream, event_key_hard_limit);
            return srtp_err_status_key_expired;
        default:
            break;
        }

        status = srtp_decrypt(stream,
                              srtp_hdr,
                              pkt_octet_len,
                              srtp_packet_rtp);
        if (status) {
            if (replaced_stream_key) {
                memcpy(stream->master_key, master_key_in_stream, base_key_len);
                srtp_stream_init_keys(stream, stream->master_key);
            }
            return srtp_err_status_cipher_fail;
        }
    }

    /*
     * verify that stream is for received traffic - this check will
     * detect SSRC collisions, since a stream that appears in both
     * srtp_protect() and srtp_unprotect() will fail this test in one of
     * those functions.
     *
     * we do this check *after* the authentication check, so that the
     * latter check will catch any attempts to fool us into thinking
     * that we've got a collision
     */
    if (stream->direction != dir_srtp_receiver) {
        if (stream->direction == dir_unknown) {
            stream->direction = dir_srtp_receiver;
        }
        else {
            srtp_handle_event(ctx, stream, event_ssrc_collision);
        }
    }
    return srtp_err_status_ok;
}


srtp_err_status_t
srtp_unprotect_with_flags(srtp_ctx_t *ctx,
                          void *srtp_hdr,
                          int *pkt_octet_len,
                          srtp_service_flags_t flags) {
    srtp_hdr_t *hdr = (srtp_hdr_t *)srtp_hdr;
    srtp_xtd_seq_num_t est;        /* estimated xtd_seq_num_t of *hdr        */
    int delta;                     /* delta of local pkt idx and that in hdr */
    srtp_err_status_t status;
    srtp_stream_ctx_t *stream;
    int advance_packet_index = 0;
    ekt_tag_contents_t ekt_tag_contents;

    debug_print(mod_srtp, "function srtp_unprotect_with_flags", NULL);

    /* we assume the hdr is 32-bit aligned to start */

    /* Verify RTP header */
    status = srtp_validate_rtp_header(srtp_hdr, pkt_octet_len);
    if (status)
        return status;

    /*
     * look up ssrc in srtp_stream list, and process the packet with
     * the appropriate stream.  if we haven't seen this stream before,
     * there's only one key for this srtp_session, and the cipher
     * supports key-sharing, then we assume that a new stream using
     * that key has just started up
     */
    stream = srtp_get_stream(ctx, hdr->ssrc);
    if (stream == NULL)
    {
        if (ctx->stream_template != NULL) {
            stream = ctx->stream_template;
            debug_print(mod_srtp, "using provisional stream (SSRC: 0x%08x)",
                        hdr->ssrc);
        }
        else {
            /*
             * no stream corresponding to SSRC found, and we don't do
             * key-sharing, so return an error
             */
            return srtp_err_status_no_ctx;
        }
    }

    /*
     * For regular EKT mode, parse the EKT tag now, as we will need the
     * SSRC and ROC information to estimate the packet index.  The ROC
     * can change substantially if a sender's media is not received for
     * some period of time, which might be common with switched
     * conferencing.  Note that for PRIME, the ROC is in the clear and
     * accessed directly when estimating the packet index.
     */
    if (stream->ektMode == ekt_mode_regular) {
        status = ekt_parse_tag(stream,
                               ctx,
                               srtp_hdr,
                               pkt_octet_len,
                               &ekt_tag_contents);
        if (status != srtp_err_status_ok && status != srtp_err_no_ekt)
            return status;

        /* Recheck header as EKT tag extraction reduces the packet length */
        status = srtp_validate_rtp_header(srtp_hdr, pkt_octet_len);
        if (status)
            return status;
    }
    else {
        ekt_tag_contents.present = 0;
    }

    /* Get the estimated packet index value */
    status = srtp_get_est_pkt_index(hdr,
                                    pkt_octet_len,
                                    stream,
                                    &est,
                                    &delta,
                                    &ekt_tag_contents,
                                    flags);
    if (status && (status != srtp_err_status_pkt_idx_adv))
        return status;

    /*
     * Replay check will be skipped if this packet is far in advance
     * of the internally maintained packet index value.
     */
    if (status == srtp_err_status_pkt_idx_adv) {
        advance_packet_index = 1;
    }

    /* Check if the packet is being replayed */
    if ((flags & srtp_service_chk_replay) & !advance_packet_index) {
        /*
         * If the SSRC is not a new one then we have rdbx database therefore
         * check if the packet is being replayed.
         */
        if (stream != ctx->stream_template) {
            /* check replay database */
            status = srtp_rdbx_check(&stream->rtp_rdbx, delta);
            if (status)
                return status;
        }
    }

    /*
     * If the packet looks good then authenticate and decrypt the packet. For
     * PRIME, if we are an endpoint then we first authenticate the packet with
     * hop-by-hop ctx and then we decrypt the packet using end-to-end ctx.
     */
    if (stream->ektMode == ekt_mode_prime_hop_by_hop)
    {
        /*
         * The flag is checked before authenticating the actual packet. But the
         * check here avoids uneccessary function call.
         */
        if (flags & srtp_service_prime_hbh) {
            status = srtp_process_unprotect(srtp_hdr,
                                            pkt_octet_len,
                                            ctx,
                                            stream,
                                            est,
                                            &ekt_tag_contents);
            if (status)
                return status;
        }

        if (flags & srtp_service_prime_e2e) {
            if (stream->prime_end_to_end_stream_ctx == NULL)
                return srtp_err_status_bad_param;

            /* Before attempting to decrypt, parse the EKT tag */
            status = ekt_parse_tag(stream->prime_end_to_end_stream_ctx,
                                   ctx,
                                   srtp_hdr,
                                   pkt_octet_len,
                                   &ekt_tag_contents);
            if (status != srtp_err_status_ok && status != srtp_err_no_ekt)
                return status;

            /* Recheck header as EKT tag extraction reduces the packet length */
            status = srtp_validate_rtp_header(srtp_hdr, pkt_octet_len);
            if (status)
                return status;

            /* Decrypt the packet */
            status = srtp_process_unprotect(srtp_hdr,
                                            pkt_octet_len,
                                            ctx,
                                            stream->prime_end_to_end_stream_ctx,
                                            est,
                                            &ekt_tag_contents);
            if (status)
                return status;
        }
    }
    else
    {
        status = srtp_process_unprotect(srtp_hdr,
                                        pkt_octet_len,
                                        ctx,
                                        stream,
                                        est,
                                        &ekt_tag_contents);
        if (status)
            return status;
    }

    /*
     * if the stream is a 'provisional' one, in which the template context
     * is used, then we need to allocate a new stream at this point, since
     * the authentication passed
     */
    if (stream == ctx->stream_template) {
        srtp_stream_ctx_t *new_stream;

        /*
         * allocate and initialize a new stream
         *
         * note that we indicate failure if we can't allocate the new
         * stream, and some implementations will want to not return
         * failure here
         */
        status = srtp_stream_clone(ctx->stream_template,
                                   hdr->ssrc,
                                   &new_stream);
        if (status)
            return status;

         /* add new stream to the head of the stream_list */
        new_stream->next = ctx->stream_list;
        ctx->stream_list = new_stream;

        /* set stream (the pointer used in this function) */
        stream = new_stream;
    }

    /*
     * the message authentication function passed, so add the packet
     * index into the replay database
    */
    if ((flags & srtp_service_chk_replay) && advance_packet_index) {
        /* A lot of packet were skipped, so reset the replay database */
        srtp_rdbx_set_roc_seq(&stream->rtp_rdbx,
                              (uint32_t)(est >> 16),
                              (uint16_t)(est & 0xFFFF));
        srtp_rdbx_add_index(&stream->rtp_rdbx, 0);
    }
    else if (flags & srtp_service_chk_replay) {
        srtp_rdbx_add_index(&stream->rtp_rdbx, delta);
    }

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_unprotect(srtp_ctx_t *ctx, void *rtp_hdr, int *pkt_octet_len) {

  srtp_err_status_t status;

  debug_print(mod_srtp, "function srtp_unprotect", NULL);
  
  status = srtp_unprotect_with_flags(ctx, rtp_hdr, pkt_octet_len, srtp_service_default);
  if (status) {
    debug_print(mod_srtp, "function srtp_unprotect: failed to unprotect packet", NULL);
  }

  return status;
}

srtp_err_status_t
srtp_init() {
  srtp_err_status_t status;

  /* initialize crypto kernel */
  status = srtp_crypto_kernel_init();
  if (status) 
    return status;

  /* load srtp debug module into the kernel */
  status = srtp_crypto_kernel_load_debug_module(&mod_srtp);
  if (status)
    return status;

  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_shutdown() {
  srtp_err_status_t status;

  /* shut down crypto kernel */
  status = srtp_crypto_kernel_shutdown();
  if (status) 
    return status;

  /* shutting down crypto kernel frees the srtp debug module as well */

  return srtp_err_status_ok;
}


/* 
 * The following code is under consideration for removal.  See
 * SRTP_MAX_TRAILER_LEN 
 */
#if 0

/*
 * srtp_get_trailer_length(&a) returns the number of octets that will
 * be added to an RTP packet by the SRTP processing.  This value
 * is constant for a given srtp_stream_t (i.e. between initializations).
 */

int
srtp_get_trailer_length(const srtp_stream_t s) {
  return srtp_auth_get_tag_length(s->rtp_auth);
}

#endif

/*
 * srtp_get_stream(ssrc) returns a pointer to the stream corresponding
 * to ssrc, or NULL if no stream exists for that ssrc
 *
 * this is an internal function 
 */

srtp_stream_ctx_t *
srtp_get_stream(srtp_t srtp, uint32_t ssrc) {
  srtp_stream_ctx_t *stream;

  /* walk down list until ssrc is found */
  stream = srtp->stream_list;
  while (stream != NULL) {
    if (stream->ssrc == ssrc)
      return stream;
    stream = stream->next;
  }
  
  /* we haven't found our ssrc, so return a null */
  return NULL;
}

srtp_err_status_t
srtp_dealloc(srtp_t session) {
  srtp_stream_ctx_t *stream;
  srtp_err_status_t status;

  /*
   * we take a conservative deallocation strategy - if we encounter an
   * error deallocating a stream, then we stop trying to deallocate
   * memory and just return an error
   */

  /* walk list of streams, deallocating as we go */
  stream = session->stream_list;
  while (stream != NULL) {
    srtp_stream_t next = stream->next;
    status = srtp_stream_dealloc(stream, session->stream_template);
    if (status)
      return status;
    stream = next;
  }

  /* walk list of spi, deallocating as we go */
  srtp_ekt_spi_info_t *spi = session->spi_info;
  while (spi != NULL) {
    srtp_ekt_spi_info_t *next = spi->next;
    srtp_crypto_free(spi);
    spi = next;
  }
  
  /* deallocate stream template, if there is one */
  if (session->stream_template != NULL) {
    status = srtp_stream_dealloc(session->stream_template, NULL);
    if (status)
      return status;
  }

  /* deallocate session context */
  srtp_crypto_free(session);

  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_stream_create(srtp_t session,
                   const srtp_policy_t *policy,
                   srtp_stream_ctx_t **str_ptr) {
  srtp_err_status_t status;
  srtp_stream_ctx_t *tmp;

  /*
   * Allocate stream context.
   * For PRIME allocate the outer context.
   */
  if (policy->ekt_policy.ekt_ctx_type == ekt_ctx_type_prime)
    status = srtp_stream_alloc(&tmp, policy, ekt_mode_prime_hop_by_hop);
  else if (policy->ekt_policy.ekt_ctx_type == ekt_ctx_type_ekt)
    status = srtp_stream_alloc(&tmp, policy, ekt_mode_regular);
  else
    status = srtp_stream_alloc(&tmp, policy, ekt_mode_no_ekt);
  if (status) {
    return status;
  }

  *str_ptr = tmp;

  tmp->prime_end_to_end_stream_ctx = NULL;

  /*
   * If PRIME then we have allocated the outer hop-by-hop context.
   * Now we need to allocate and intialize the inner end-to-end context.
   */
  if (policy->ekt_policy.ekt_ctx_type == ekt_ctx_type_prime) {
    status = srtp_stream_alloc(&tmp->prime_end_to_end_stream_ctx,
                               policy,
                               ekt_mode_prime_end_to_end);
    if (status) {
      srtp_stream_dealloc(tmp, session->stream_template);
      return status;
    }
    /* Assign the replay database for EKT tag generation */
    tmp->prime_end_to_end_stream_ctx->rtp_rdbx_prime = &tmp->rtp_rdbx;
  }

  int key_len = srtp_cipher_get_key_length(tmp->rtp_cipher);

  /*
   * AES GCM uses a 96-bit salt, whereas AES CM uses a 112-bit salt.
   * Let ensure we get the full key and salt values based on whichever
   * has the longest value, considering both the RTP master key and salt
   * and the key and salt length associated with the cipher for the header
   * extensions.
   */
  if (tmp->rtp_xtn_hdr_cipher) {
      int xtn_hdr_key_len = srtp_cipher_get_key_length(tmp->rtp_xtn_hdr_cipher);
      if (xtn_hdr_key_len > key_len) {
          key_len = xtn_hdr_key_len;
      }
  }

  /* Initialize PRIME outer context and non EKT stream context */
  if (policy->ekt_policy.ekt_ctx_type == ekt_ctx_type_no_ekt ||
      policy->ekt_policy.ekt_ctx_type == ekt_ctx_type_prime) {

    /* Copy master key copy as provided by the application */
    memcpy(tmp->master_key, policy->key, key_len);
    status = srtp_stream_init(tmp, policy);
    if (status) {
      if (tmp->prime_end_to_end_stream_ctx)
        srtp_stream_dealloc(tmp->prime_end_to_end_stream_ctx, session->stream_template);
      srtp_stream_dealloc(tmp, session->stream_template);
      return status;
    }
  }

  if (policy->ekt_policy.ekt_ctx_type == ekt_ctx_type_ekt ||
      policy->ekt_policy.ekt_ctx_type == ekt_ctx_type_prime) {

    srtp_stream_ctx_t *tmp_stream_ctx;

    /* For PRIME the E2E context uses the EKT keys */
    if (policy->ekt_policy.ekt_ctx_type == ekt_ctx_type_prime)
      tmp_stream_ctx = tmp->prime_end_to_end_stream_ctx;
    else
      tmp_stream_ctx = tmp;

    /* Initialize the key lengths */
    int key_len = srtp_cipher_get_key_length(tmp_stream_ctx->rtp_cipher);
    if (tmp_stream_ctx->rtp_xtn_hdr_cipher) {
        int xtn_hdr_key_len =
                srtp_cipher_get_key_length(tmp_stream_ctx->rtp_xtn_hdr_cipher);
        if (xtn_hdr_key_len > key_len) {
            key_len = xtn_hdr_key_len;
        }
    }
    int base_key_len = base_key_length(tmp_stream_ctx->rtp_cipher->type,
                                       key_len);
    unsigned salt_len = key_len - base_key_len;

    /* Get the SPI info */
    srtp_ekt_spi_info_t *spi_info = NULL;
    status = ekt_get_spi_info(session,
                              policy->ekt_policy.spi,
                              &spi_info);
    if (status != srtp_err_status_ok || spi_info == NULL) {
      if (tmp->prime_end_to_end_stream_ctx)
        srtp_stream_dealloc(tmp->prime_end_to_end_stream_ctx, session->stream_template);
      srtp_stream_dealloc(tmp, session->stream_template);
      return status;
    }

    /* Ensure that the computed salt length matches SPI info */
    if (salt_len != spi_info->ekt_salt_length) {
      if (tmp->prime_end_to_end_stream_ctx)
        srtp_stream_dealloc(tmp->prime_end_to_end_stream_ctx, session->stream_template);
      srtp_stream_dealloc(tmp, session->stream_template);
      return srtp_err_status_bad_param;
    }

    /*
     * For EKT enabled outgoing context the key used for encryption (send ctx)
     * is sent by application in the EKT Policy. The salt for the outgoing
     * key should be the salt in the EKT key. Therefore construct the master
     * key using master key provided by the application and the salt in
     * SPI - EKT master salt. For incoming context the key will be learnt
     * from EKT tags. Therefore just initialize master key to 0 and copy salt
     * from the EKT master salt.
     */
    if (policy->ekt_policy.key != NULL)
      memcpy(tmp_stream_ctx->master_key, policy->ekt_policy.key, base_key_len);
    else
      memset(tmp_stream_ctx->master_key, 0, key_len);

    memcpy((tmp_stream_ctx->master_key) + base_key_len,
           (const void *) (spi_info->ekt_salt),
           salt_len);
    status = srtp_stream_init(tmp_stream_ctx, policy);
    if (status) {
      if (tmp->prime_end_to_end_stream_ctx)
        srtp_stream_dealloc(tmp->prime_end_to_end_stream_ctx, session->stream_template);
      srtp_stream_dealloc(tmp, session->stream_template);
      return status;
    }
  }

  /*
   * Initialize the end-to-end context for PRIME to perform encryption and
   * decryption
   */
  if (tmp->prime_end_to_end_stream_ctx != NULL)
    tmp->prime_end_to_end_stream_ctx->rtp_services = sec_serv_conf;

  return status;
}

srtp_err_status_t
srtp_add_stream(srtp_t session,
                const srtp_policy_t *policy)  {
  srtp_err_status_t status;
  srtp_stream_t tmp;

  /* sanity check arguments */
  if ((session == NULL) || (policy == NULL) || (policy->key == NULL))
    return srtp_err_status_bad_param;

  /* create stream */
  status = srtp_stream_create(session, policy, &tmp);
  if (status) {
    return status;
  }

  /*
   * set the head of the stream list or the template to point to the
   * stream that we've just alloced and init'ed, depending on whether
   * or not it has a wildcard SSRC value or not
   *
   * if the template stream has already been set, then the policy is
   * inconsistent, so we return a bad_param error code
   */
  switch (policy->ssrc.type) {
  case (ssrc_any_outbound):
    if (session->stream_template) {
      if (tmp->prime_end_to_end_stream_ctx)
        srtp_stream_dealloc(tmp->prime_end_to_end_stream_ctx, session->stream_template);
      srtp_stream_dealloc(tmp, session->stream_template);
      return srtp_err_status_bad_param;
    }
    session->stream_template = tmp;
    session->stream_template->direction = dir_srtp_sender;
    break;
  case (ssrc_any_inbound):
    if (session->stream_template) {
      if (tmp->prime_end_to_end_stream_ctx)
        srtp_stream_dealloc(tmp->prime_end_to_end_stream_ctx, session->stream_template);
      srtp_stream_dealloc(tmp, session->stream_template);
      return srtp_err_status_bad_param;
    }
    session->stream_template = tmp;
    session->stream_template->direction = dir_srtp_receiver;
    break;
  case (ssrc_specific):
    tmp->next = session->stream_list;
    session->stream_list = tmp;
    break;
  case (ssrc_undefined):
  default:
    if (tmp->prime_end_to_end_stream_ctx)
      srtp_stream_dealloc(tmp->prime_end_to_end_stream_ctx, session->stream_template);
    srtp_stream_dealloc(tmp, session->stream_template);
    return srtp_err_status_bad_param;
  }

  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_create(srtp_t *session,               /* handle for session     */ 
	    const srtp_policy_t *policy) { /* SRTP policy (list)     */
  srtp_err_status_t stat;
  srtp_ctx_t *ctx;

  /* sanity check arguments */
  if (session == NULL)
    return srtp_err_status_bad_param;

  /* allocate srtp context and set ctx_ptr */
  ctx = (srtp_ctx_t *) srtp_crypto_alloc(sizeof(srtp_ctx_t));
  if (ctx == NULL)
    return srtp_err_status_alloc_fail;
  *session = ctx;

  /* 
   * loop over elements in the policy list, allocating and
   * initializing a stream for each element
   */
  ctx->stream_template = NULL;
  ctx->stream_list = NULL;
  ctx->user_data = NULL;
  ctx->spi_info = NULL;
  while (policy != NULL) {    
    stat = srtp_add_stream(ctx, policy);
    if (stat) {
      /* clean up everything */
      srtp_dealloc(*session);
      *session = NULL;
      return stat;
    }    

    /* set policy to next item in list  */
    policy = policy->next;
  }

  return srtp_err_status_ok;
}


srtp_err_status_t
srtp_remove_stream(srtp_t session, uint32_t ssrc) {
  srtp_stream_ctx_t *stream, *last_stream;
  srtp_err_status_t status;

  /* sanity check arguments */
  if (session == NULL)
    return srtp_err_status_bad_param;
  
  /* find stream in list; complain if not found */
  last_stream = stream = session->stream_list;
  while ((stream != NULL) && (ssrc != stream->ssrc)) {
    last_stream = stream;
    stream = stream->next;
  }
  if (stream == NULL)
    return srtp_err_status_no_ctx;

  /* remove stream from the list */
  if (last_stream == stream)
    /* stream was first in list */
    session->stream_list = stream->next;
  else
    last_stream->next = stream->next;

  /*
   * Deallocate the stream. For PRIME there will be an inner stream context
   * and outer stream context. Deallocate the inner stream context and then
   * the outer stream context. We need to dealloc the outer context even if
   * there is a problem while deallocating the inner context.
   */
  if (stream->ektMode == ekt_mode_prime_hop_by_hop &&
      stream->prime_end_to_end_stream_ctx != NULL) {
      status = srtp_stream_dealloc(
            stream->prime_end_to_end_stream_ctx,
            session->stream_template ?
                session->stream_template->prime_end_to_end_stream_ctx:NULL);
      if (status) {
          srtp_stream_dealloc(stream, session->stream_template);
          return status;
      }
  }

  /* deallocate the stream */
  status = srtp_stream_dealloc(stream, session->stream_template);
  if (status)
    return status;

  return srtp_err_status_ok;
}


srtp_err_status_t
srtp_update(srtp_t session,
            const srtp_policy_t *policy) {
  srtp_err_status_t stat;

  /* sanity check arguments */
  if ((session == NULL) || (policy == NULL) || (policy->key == NULL)) {
    return srtp_err_status_bad_param;
  }

  while (policy != NULL) {
    stat = srtp_update_stream(session, policy);
    if (stat) {
      return stat;
    }

    /* set policy to next item in list  */
    policy = policy->next;
  }
  return srtp_err_status_ok;
}


static srtp_err_status_t
update_template_streams(srtp_t session,
                        const srtp_policy_t *policy) {
  srtp_err_status_t status;
  srtp_stream_t new_stream_template;
  srtp_stream_t new_stream_list = NULL;

  if (session->stream_template == NULL) {
    return srtp_err_status_bad_param;
  }

  /* create stream */
  status = srtp_stream_create(session, policy, &new_stream_template);
  if (status) {
    return status;
  }

  /* for all old templated streams */
  for (;;) {
    srtp_stream_t stream;
    uint32_t ssrc;
    srtp_xtd_seq_num_t old_index;
    srtp_rdb_t old_rtcp_rdb;

    stream = session->stream_list;
    while ((stream != NULL) &&
           (stream->rtp_auth != session->stream_template->rtp_auth)) {
      stream = stream->next;
    }
    if (stream == NULL) {
      /* no more templated streams */
      break;
    }

    /* save old extendard seq */
    ssrc = stream->ssrc;
    old_index = stream->rtp_rdbx.index;
    old_rtcp_rdb = stream->rtcp_rdb;

    /* remove stream */
    status = srtp_remove_stream(session, ssrc);
    if (status) {
      /* free new allocations */
      while (new_stream_list != NULL) {
        srtp_stream_t next = new_stream_list->next;
        srtp_stream_dealloc(new_stream_list, new_stream_template);
        new_stream_list = next;
      }
      srtp_stream_dealloc(new_stream_template, NULL);
      return status;
    }

    /* allocate and initialize a new stream */
    status = srtp_stream_clone(new_stream_template, ssrc, &stream);
    if (status) {
      /* free new allocations */
      while (new_stream_list != NULL) {
        srtp_stream_t next = new_stream_list->next;
        srtp_stream_dealloc(new_stream_list, new_stream_template);
        new_stream_list = next;
      }
      srtp_stream_dealloc(new_stream_template, NULL);
      return status;
    }

    /* add new stream to the head of the new_stream_list */
    stream->next = new_stream_list;
    new_stream_list = stream;

    /* restore old extended seq */
    stream->rtp_rdbx.index = old_index;
    stream->rtcp_rdb = old_rtcp_rdb;
  }

  /* dealloc old template */
  srtp_stream_dealloc(session->stream_template, NULL);

  /* set new template */
  session->stream_template = new_stream_template;

  /* add new list */
  if (new_stream_list) {
    srtp_stream_t tail = new_stream_list;
    while (tail->next) {
      tail = tail->next;
    }
    tail->next = session->stream_list;
    session->stream_list = new_stream_list;
  }
  return status;
}


static srtp_err_status_t
update_stream(srtp_t session, const srtp_policy_t *policy) {
  srtp_err_status_t status;
  srtp_xtd_seq_num_t old_index;
  srtp_rdb_t old_rtcp_rdb;
  srtp_stream_t stream;

  stream = srtp_get_stream(session, policy->ssrc.value);
  if (stream == NULL) {
    return srtp_err_status_bad_param;
  }

  /* save old extendard seq */
  old_index = stream->rtp_rdbx.index;
  old_rtcp_rdb = stream->rtcp_rdb;

  status = srtp_remove_stream(session, policy->ssrc.value);
  if (status) {
    return status;
  }

  status = srtp_add_stream(session, policy);
  if (status) {
    return status;
  }

  stream = srtp_get_stream(session, policy->ssrc.value);
  if (stream == NULL) {
    return srtp_err_status_fail;
  }

  /* restore old extended seq */
  stream->rtp_rdbx.index = old_index;
  stream->rtcp_rdb = old_rtcp_rdb;

  return srtp_err_status_ok;
}


srtp_err_status_t
srtp_update_stream(srtp_t session,
                   const srtp_policy_t *policy) {
  srtp_err_status_t status;

  /* sanity check arguments */
  if ((session == NULL) || (policy == NULL) || (policy->key == NULL))
    return srtp_err_status_bad_param;

  switch (policy->ssrc.type) {
  case (ssrc_any_outbound):
  case (ssrc_any_inbound):
    status = update_template_streams(session, policy);
    break;
  case (ssrc_specific):
    status = update_stream(session, policy);
    break;
  case (ssrc_undefined):
  default:
    return srtp_err_status_bad_param;
  }

  return status;
}


/*
 * the default policy - provides a convenient way for callers to use
 * the default security policy
 * 
 * this policy is that defined in the current SRTP internet draft.
 *
 */

/* 
 * NOTE: cipher_key_len is really key len (128 bits) plus salt len
 *  (112 bits)
 */
/* There are hard-coded 16's for base_key_len in the key generation code */

void
srtp_crypto_policy_set_rtp_default(srtp_crypto_policy_t *p) {

  p->cipher_type     = SRTP_AES_ICM;           
  p->cipher_key_len  = 30;                /* default 128 bits per RFC 3711 */
  p->auth_type       = SRTP_HMAC_SHA1;             
  p->auth_key_len    = 20;                /* default 160 bits per RFC 3711 */
  p->auth_tag_len    = 10;                /* default 80 bits per RFC 3711 */
  p->sec_serv        = sec_serv_conf_and_auth;
  
}

void
srtp_crypto_policy_set_rtcp_default(srtp_crypto_policy_t *p) {

  p->cipher_type     = SRTP_AES_ICM;           
  p->cipher_key_len  = 30;                 /* default 128 bits per RFC 3711 */
  p->auth_type       = SRTP_HMAC_SHA1;             
  p->auth_key_len    = 20;                 /* default 160 bits per RFC 3711 */
  p->auth_tag_len    = 10;                 /* default 80 bits per RFC 3711 */
  p->sec_serv        = sec_serv_conf_and_auth;
  
}

void
srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(srtp_crypto_policy_t *p) {

  /*
   * corresponds to RFC 4568
   *
   * note that this crypto policy is intended for SRTP, but not SRTCP
   */

  p->cipher_type     = SRTP_AES_ICM;           
  p->cipher_key_len  = 30;                /* 128 bit key, 112 bit salt */
  p->auth_type       = SRTP_HMAC_SHA1;             
  p->auth_key_len    = 20;                /* 160 bit key               */
  p->auth_tag_len    = 4;                 /* 32 bit tag                */
  p->sec_serv        = sec_serv_conf_and_auth;
  
}


void
srtp_crypto_policy_set_aes_cm_128_null_auth(srtp_crypto_policy_t *p) {

  /*
   * corresponds to RFC 4568
   *
   * note that this crypto policy is intended for SRTP, but not SRTCP
   */

  p->cipher_type     = SRTP_AES_ICM;           
  p->cipher_key_len  = 30;                /* 128 bit key, 112 bit salt */
  p->auth_type       = SRTP_NULL_AUTH;             
  p->auth_key_len    = 0; 
  p->auth_tag_len    = 0; 
  p->sec_serv        = sec_serv_conf;
  
}


void
srtp_crypto_policy_set_null_cipher_hmac_sha1_80(srtp_crypto_policy_t *p) {

  /*
   * corresponds to RFC 4568
   */

  p->cipher_type     = SRTP_NULL_CIPHER;           
  p->cipher_key_len  = 0;
  p->auth_type       = SRTP_HMAC_SHA1;             
  p->auth_key_len    = 20; 
  p->auth_tag_len    = 10; 
  p->sec_serv        = sec_serv_auth;
  
}

void
srtp_crypto_policy_set_null_cipher_hmac_null(srtp_crypto_policy_t *p) {

  /*
   * Should only be used for testing
   */

  p->cipher_type     = SRTP_NULL_CIPHER;           
  p->cipher_key_len  = 0;
  p->auth_type       = SRTP_NULL_AUTH;             
  p->auth_key_len    = 0; 
  p->auth_tag_len    = 0; 
  p->sec_serv        = sec_serv_none;
  
}


void
srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(srtp_crypto_policy_t *p) {

  /*
   * corresponds to draft-ietf-avt-big-aes-03.txt
   */

  p->cipher_type     = SRTP_AES_ICM;           
  p->cipher_key_len  = 46;
  p->auth_type       = SRTP_HMAC_SHA1;             
  p->auth_key_len    = 20;                /* default 160 bits per RFC 3711 */
  p->auth_tag_len    = 10;                /* default 80 bits per RFC 3711 */
  p->sec_serv        = sec_serv_conf_and_auth;
}


void
srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(srtp_crypto_policy_t *p) {

  /*
   * corresponds to draft-ietf-avt-big-aes-03.txt
   *
   * note that this crypto policy is intended for SRTP, but not SRTCP
   */

  p->cipher_type     = SRTP_AES_ICM;           
  p->cipher_key_len  = 46;
  p->auth_type       = SRTP_HMAC_SHA1;             
  p->auth_key_len    = 20;                /* default 160 bits per RFC 3711 */
  p->auth_tag_len    = 4;                 /* default 80 bits per RFC 3711 */
  p->sec_serv        = sec_serv_conf_and_auth;
}

/*
 * AES-256 with no authentication.
 */
void
srtp_crypto_policy_set_aes_cm_256_null_auth (srtp_crypto_policy_t *p)
{
    p->cipher_type     = SRTP_AES_ICM;
    p->cipher_key_len  = 46;
    p->auth_type       = SRTP_NULL_AUTH;
    p->auth_key_len    = 0;
    p->auth_tag_len    = 0;
    p->sec_serv        = sec_serv_conf;
}

#ifdef OPENSSL
/*
 * AES-128 GCM mode with 8 octet auth tag. 
 */
void
srtp_crypto_policy_set_aes_gcm_128_8_auth(srtp_crypto_policy_t *p) {
  p->cipher_type     = SRTP_AES_128_GCM;           
  p->cipher_key_len  = SRTP_AES_128_GCM_KEYSIZE_WSALT; 
  p->auth_type       = SRTP_NULL_AUTH; /* GCM handles the auth for us */            
  p->auth_key_len    = 0; 
  p->auth_tag_len    = 8;   /* 8 octet tag length */
  p->sec_serv        = sec_serv_conf_and_auth;
}

/*
 * AES-256 GCM mode with 8 octet auth tag. 
 */
void
srtp_crypto_policy_set_aes_gcm_256_8_auth(srtp_crypto_policy_t *p) {
  p->cipher_type     = SRTP_AES_256_GCM;           
  p->cipher_key_len  = SRTP_AES_256_GCM_KEYSIZE_WSALT; 
  p->auth_type       = SRTP_NULL_AUTH; /* GCM handles the auth for us */ 
  p->auth_key_len    = 0; 
  p->auth_tag_len    = 8;   /* 8 octet tag length */
  p->sec_serv        = sec_serv_conf_and_auth;
}

/*
 * AES-128 GCM mode with 8 octet auth tag, no RTCP encryption. 
 */
void
srtp_crypto_policy_set_aes_gcm_128_8_only_auth(srtp_crypto_policy_t *p) {
  p->cipher_type     = SRTP_AES_128_GCM;           
  p->cipher_key_len  = SRTP_AES_128_GCM_KEYSIZE_WSALT; 
  p->auth_type       = SRTP_NULL_AUTH; /* GCM handles the auth for us */ 
  p->auth_key_len    = 0; 
  p->auth_tag_len    = 8;   /* 8 octet tag length */
  p->sec_serv        = sec_serv_auth;  /* This only applies to RTCP */
}

/*
 * AES-256 GCM mode with 8 octet auth tag, no RTCP encryption. 
 */
void
srtp_crypto_policy_set_aes_gcm_256_8_only_auth(srtp_crypto_policy_t *p) {
  p->cipher_type     = SRTP_AES_256_GCM;           
  p->cipher_key_len  = SRTP_AES_256_GCM_KEYSIZE_WSALT; 
  p->auth_type       = SRTP_NULL_AUTH; /* GCM handles the auth for us */ 
  p->auth_key_len    = 0; 
  p->auth_tag_len    = 8;   /* 8 octet tag length */
  p->sec_serv        = sec_serv_auth;  /* This only applies to RTCP */
}

/*
 * AES-128 GCM mode with 16 octet auth tag. 
 */
void
srtp_crypto_policy_set_aes_gcm_128_16_auth(srtp_crypto_policy_t *p) {
  p->cipher_type     = SRTP_AES_128_GCM;           
  p->cipher_key_len  = SRTP_AES_128_GCM_KEYSIZE_WSALT; 
  p->auth_type       = SRTP_NULL_AUTH; /* GCM handles the auth for us */            
  p->auth_key_len    = 0; 
  p->auth_tag_len    = 16;   /* 16 octet tag length */
  p->sec_serv        = sec_serv_conf_and_auth;
}

/*
 * AES-256 GCM mode with 16 octet auth tag. 
 */
void
srtp_crypto_policy_set_aes_gcm_256_16_auth(srtp_crypto_policy_t *p) {
  p->cipher_type     = SRTP_AES_256_GCM;           
  p->cipher_key_len  = SRTP_AES_256_GCM_KEYSIZE_WSALT; 
  p->auth_type       = SRTP_NULL_AUTH; /* GCM handles the auth for us */ 
  p->auth_key_len    = 0; 
  p->auth_tag_len    = 16;   /* 16 octet tag length */
  p->sec_serv        = sec_serv_conf_and_auth;
}

#endif

/* 
 * secure rtcp functions
 */

/*
 * AEAD uses a new IV formation method.  This function implements
 * section 10.1 from draft-ietf-avtcore-srtp-aes-gcm-07.txt.  The
 * calculation is defined as, where (+) is the xor operation:
 *
 *                0  1  2  3  4  5  6  7  8  9 10 11
 *               +--+--+--+--+--+--+--+--+--+--+--+--+
 *               |00|00|    SSRC   |00|00|0+SRTCP Idx|---+
 *               +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *                                                       |
 *               +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *               |         Encryption Salt           |->(+)
 *               +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *                                                       |
 *               +--+--+--+--+--+--+--+--+--+--+--+--+   |
 *               |       Initialization Vector       |<--+
 *               +--+--+--+--+--+--+--+--+--+--+--+--+*
 *
 * Input:  *stream - pointer to SRTP stream context, used to retrieve
 *                   the SALT 
 *         *iv     - Pointer to recieve the calculated IV
 *         seq_num - The SEQ value to use for the IV calculation.
 *         *hdr    - The RTP header, used to get the SSRC value
 *
 */
static void srtp_calc_aead_iv_srtcp(srtp_stream_ctx_t *stream, v128_t *iv, 
                                    uint32_t seq_num, srtcp_hdr_t *hdr)
{
    v128_t	in;
    v128_t	salt;

    memset(&in, 0, sizeof(v128_t));
    memset(&salt, 0, sizeof(v128_t));

    in.v16[0] = 0;
    memcpy(&in.v16[1], &hdr->ssrc, 4); /* still in network order! */
    in.v16[3] = 0;
    in.v32[2] = 0x7FFFFFFF & htonl(seq_num); /* bit 32 is suppose to be zero */

    debug_print(mod_srtp, "Pre-salted RTCP IV = %s\n", v128_hex_string(&in));

    /*
     * Get the SALT value from the context
     */
    memcpy(salt.v8, stream->c_salt, 12);
    debug_print(mod_srtp, "RTCP SALT = %s\n", v128_hex_string(&salt));

    /*
     * Finally, apply the SALT to the input
     */
    v128_xor(iv, &in, &salt);
}

/*
 * This code handles AEAD ciphers for outgoing RTCP.  We currently support
 * AES-GCM mode with 128 or 256 bit keys. 
 */
static srtp_err_status_t
srtp_protect_rtcp_aead (srtp_stream_ctx_t *stream,
                        void *rtcp_hdr,
                        unsigned int *pkt_octet_len)
{
    srtcp_hdr_t *hdr = (srtcp_hdr_t*)rtcp_hdr;
    uint32_t *enc_start;        /* pointer to start of encrypted portion  */
    uint32_t *trailer;          /* pointer to start of trailer            */
    unsigned int enc_octet_len = 0; /* number of octets in encrypted portion */
    uint8_t *auth_tag = NULL;   /* location of auth_tag within packet     */
    srtp_err_status_t status;
    uint32_t tag_len;
    uint32_t seq_num;
    v128_t iv;
    uint32_t tseq;

    /* get tag length from stream context */
    tag_len = srtp_auth_get_tag_length(stream->rtcp_auth);

    /*
     * set encryption start and encryption length - if we're not
     * providing confidentiality, set enc_start to NULL
     */
    enc_start = (uint32_t*)hdr + uint32s_in_rtcp_header;
    enc_octet_len = *pkt_octet_len - octets_in_rtcp_header;

    /* NOTE: hdr->length is not usable - it refers to only the first
           RTCP report in the compound packet! */
    /* NOTE: trailer is 32-bit aligned because RTCP 'packets' are always
           multiples of 32-bits (RFC 3550 6.1) */
    trailer = (uint32_t*)((char*)enc_start + enc_octet_len + tag_len);

    if (stream->rtcp_services & sec_serv_conf) {
        *trailer = htonl(SRTCP_E_BIT); /* set encrypt bit */
    } else {
        enc_start = NULL;
        enc_octet_len = 0;
        /* 0 is network-order independant */
        *trailer = 0x00000000; /* set encrypt bit */
    }

    /*
     * set the auth_tag pointer to the proper location, which is after
     * the payload, but before the trailer
     * (note that srtpc *always* provides authentication, unlike srtp)
     */
    /* Note: This would need to change for optional mikey data */
    auth_tag = (uint8_t*)hdr + *pkt_octet_len;

    /*
     * check sequence number for overruns, and copy it into the packet
     * if its value isn't too big
     */
    status = srtp_rdb_increment(&stream->rtcp_rdb);
    if (status) {
        return status;
    }
    seq_num = srtp_rdb_get_value(&stream->rtcp_rdb);
    *trailer |= htonl(seq_num);
    debug_print(mod_srtp, "srtcp index: %x", seq_num);

    /*
     * Calculating the IV and pass it down to the cipher 
     */
    srtp_calc_aead_iv_srtcp(stream, &iv, seq_num, hdr);
    status = srtp_cipher_set_iv(stream->rtcp_cipher, (uint8_t*)&iv, direction_encrypt);
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /*
     * Set the AAD for GCM mode
     */
    if (enc_start) {
	/*
	 * If payload encryption is enabled, then the AAD consist of
	 * the RTCP header and the seq# at the end of the packet
	 */
	status = srtp_cipher_set_aad(stream->rtcp_cipher, (uint8_t*)hdr, octets_in_rtcp_header);
	if (status) {
	    return ( srtp_err_status_cipher_fail);
	}
    } else {
	/*
	 * Since payload encryption is not enabled, we must authenticate
	 * the entire packet as described in section 10.3 in revision 07
	 * of the draft.
	 */
	status = srtp_cipher_set_aad(stream->rtcp_cipher, (uint8_t*)hdr, *pkt_octet_len);
	if (status) {
	    return ( srtp_err_status_cipher_fail);
	}
    }
    /* 
     * Process the sequence# as AAD
     */
    tseq = *trailer;
    status = srtp_cipher_set_aad(stream->rtcp_cipher, (uint8_t*)&tseq, sizeof(srtcp_trailer_t));
    if (status) {
        return ( srtp_err_status_cipher_fail);
    }

    /* if we're encrypting, exor keystream into the message */
    if (enc_start) {
        status = srtp_cipher_encrypt(stream->rtcp_cipher,
                                    (uint8_t*)enc_start, &enc_octet_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
	/*
	 * Get the tag and append that to the output
	 */
	status = srtp_cipher_get_tag(stream->rtcp_cipher, (uint8_t*)auth_tag, &tag_len);
	if (status) {
	    return ( srtp_err_status_cipher_fail);
	}
	enc_octet_len += tag_len;
    } else {
	/*
	 * Even though we're not encrypting the payload, we need
	 * to run the cipher to get the auth tag.
	 */
	unsigned int nolen = 0;
        status = srtp_cipher_encrypt(stream->rtcp_cipher, NULL, &nolen);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
	/*
	 * Get the tag and append that to the output
	 */
	status = srtp_cipher_get_tag(stream->rtcp_cipher, (uint8_t*)auth_tag, &tag_len);
	if (status) {
	    return ( srtp_err_status_cipher_fail);
	}
	enc_octet_len += tag_len;
    }

    /* increase the packet length by the length of the auth tag and seq_num*/
    *pkt_octet_len += (tag_len + sizeof(srtcp_trailer_t));

    return srtp_err_status_ok;
}

/*
 * This function handles incoming SRTCP packets while in AEAD mode,
 * which currently supports AES-GCM encryption.  Note, the auth tag is 
 * at the end of the packet stream and is automatically checked by GCM
 * when decrypting the payload.
 */
static srtp_err_status_t
srtp_unprotect_rtcp_aead (srtp_stream_ctx_t *stream, 
                          void *srtcp_hdr,
                          unsigned int *pkt_octet_len,
                          uint32_t *seq_num)
{
    srtcp_hdr_t *hdr = (srtcp_hdr_t*)srtcp_hdr;
    uint32_t *enc_start;        /* pointer to start of encrypted portion  */
    uint32_t *trailer;          /* pointer to start of trailer            */
    unsigned int enc_octet_len = 0; /* number of octets in encrypted portion */
    uint8_t *auth_tag = NULL;   /* location of auth_tag within packet     */
    srtp_err_status_t status;
    int tag_len;
    unsigned int tmp_len;
    v128_t iv;
    uint32_t tseq;

    /* get tag length from stream context */
    tag_len = srtp_auth_get_tag_length(stream->rtcp_auth);

    /*
     * set encryption start, encryption length, and trailer
     */
    /* index & E (encryption) bit follow normal data.  hdr->len
           is the number of words (32-bit) in the normal packet minus 1 */
    /* This should point trailer to the word past the end of the
           normal data. */
    /* This would need to be modified for optional mikey data */
    /*
     * NOTE: trailer is 32-bit aligned because RTCP 'packets' are always
     *	 multiples of 32-bits (RFC 3550 6.1)
     */
    trailer = (uint32_t*)((char*)hdr + *pkt_octet_len - sizeof(srtcp_trailer_t));
    /*
     * We pass the tag down to the cipher when doing GCM mode 
     */
    enc_octet_len = *pkt_octet_len - (octets_in_rtcp_header + 
                                      sizeof(srtcp_trailer_t));
    auth_tag = (uint8_t*)hdr + *pkt_octet_len - tag_len - sizeof(srtcp_trailer_t);

    if (*((unsigned char*)trailer) & SRTCP_E_BYTE_BIT) {
        enc_start = (uint32_t*)hdr + uint32s_in_rtcp_header;
    } else {
        enc_octet_len = 0;
        enc_start = NULL; /* this indicates that there's no encryption */
    }

    /*
     * check the sequence number for replays
     */
    /* this is easier than dealing with bitfield access */
    *seq_num = ntohl(*trailer) & SRTCP_INDEX_MASK;
    debug_print(mod_srtp, "srtcp index: %x", *seq_num);
    status = srtp_rdb_check(&stream->rtcp_rdb, *seq_num);
    if (status) {
        return status;
    }

    /*
     * Calculate and set the IV
     */
    srtp_calc_aead_iv_srtcp(stream, &iv, *seq_num, hdr);
    status = srtp_cipher_set_iv(stream->rtcp_cipher, (uint8_t*)&iv, direction_decrypt);
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /*
     * Set the AAD for GCM mode
     */
    if (enc_start) {
	/*
	 * If payload encryption is enabled, then the AAD consist of
	 * the RTCP header and the seq# at the end of the packet
	 */
	status = srtp_cipher_set_aad(stream->rtcp_cipher, (uint8_t*)hdr, octets_in_rtcp_header);
	if (status) {
	    return srtp_err_status_cipher_fail;
	}
    } else {
	/*
	 * Since payload encryption is not enabled, we must authenticate
	 * the entire packet as described in section 10.3 in revision 07
	 * of the draft.
	 */
	status = srtp_cipher_set_aad(stream->rtcp_cipher, (uint8_t*)hdr, 
			            (*pkt_octet_len - tag_len - sizeof(srtcp_trailer_t)));
	if (status) {
	    return srtp_err_status_cipher_fail;
	}
    }

    /* 
     * Process the sequence# as AAD 
     */
    tseq = *trailer;
    status = srtp_cipher_set_aad(stream->rtcp_cipher, (uint8_t*)&tseq, sizeof(srtcp_trailer_t));
    if (status) {
	return srtp_err_status_cipher_fail;
    }

    /* if we're decrypting, exor keystream into the message */
    if (enc_start) {
        status = srtp_cipher_decrypt(stream->rtcp_cipher, (uint8_t*)enc_start, &enc_octet_len);
        if (status) {
            return status;
        }
    } else {
	/*
	 * Still need to run the cipher to check the tag
	 */
	tmp_len = tag_len;
        status = srtp_cipher_decrypt(stream->rtcp_cipher, (uint8_t*)auth_tag, &tmp_len);
        if (status) {
            return status;
        }
    }

    /* decrease the packet length by the length of the auth tag and seq_num*/
    *pkt_octet_len -= (tag_len + sizeof(srtcp_trailer_t));

    return srtp_err_status_ok;
}

srtp_err_status_t
srtp_process_protect_rtcp(srtp_ctx_t *ctx, void *rtcp_hdr, int *pkt_octet_len, srtp_stream_ctx_t *stream, srtp_service_flags_t flags) {
  srtp_xtd_seq_num_t est;
  unsigned long seq_num;
  srtcp_hdr_t *hdr = (srtcp_hdr_t *)rtcp_hdr;
  uint8_t *ektp;
  unsigned int ekt_tag_len = 0;
  uint32_t *trailer;        /* pointer to start of trailer            */
  srtp_err_status_t status;

  debug_print(mod_srtp, "function srtp_protect_rtcp", NULL);

  /*
  * Check if this is an AEAD stream (GCM mode).  If so, then dispatch
  * the request to our AEAD handler.
  */
  if (stream->rtcp_cipher->algorithm == SRTP_AES_128_GCM ||
    stream->rtcp_cipher->algorithm == SRTP_AES_256_GCM) {
    status = srtp_protect_rtcp_aead(stream, rtcp_hdr, (unsigned int*)pkt_octet_len);
    if (status)
      return status;

    /* For EKT and PRIME end-to-end, generate the EKT tag */
    if (stream->ektMode == ekt_mode_prime_end_to_end ||
        stream->ektMode == ekt_mode_regular) {
        ektp = (uint8_t *)hdr + *pkt_octet_len;
        status = ekt_generate_tag(stream, ctx, hdr, ektp, &ekt_tag_len, flags);
        *pkt_octet_len += ekt_tag_len;
    }
    return status;
  }

  /* all of the packet, except the header, gets encrypted */
  /* NOTE: hdr->length is not usable - it refers to only the first
           RTCP report in the compound packet! */
  /* NOTE: trailer is 32-bit aligned because RTCP 'packets' are always
     multiples of 32-bits (RFC 3550 6.1) */
  trailer = (uint32_t *) ((char *)hdr + *pkt_octet_len);
  if (stream->rtcp_services & sec_serv_conf) {
    *trailer = htonl(SRTCP_E_BIT);     /* set encrypt bit */
  }
  else {
    /* 0 is network-order independant */
    *trailer = 0x00000000;     /* set encrypt bit */
  }
  status = srtp_rdb_increment(&stream->rtcp_rdb);
  if (status) {
    return status;
  }
  seq_num = srtp_rdb_get_value(&stream->rtcp_rdb);
  *trailer |= htonl(seq_num);
  debug_print(mod_srtp, "srtcp index: %x", seq_num);

#ifdef NO_64BIT_MATH
  est = make64(0, seq_num);
#else
  est = seq_num;
#endif

  status = srtp_set_iv(rtcp_hdr,
                       stream->rtcp_cipher,
                       est,
                       direction_encrypt,
                       srtp_packet_rtcp);
  if (!status && stream->rtp_xtn_hdr_cipher) {
    status = srtp_set_iv(hdr,
                         stream->rtp_xtn_hdr_cipher,
                         est,
                         direction_encrypt,
                         srtp_packet_rtp);
  }
  if (status)
    return srtp_err_status_cipher_fail;

  /* Encrypt the packet */
  status = srtp_encrypt(stream, rtcp_hdr, *pkt_octet_len, srtp_packet_rtcp);
  if (status)
    return srtp_err_status_cipher_fail;

  *pkt_octet_len += sizeof(srtcp_trailer_t);

  /*
   * Generate authentication tag. For PRIME this function auth tag will not
   * be generated for E2E ctx because the auth func for E2E ctx is set to NULL.
   */
  status = srtp_generate_authentication_tag(stream,
                                            rtcp_hdr,
                                            pkt_octet_len,
                                            est,
                                            srtp_packet_rtcp);
  if (status != srtp_err_status_ok)
    return status;

  /* For EKT and PRIME end-to-end, generate the EKT tag */
  if (stream->ektMode == ekt_mode_regular ||
      stream->ektMode == ekt_mode_prime_end_to_end) {
    ektp = (uint8_t *) hdr + *pkt_octet_len;
    status = ekt_generate_tag(stream, ctx, hdr, ektp, &ekt_tag_len, flags);
    if (status)
      return srtp_err_status_cipher_fail;
    *pkt_octet_len += ekt_tag_len;
  }

  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_protect_rtcp_with_flags(srtp_t ctx,
                             void *rtcp_hdr,
                             int *pkt_octet_len,
                             srtp_service_flags_t flags) {
  srtcp_hdr_t *hdr = (srtcp_hdr_t *)rtcp_hdr;
  srtp_err_status_t status;
  srtp_stream_ctx_t *stream;

  /* we assume the hdr is 32-bit aligned to start */

  /* check the packet length - it must at least contain a full header */
  if (*pkt_octet_len < octets_in_rtcp_header)
    return srtp_err_status_bad_param;

  /*
   * look up ssrc in srtp_stream list, and process the packet with
   * the appropriate stream.  if we haven't seen this stream before,
   * there's only one key for this srtp_session, and the cipher
   * supports key-sharing, then we assume that a new stream using
   * that key has just started up
   */
  stream = srtp_get_stream(ctx, hdr->ssrc);
  if (stream == NULL) {
    if (ctx->stream_template != NULL) {
      srtp_stream_ctx_t *new_stream;

      /* allocate and initialize a new stream */
      status = srtp_stream_clone(ctx->stream_template,
                                 hdr->ssrc, &new_stream);
      if (status)
          return status;

      /* add new stream to the head of the stream_list */
      stream = ctx->stream_template;
      new_stream->next = ctx->stream_list;
      ctx->stream_list = new_stream;

      /* set stream (the pointer used in this function) */
      stream = new_stream;
    }
    else {
      /* no template stream, so we return an error */
      return srtp_err_status_no_ctx;
    }
  }

  /*
   * verify that stream is for sending traffic - this check will
   * detect SSRC collisions, since a stream that appears in both
   * srtp_protect() and srtp_unprotect() will fail this test in one of
   * those functions.
   */
  if (stream->direction != dir_srtp_sender) {
    if (stream->direction == dir_unknown) {
      stream->direction = dir_srtp_sender;
    }
    else {
      srtp_handle_event(ctx, stream, event_ssrc_collision);
    }
  }

  status = srtp_process_protect_rtcp(ctx, hdr, pkt_octet_len, stream, flags);
  if (status)
    return status;

  /*
   * check sequence number for overruns, and copy it into the packet
   * if its value isn't too big
   */
  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_protect_rtcp(srtp_t ctx, void *rtcp_hdr, int *pkt_octet_len) {

    return srtp_protect_rtcp_with_flags(ctx,
                                        rtcp_hdr,
                                        pkt_octet_len,
                                        srtp_service_default);
}


srtp_err_status_t
srtp_process_unprotect_rtcp(void *srtcp_hdr,
                            srtp_ctx_t *ctx,
                            srtp_stream_ctx_t *stream,
                            int *pkt_octet_len,
                            uint32_t *seq_num) {
  srtcp_hdr_t *hdr = (srtcp_hdr_t *)srtcp_hdr;
  srtp_err_status_t status;
  unsigned int tag_len;
  uint8_t master_key_in_stream[MAX_SRTP_KEY_LEN];
  int key_len = 0;
  int replaced_stream_key;
  srtp_xtd_seq_num_t est;           /* RTCP paccket sequence number         */
  uint32_t *trailer;                /* pointer to start of trailer          */
  ekt_tag_contents_t ekt_tag_contents;

  /*
   * If EKT tag is present then extract the EKT tag and initialize the key
   * in the context with the key received in the EKT tag
   */
  if (stream->ektMode == ekt_mode_regular ||
      stream->ektMode == ekt_mode_prime_end_to_end) {

    status = ekt_parse_tag(stream,
                           ctx,
                           srtcp_hdr,
                           pkt_octet_len,
                           &ekt_tag_contents);
    if (status != srtp_err_status_ok || status != srtp_err_no_ekt)
      return status;

    /* Recheck header since EKT tag extraction reduces the packet length */
    if (*pkt_octet_len < (int)(octets_in_rtcp_header + sizeof(srtcp_trailer_t)))
      return srtp_err_status_bad_param;

    if (ekt_tag_contents.present) {
      key_len = srtp_cipher_get_key_length(stream->rtp_cipher);
      if (memcmp(ekt_tag_contents.master_key, stream->master_key, key_len)) {
        status = srtp_stream_init_keys(stream, ekt_tag_contents.master_key);
        if (status != srtp_err_status_ok) {
          srtp_stream_init_keys(stream, stream->master_key);
          return status;
        }
        memcpy(master_key_in_stream, stream->master_key, key_len);
        memcpy(stream->master_key, ekt_tag_contents.master_key, key_len);
        replaced_stream_key = 1;
      }
      else {
        replaced_stream_key = 0;
        debug_print(mod_srtp,
            "Key update is not needed since same key received in EKT tag\n",
            NULL);
      }
    }
    else {
      replaced_stream_key = 0;
      debug_print(mod_srtp,
        "Key update is not needed since EKT tag not present \n",
        NULL);
    }
  }
  else {
    replaced_stream_key = 0;
  }

  /*
   * Check if this is an AEAD stream (GCM mode).  If so, then dispatch
   * the request to our AEAD handler.
   */
  if (stream->rtcp_cipher->algorithm == SRTP_AES_128_GCM ||
      stream->rtcp_cipher->algorithm == SRTP_AES_256_GCM) {
    status = srtp_unprotect_rtcp_aead(stream,
                                      srtcp_hdr,
                                      (unsigned int*) pkt_octet_len,
                                      seq_num);
    if (status) {
      if (replaced_stream_key) {
        memcpy(stream->master_key, master_key_in_stream, key_len);
        srtp_stream_init_keys(stream, stream->master_key);
      }
    }

    /* AES GCM packet is authenticated already, so return */
    return status;
  }

  /* Get tag length from stream context */
  tag_len = srtp_auth_get_tag_length(stream->rtcp_auth);
  trailer = (uint32_t *)((char *)hdr +
                         *pkt_octet_len - (tag_len + sizeof(srtcp_trailer_t)));

  /* Check the sequence number for replays */
  *seq_num = ntohl(*trailer) & SRTCP_INDEX_MASK;
  debug_print(mod_srtp, "srtcp index: %x", *seq_num);
  status = srtp_rdb_check(&stream->rtcp_rdb, *seq_num);
  if (status) {
    if (replaced_stream_key) {
        memcpy(stream->master_key, master_key_in_stream, key_len);
        srtp_stream_init_keys(stream, stream->master_key);
    }
    return status;
  }
#ifdef NO_64BIT_MATH
  est = make64(0, *seq_num)
#else
  est = (srtp_xtd_seq_num_t) *seq_num;
#endif

  /* Set the IV properly */
  status = srtp_set_iv(srtcp_hdr,
                       stream->rtcp_cipher,
                       est,
                       direction_decrypt,
                       srtp_packet_rtcp);
  if (status) {
    if (replaced_stream_key) {
        memcpy(stream->master_key, master_key_in_stream, key_len);
        srtp_stream_init_keys(stream, stream->master_key);
    }
    return status;
  }

  /* Authenticate the RTCP packet */
  status = srtp_authenticate(stream, srtcp_hdr, (unsigned int*)pkt_octet_len, est, srtp_packet_rtcp);

  if (status) {
    if (replaced_stream_key) {
        memcpy(stream->master_key, master_key_in_stream, key_len);
        srtp_stream_init_keys(stream, stream->master_key);
    }
    return status;
  }

  status = srtp_decrypt(stream, hdr, pkt_octet_len, srtp_packet_rtcp);
  if (status != srtp_err_status_cant_check && status != srtp_err_status_ok) {
    if (replaced_stream_key) {
        memcpy(stream->master_key, master_key_in_stream, key_len);
        srtp_stream_init_keys(stream, stream->master_key);
    }
    return srtp_err_status_cipher_fail;
  }

  /* Decrease the packet length by the length of the auth tag and seq_num */
  *pkt_octet_len -= (sizeof(srtcp_trailer_t));

  return srtp_err_status_ok;
}


srtp_err_status_t
srtp_unprotect_rtcp_with_flags(srtp_t ctx,
                               void *srtcp_hdr,
                               int *pkt_octet_len,
                               srtp_service_flags_t flags) {
  srtcp_hdr_t *hdr = (srtcp_hdr_t *)srtcp_hdr;
  srtp_err_status_t status;
  srtp_stream_ctx_t *stream;
  unsigned int tag_len;
  uint32_t seq_num;

  /*
   * Check that the length value is sane; we'll check again once we
   * know the tag length, but we at least want to know that it is
   * a positive value
   */
  if (*pkt_octet_len < (int)(octets_in_rtcp_header + sizeof(srtcp_trailer_t)))
    return srtp_err_status_bad_param;

  /*
   * Look up SSRC in srtp_stream list, and process the packet with
   * the appropriate stream.  if we haven't seen this stream before,
   * there's only one key for this srtp_session, and the cipher
   * supports key-sharing, then we assume that a new stream using
   * that key has just started up
   */
  stream = srtp_get_stream(ctx, hdr->ssrc);
  if (stream == NULL) {
    if (ctx->stream_template != NULL) {
      stream = ctx->stream_template;
      debug_print(mod_srtp, "srtcp using provisional stream (SSRC: 0x%08x)",
                  hdr->ssrc);
    }
    else {
      /* No template stream, so we return an error */
      return srtp_err_status_no_ctx;
    }
  }

  /* Get tag length from stream context */
  tag_len = srtp_auth_get_tag_length(stream->rtcp_auth);

  /*
   * Check the packet length - it must contain at least a full RTCP
   * header, an auth tag (if applicable), and the SRTCP encrypted flag
   * and 31-bit index value
   */
  if ((unsigned int)(*pkt_octet_len) < (octets_in_rtcp_header + tag_len + sizeof(srtcp_trailer_t))) {
    return srtp_err_status_bad_param;
  }

  /* Authenticate and/or decrypt the packet */
  status = srtp_process_unprotect_rtcp(srtcp_hdr,
                                       ctx,
                                       stream,
                                       pkt_octet_len,
                                       &seq_num);
  if (status)
    return status;

  /*
   * Verify that stream is for received traffic - this check will
   * detect SSRC collisions, since a stream that appears in both
   * srtp_protect() and srtp_unprotect() will fail this test in one of
   * those functions.
   *
   * We do this check *after* the authentication check, so that the
   * latter check will catch any attempts to fool us into thinking
   * that we've got a collision
   */
  if (stream->direction != dir_srtp_receiver) {
    if (stream->direction == dir_unknown) {
      stream->direction = dir_srtp_receiver;
    } else {
      srtp_handle_event(ctx, stream, event_ssrc_collision);
    }
  }

  /*
   * if the stream is a 'provisional' one, in which the template context
   * is used, then we need to allocate a new stream at this point, since
   * the authentication passed
   */
  if (stream == ctx->stream_template) {
    srtp_stream_ctx_t *new_stream;

    /*
     * allocate and initialize a new stream
     *
     * note that we indicate failure if we can't allocate the new
     * stream, and some implementations will want to not return
     * failure here
     */
    status = srtp_stream_clone(ctx->stream_template, hdr->ssrc, &new_stream);
    if (status) {
      return status;
    }

    /* add new stream to the head of the stream_list */
    new_stream->next = ctx->stream_list;
    ctx->stream_list = new_stream;

    /* set stream (the pointer used in this function) */
    stream = new_stream;
  }

  /* we've passed the authentication check, so add seq_num to the rdb */
  return (srtp_rdb_add_index(&stream->rtcp_rdb, seq_num));
}

srtp_err_status_t
srtp_unprotect_rtcp(srtp_t ctx, void *srtcp_hdr, int *pkt_octet_len) {

  srtp_err_status_t status;

  debug_print(mod_srtp, "function srtp_unprotect_rtcp", NULL);

  status = srtp_unprotect_rtcp_with_flags(ctx,
                                          srtcp_hdr,
                                          pkt_octet_len,
                                          srtp_service_default);

  if (status) {
    debug_print(mod_srtp, "function srtp_unprotect_rtcp: failed to unprotect packet", NULL);
  }

  return status;
}


/*
 * user data within srtp_t context
 */

void
srtp_set_user_data(srtp_t ctx, void *data) {
  ctx->user_data = data;
}

void*
srtp_get_user_data(srtp_t ctx) {
  return ctx->user_data;
}


/*
 * dtls keying for srtp 
 */

srtp_err_status_t
srtp_crypto_policy_set_from_profile_for_rtp(srtp_crypto_policy_t *policy, 
				            srtp_profile_t profile) {

  /* set SRTP policy from the SRTP profile in the key set */
  switch(profile) {
  case srtp_profile_aes128_cm_sha1_80:
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
    break;
  case srtp_profile_aes128_cm_sha1_32:
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(policy);
    break;
  case srtp_profile_null_sha1_80:
    srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
    break;
  case srtp_profile_aes256_cm_sha1_80:
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(policy);
    break;
  case srtp_profile_aes256_cm_sha1_32:
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(policy);
    break;
    /* the following profiles are not (yet) supported */
  case srtp_profile_null_sha1_32:
  default:
    return srtp_err_status_bad_param;
  }

  return srtp_err_status_ok;
}

srtp_err_status_t
srtp_crypto_policy_set_from_profile_for_rtcp(srtp_crypto_policy_t *policy, 
					     srtp_profile_t profile) {

  /* set SRTP policy from the SRTP profile in the key set */
  switch(profile) {
  case srtp_profile_aes128_cm_sha1_80:
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
    break;
  case srtp_profile_aes128_cm_sha1_32:
    /* We do not honor the 32-bit auth tag request since
     * this is not compliant with RFC 3711 */
    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
    break;
  case srtp_profile_null_sha1_80:
    srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
    break;
  case srtp_profile_aes256_cm_sha1_80:
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(policy);
    break;
  case srtp_profile_aes256_cm_sha1_32:
    /* We do not honor the 32-bit auth tag request since
     * this is not compliant with RFC 3711 */
    srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(policy);
    break;
    /* the following profiles are not (yet) supported */
  case srtp_profile_null_sha1_32:
  default:
    return srtp_err_status_bad_param;
  }

  return srtp_err_status_ok;
}

void srtp_append_salt_to_key(uint8_t *key, unsigned int bytes_in_key, uint8_t *salt, unsigned int bytes_in_salt) {
  memcpy(key + bytes_in_key, salt, bytes_in_salt);
}

unsigned int
srtp_profile_get_master_key_length(srtp_profile_t profile) {

  switch(profile) {
  case srtp_profile_aes128_cm_sha1_80:
    return 16;
    break;
  case srtp_profile_aes128_cm_sha1_32:
    return 16;
    break;
  case srtp_profile_null_sha1_80:
    return 16;
    break;
  case srtp_profile_aes256_cm_sha1_80:
    return 32;
    break;
  case srtp_profile_aes256_cm_sha1_32:
    return 32;
    break;
    /* the following profiles are not (yet) supported */
  case srtp_profile_null_sha1_32:
  default:
    return 0;  /* indicate error by returning a zero */
  }
}

unsigned int
srtp_profile_get_master_salt_length(srtp_profile_t profile) {

  switch(profile) {
  case srtp_profile_aes128_cm_sha1_80:
    return 14;
    break;
  case srtp_profile_aes128_cm_sha1_32:
    return 14;
    break;
  case srtp_profile_null_sha1_80:
    return 14;
    break;
  case srtp_profile_aes256_cm_sha1_80:
    return 14;
    break;
  case srtp_profile_aes256_cm_sha1_32:
    return 14;
    break;
    /* the following profiles are not (yet) supported */
  case srtp_profile_null_sha1_32:
  default:
    return 0;  /* indicate error by returning a zero */
  }
}

/*
 * SRTP debug interface
 */
srtp_err_status_t srtp_set_debug_module(char *mod_name, int v)
{
    return srtp_crypto_kernel_set_debug_module(mod_name, v);
}

srtp_err_status_t srtp_list_debug_modules(void)
{
    return srtp_crypto_kernel_list_debug_modules();
}

