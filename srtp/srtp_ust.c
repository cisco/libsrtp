/*
 * srtp.c
 *
 *  the secure real-time transport protocol
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *	
 * Copyright (c) 2001-2005, Cisco Systems, Inc.
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


#include "alloc.h"           /* for crypto_alloc() */
#include "srtp.h"
#include "rijndael-icm.h"    /* for rijndael_icm   */


extern cipher_type_t rijndael_icm;
extern auth_type_t   tmmhv2;

/* the debug module for srtp */

debug_module_t mod_srtp = {
  0,                  /* debugging is off by default */
  "srtp"              /* printable name for module   */
};

#define octets_in_rtp_header  12
#define uint32s_in_rtp_header 3

err_status_t
srtp_alloc(srtp_ctx_t    **ctx_ptr,
	    cipher_type_id_t c_id,
	    int              cipher_key_len, 
	    auth_type_id_t   a_id,
	    int              auth_key_len,
	    int              auth_tag_len,
	    sec_serv_t       sec_serv) {

  err_status_t stat;
  srtp_ctx_t *ctx;

  /* allocate srtp context and set ctx_ptr */
  ctx = (srtp_ctx_t *) crypto_alloc(sizeof(srtp_ctx_t));
  if (ctx == NULL)
    return err_status_alloc_fail;
  *ctx_ptr = ctx;

  /* set security services flag */
  ctx->services = sec_serv;

  /* allocate ust context */
  stat = ust_alloc(&ctx->ust,     /* ust context                       */
		   c_id,          /* keystream generator identifier    */
		   cipher_key_len,/* number of octets in cipher key    */
		   a_id,          /* auth algorithm specification      */
		   auth_key_len,  /* number of octets in the auth key  */
		   auth_tag_len,  /* number of octets in the auth tag  */
		   128            /* bits in replay window             */
		   );
  
  if (stat) {
    free(ctx);
    return stat;
  }
 
  return err_status_ok;
}

/*
 * srtp_init_aes_128_prf(ctx, key) initializes an srtp_ctx_t
 * with a given master key.  (The offset or salt value is assumed
 * to be the trailing octets of the key.)
 * 
 * the key MUST be 30 octets long
 *
 * The PRF used for key derivation here is that defined in the secure
 * rtp specification, though in theory, other PRFs can be used.  The
 * cipher is hardwired to AES-128 Counter Mode with 112 bits of salt.
 */

typedef enum {
  label_encryption             = 0x00,
  label_message_authentication = 0x01,
  label_salt                   = 0x02
} srtp_prf_label;

err_status_t
srtp_init_aes_128_prf(srtp_ctx_t *srtp, const octet_t key[30]) {
  err_status_t stat;
  rijndael_icm_context c;
  xtd_seq_num_t idx = 0;               /* for setting icm to zero-index   */   
  octet_t *buffer;                     /* temporary storage for keystream */
  octet_t *enc_key_buf, *enc_salt_buf, *auth_key_buf; 
  int buffer_size;

  rdbx_init(&srtp->ust.rdbx);

  debug_print(mod_srtp, "srtp_init_aes_128_prf()", NULL);

  /* allocate temporary storage, set pointers, and zeroize buffer */
  buffer_size = cipher_get_key_length(srtp->ust.c)
    + auth_get_key_length(srtp->ust.h);

  /* if we're using rijndael_icm, we need to allocate room for the salt */
  if (srtp->ust.c->type == &rijndael_icm)
    buffer_size += 16;
  buffer = crypto_alloc(buffer_size);
  if (buffer == NULL)
    return err_status_alloc_fail;
  enc_key_buf = buffer;
  enc_salt_buf = buffer + cipher_get_key_length(srtp->ust.c);
  auth_key_buf = enc_salt_buf + 16;  /* DAM - this should depend on cipher! */
  octet_string_set_to_zero(buffer, buffer_size);
    
  /* generate encryption key, putting it into enc_key_buf  */

  /* note that we assume that index DIV t == 0 in this implementation */
  
  rijndael_icm_context_init(&c, key);

  /* exor <label> into the eigth octet of the state */
  rijndael_icm_set_div_param(&c, (uint64_t) label_encryption);
  rijndael_icm_set_segment(&c, idx);

  debug_print(mod_srtp, "master key: %s", 
	      octet_string_hex_string((octet_t *)&c.expanded_key[0], 60));
  debug_print(mod_srtp, "generating cipher key", NULL);
  debug_print(mod_srtp, "cipher ctr: %s", 
	      octet_string_hex_string((octet_t *)&c.counter, 32));  

  rijndael_icm_encrypt(&c, enc_key_buf, 
		       cipher_get_key_length(srtp->ust.c));

  debug_print(mod_srtp, "cipher key: %s", 
	      octet_string_hex_string(enc_key_buf, 32));  

  /* generate encryption salt, putting it into enc_salt_buf */
  rijndael_icm_context_init(&c, key);


  /* 
   * if the cipher in the srtp context is rijndael_icm, then we need
   * to generate the salt value
   */

  if (srtp->ust.c->type == &rijndael_icm) {

/*     printf("found rijndael_icm, generating salt\n"); */

    /* exor <label> into the eigth octet of the state */
    rijndael_icm_set_div_param(&c, (uint64_t) label_salt); 
    rijndael_icm_set_segment(&c, idx);
    
    debug_print(mod_srtp, "generating cipher salt", NULL);
    debug_print(mod_srtp, "cr slt ctr: %s", 
		octet_string_hex_string((octet_t *)&c.counter, 32));  

    rijndael_icm_encrypt(&c, enc_salt_buf, 14);

    debug_print(mod_srtp, "cipher slt: %s", 
		octet_string_hex_string(enc_salt_buf, 32));  

    /*
     * we don't yet know the ssrc of the sender, so we don't exor the
     * ssrc value into the enc_salt_buf
     */
  }
  
  /* generate authentication key, putting it into auth_key_buf */

  rijndael_icm_context_init(&c, key);

  /* exor <label> into the eigth octet of the state */
  rijndael_icm_set_div_param(&c, (uint64_t) label_message_authentication);
  rijndael_icm_set_segment(&c, idx);

  debug_print(mod_srtp, "generating auth key", NULL);
  debug_print(mod_srtp, "auth ctr:   %s",
	      octet_string_hex_string((octet_t *)&c.counter, 32));  

  rijndael_icm_encrypt(&c, auth_key_buf,
		       auth_get_key_length(srtp->ust.h));
  
  debug_print(mod_srtp, "auth key:   %s",
	      octet_string_hex_string(auth_key_buf, 
	          2*auth_get_key_length(srtp->ust.h))); 
  
  /* initialize ust context with keys */
  stat = ust_init(&srtp->ust, enc_key_buf, auth_key_buf);  
  if (stat) {
    free(buffer);
    return err_status_init_fail;
  }  

  /* free memory then return */
  free(buffer);
  return err_status_ok;  
}


err_status_t
srtp_protect(srtp_ctx_t *ctx, srtp_hdr_t *hdr, int *pkt_octet_len) {
  uint32_t *enc_start;      /* pointer to start of encrypted portion  */
  uint32_t *auth_start;     /* pointer to start of auth. portion      */
  int enc_octet_len = 0;    /* number of octets in encrypted portion  */
  xtd_seq_num_t est;        /* estimated xtd_seq_num_t of *hdr        */
  int delta;                /* delta of local pkt idx and that in hdr */
  octet_t *auth_tag = NULL; /* location of auth_tag within packet     */
  err_status_t status;   
  int tag_len = ust_get_tag_len(&ctx->ust); 
 
  /* if we're using rindael counter mode, exor the ssrc into the salt */
  if (ctx->ust.c->type == &rijndael_icm) {
    uint32_t ssrc = ntohl(hdr->ssrc);
    rijndael_icm_context *cipher 
      = (rijndael_icm_context *)ctx->ust.c->state;

    /* exor the ssrc into bytes four through seven of the salt */
    cipher->offset.octet[4] ^= (ssrc >> 24);
    cipher->offset.octet[5] ^= (ssrc >> 16) & 0xff;
    cipher->offset.octet[6] ^= (ssrc >> 8) & 0xff;
    cipher->offset.octet[7] ^= ssrc & 0xff;
  }

  /*
   * find starting point for encryption and length of data to be
   * encrypted - the encrypted portion starts after the rtp header
   * extension, if present; otherwise, it starts after the last csrc,
   * if any are present
   *
   * if we're not providing confidentiality, set enc_start to NULL
   */
  if (ctx->services & sec_serv_conf) {
    enc_start = (uint32_t *)hdr + uint32s_in_rtp_header + hdr->cc;  
    if (hdr->x == 1) 
      enc_start += ((srtp_hdr_xtnd_t *)enc_start)->length;
    enc_octet_len = *pkt_octet_len - ((enc_start - (uint32_t *)hdr) << 2);
  } else {
    enc_start = NULL;
  }

  /* 
   * if we're providing authentication, set the auth_start and auth_tag
   * pointers to the proper locations; otherwise, set auth_start to NULL
   * to indicate that no authentication is needed
   */
  if (ctx->services & sec_serv_auth) {
    auth_start = (uint32_t *)hdr;
    auth_tag = (octet_t *)hdr + *pkt_octet_len;
  } else {
    auth_start = NULL;
    auth_tag = NULL;
  }

  /*
   * estimate the packet index using the start of the replay window   
   * and the sequence number from the header
   */
  delta = rdbx_estimate_index(&ctx->ust.rdbx, &est, ntohs(hdr->seq));
  if (rdbx_check(&ctx->ust.rdbx, delta) != replay_check_ok)
    return err_status_replay_fail;  /* we've been asked to reuse an index */
  rdbx_add_index(&ctx->ust.rdbx, delta);

  status = 
  ust_xfm(&ctx->ust,           /* ust context                      */
	  est,                 /* index                            */
	  (octet_t *)enc_start,/* pointer to encryption start      */
	  enc_octet_len,       /* number of octets to encrypt      */
	  (octet_t *)hdr,      /* pointer to authentication start  */
	  *pkt_octet_len,      /* number of octets to authenticate */
	  auth_tag);           /* authentication tag               */
	  
#if 0  
  status = 
  ust_xfm_u16(&ctx->ust,           /* ust context                      */
	      ntohs(hdr->seq),     /* index                            */
	      (octet_t *)enc_start,/* pointer to encryption start      */
	      enc_octet_len,       /* number of octets to encrypt      */
	      (octet_t *)hdr,      /* pointer to authentication start  */
	      *pkt_octet_len,      /* number of octets to authenticate */
	      auth_tag);           /* authentication tag               */
#endif
  
  /* increase the packet length by the length of the auth tag */
  *pkt_octet_len += tag_len;
    
  return err_status_ok;  
}


err_status_t
srtp_unprotect(srtp_ctx_t *ctx, srtp_hdr_t *hdr, int *pkt_octet_len) {
  uint32_t *enc_start;      /* pointer to start of encrypted portion  */
  uint32_t *auth_start;     /* pointer to start of auth. portion      */
  int enc_octet_len = 0;    /* number of octets in encrypted portion  */
  octet_t *auth_tag = NULL; /* location of auth_tag within packet     */
  err_status_t status;   
  int tag_len = ust_get_tag_len(&ctx->ust); 

  /*
   * look up ssrc in srtp_stream list, and process the packet with 
   * the appropriate stream.  if we haven't seen this stream before,
   * there's only one key for this srtp_session, and the cipher
   * supports key-sharing, then we assume that a new stream using
   * that key has just started up
   */
#if 0
  stream = srtp_stream_lookup(&ctx);
  if (stream == NULL)
    stream = temp_stream;
#endif
  /* 
   * add ssrc into cipher context ("diversification") - note that if
   * the cipher does not support this operation, it will silently
   * fail, which is actually what we want here 
   */
  ust_set_diversifier(&ctx->ust, ntohl(hdr->ssrc));

  /*
   * find starting point for decryption and length of data to be
   * decrypted - the encrypted portion starts after the rtp header
   * extension, if present; otherwise, it starts after the last csrc,
   * if any are present
   *
   * if we're not providing confidentiality, set enc_start to NULL
   */
  if (ctx->services & sec_serv_conf) {
    enc_start = (uint32_t *)hdr + uint32s_in_rtp_header + hdr->cc;  
    if (hdr->x == 1) 
      enc_start += ((srtp_hdr_xtnd_t *)enc_start)->length;
    enc_octet_len = *pkt_octet_len - tag_len
      - ((enc_start - (uint32_t *)hdr) << 2);
  } else {
    enc_start = NULL;
  }

  /* 
   * if we're providing authentication, set the auth_start and auth_tag
   * pointers to the proper locations; otherwise, set auth_start to NULL
   * to indicate that no authentication is needed
   */
  if (ctx->services & sec_serv_auth) {
    auth_start = (uint32_t *)hdr;
    auth_tag = (octet_t *)hdr + *pkt_octet_len - tag_len;
  } else {
    auth_start = NULL;
    auth_tag = NULL;
  }

  /* at this point, the ust context should look into the stream */
  status = 
  ust_inv_xfm_u16(
	      &ctx->ust,                /* ust context                 */
	      ntohs(hdr->seq),          /* index                       */
	      (octet_t *)enc_start,     /* pointer to encryption start */
	      enc_octet_len,            /* number of octets to encrypt */
	      (octet_t *)hdr,           /* pointer to auth start       */
	      *pkt_octet_len - tag_len, /* num octets to authenticate  */
	      auth_tag);                /* authentication tag          */

  if (status)
    return status;

  /* decrease the packet length by the length of the auth tag */
  *pkt_octet_len -= tag_len;
    
  return err_status_ok;  
}


/*
 * srtp_get_trailer_length(&a) returns the number of octets that will
 * be added to an RTP packet by the SRTP processing.  This value
 * is constant for a given srtp_ctx_t (i.e. between initializations).
 */

int
srtp_get_trailer_length(const srtp_t a) {
  return ust_get_tag_len(&a->ust);
}

/* 
 * srtp_print_packet(...) is for debugging only 
 * it prints an RTP packet to the stdout
 */

#include <stdio.h>

void
srtp_print_packet(srtp_hdr_t *hdr, int pkt_octet_len) {
  octet_t *data = ((octet_t *)hdr)+octets_in_rtp_header;
  int hex_len = 2*(pkt_octet_len-octets_in_rtp_header);

  printf("rtp packet: {\n");
  printf("   version:\t%d\n", hdr->version);
  printf("   p:\t\t%d\n", hdr->p);
  printf("   x:\t\t%d\n", hdr->x);
  printf("   cc:\t\t%d\n", hdr->cc);
  printf("   m:\t\t%d\n", hdr->m);
  printf("   pt:\t\t%x\n", hdr->pt);
  printf("   seq:\t\t%x\n", hdr->seq);
  printf("   ts:\t\t%x\n", hdr->ts);
  printf("   ssrc:\t%x\n", hdr->ssrc);
  printf("   data:\t%s\n", octet_string_hex_string(data, hex_len));
  printf("} (%d octets in data)\n", pkt_octet_len-octets_in_rtp_header);

}

