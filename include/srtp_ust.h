/*
 * srtp.h
 *
 * interface to libsrtp
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


#ifndef SRTP_H
#define SRTP_H

#include "crypto_kernel.h"
#include "rdbx.h"
#include "integers.h"

/* a sec_serv_t describes a set of security services */

typedef enum {
  sec_serv_none          = 0,
  sec_serv_conf          = 1,
  sec_serv_auth          = 2,
  sec_serv_conf_and_auth = 3
} sec_serv_t;

/* srtp_ctx_t stores all of the state needed for an srtp session */

#include "ust.h"

typedef struct {
  ust_ctx_t  ust;
  sec_serv_t services;
  uint32_t   ssrc;
} srtp_ctx_t;


/*
 * an srtp_hdr_t represents the srtp header
 *
 * in this implementation, an srtp_hdr_t is assumed to be 32-bit aligned
 * 
 * (note that this definition follows that of RFC 1889 Appendix A, but
 * is not identical)
 */

#if (WORDS_BIGENDIAN == 0) /* assume LITTLE_ENDIAN */

typedef struct {
  unsigned char cc:4;		/* CSRC count */
  unsigned char x:1;		/* header extension flag */
  unsigned char p:1;		/* padding flag */
  unsigned char version:2;	/* protocol version */
  unsigned char pt:7;		/* payload type */
  unsigned char m:1;		/* marker bit */
  uint16_t seq;			/* sequence number */
  uint32_t ts;			/* timestamp */
  uint32_t ssrc;	       	/* synchronization source */
} srtp_hdr_t;

#else /*  BIG_ENDIAN */

typedef struct {
  unsigned char version:2;	/* protocol version */
  unsigned char p:1;		/* padding flag */
  unsigned char x:1;		/* header extension flag */
  unsigned char cc:4;		/* CSRC count */
  unsigned char m:1;		/* marker bit */
  unsigned char pt:7;		/* payload type */
  uint16_t seq;			/* sequence number */
  uint32_t ts;			/* timestamp */
  uint32_t ssrc;	       	/* synchronization source */
} srtp_hdr_t;

#endif

typedef struct {
  uint16_t profile_specific;    /* profile-specific info */
  uint16_t length;              /* number of 32-bit words in extension */
} srtp_hdr_xtnd_t;



/*
 * an srtp_t is a pointer to an srtp_ctx_t - we define this to 
 * improve encapsualtion
 *
 */

typedef srtp_ctx_t *srtp_t;


/*
 * srtp_protect(ctx, pkt, len) applies secure rtp protection to the
 * packet pkt (which has length *len) using the srtp context ctx.  this
 * is the srtp sender-side packet processing function.
 * 
 *    nota bene: this function assumes that it can write the auth tag
 *    to the end of the packet
 *
 * ctx is a pointer to the srtp_ctx_t which applies to
 * the particular packet
 *
 * pkt is a pointer to the rtp packet (before the call); after
 * the function returns, it points to the srtp packet
 *
 * pkt_octet_len is a pointer to the length in octets of the complete
 * RTP packet (header and body) before the function call, and of the
 * complete SRTP packet after the call
 *
 * return values:
 *
 *    err_status_ok            no problems
 *    err_status_replay_fail   rtp sequence number was non-increasing
 *    <other>                  failure in cryptographic mechanisms
 */

err_status_t
srtp_protect(srtp_t ctx, srtp_hdr_t *pkt, int *pkt_octet_len);
	     
/*
 * srtp_unprotect(ctx, pkt, len) applies secure rtp protection to the
 * srtp packet pointed to by pkt (which has length *len), using the
 * srtp contet pointed to by ctx.  this is the secure rtp receiver-side
 * packet processing function.
 *
 * ctx is a pointer to the srtp_ctx_t which applies to
 * the particular packet
 *
 * pkt is a pointer to the srtp packet (before the call).  after the
 * function returns, it points to the rtp packet if err_status_ok was
 * returned; otherwise, the value of the data to which it points is
 * undefined.
 *
 * pkt_octet_len is a pointer to the length in octets of the complete
 * srtp packet (header and body) before the function call, and of the
 * complete rtp packet after the call, if err_status_ok was returned.
 * otherwise, the value of the data to which it points is undefined.
 *
 * return values:
 * 
 *    err_status_ok           the rtp packet is valid
 *    err_status_auth_fail    the srtp packet failed message authentication
 *    err_status_replay_fail  the srtp packet is a replay (this packet has
 *                            already been processed)
 *    <other>                 failure in cryptographic mechanisms
 * 
 * if err_status_ok is returned, then pkt points to the RTP packet
 * and pkt_octet_len is the number of octets in that packet;  otherwise,
 * no assumptions should be made about either data elements.
 */

err_status_t
srtp_unprotect(srtp_t ctx, srtp_hdr_t *pkt, int *pkt_octet_len);

/*
 * srtp_alloc(ctx, ...) allocates a secure rtp context (srtp_ctx_t) and 
 * sets ctx to point to that value..  the other arguments are the parameter
 * values for the srtp context; see the comments in the declaration.
 * 
 * after an srtp_ctx_t is allocated, it must be initialized by calling
 * the srtp_init_aes_128_prf(...) function (see below).  an
 * alternative but unrecommended method is to initialize the cipher_t
 * and auth_t using the cipher and auth apis.
 *
 * return values:
 * 
 *   err_status_ok            no problems
 *   err_status_alloc_fail    a memory allocation failure occured
 */

err_status_t
srtp_alloc(srtp_t *ctx,                /* srtp context                */
	   cipher_type_id_t c_id,      /* cipher type                 */
	   int cipher_key_len,         /* cipher key length in octets */
	   auth_type_id_t a_id,        /* authentication func type    */
	   int auth_key_len,           /* auth key length in octets   */
	   int auth_tag_len,           /* auth tag length in octets   */
	   sec_serv_t sec_serv         /* security services flag      */
	   ); 


/*
 * srtp_dealloc(ctx) deallocates storage for an srtp_ctx_t.  this
 * function should be called exactly once to deallocate the storage
 * allocated by the function call srtp_alloc(ctx).
 *
 * return values:
 *
 *    err_status_ok             no problems
 *    err_status_dealloc_fail   a memory deallocation failure occured
 */

err_status_t
srtp_dealloc(srtp_t ctx);

/*
 * srtp_init_aes_128_prf(ctx, key, salt) initializes an srtp_ctx_t
 * with a given master key and master salt.
 * 
 * the key MUST be sixteen octets long
 * 
 * the salt MUST be fourteen octets long
 *
 * The PRF used for key derivation here is that defined in the secure
 * rtp specification, though in theory other PRFs can be used.  The
 * cipher is hardwired to AES-128 Counter Mode with 112 bits of salt.
 *
 */

err_status_t
srtp_init_aes_128_prf(srtp_t srtp, const octet_t key[16]);



/*
 * srtp_get_trailer_length(&a) returns the number of octets that will
 * be added to an RTP packet by the SRTP processing.  This value
 * is constant for a given srtp_ctx_t (i.e. between initializations).
 */

int
srtp_get_trailer_length(const srtp_t a);


/*
 * functions below are internal to libsrtp, and are not part of the
 * documented external api - caveat emptor!
 */

/* for debugging only - srtp_print_packet dumps lots of info to stdout */

void
srtp_print_packet(srtp_hdr_t *hdr, int pkt_octet_len);


/*
 * srtp_set_rollover_counter(ctx, r)
 *
 * sets the rollover_counter in ctx to r.  fails and returns
 * err_status_err if r is less than the current rollover
 * counter value; otherwise, returns err_status_ok
 *
 * this function should *only* be called if trustworthy external
 * information is available, e.g. from RTCP
 *
 * future versions of this implementation may get rid of this function
 * and instead read the correct rollover counter value directly from
 * the rtcp packets immediately after they have been authenticated
 *
 */

err_status_t
srtp_set_rollover_counter(srtp_t ctx, rollover_counter_t r);


#endif /* SRTP_H */
