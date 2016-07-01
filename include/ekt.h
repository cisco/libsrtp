/*
 * ekt.h
 *
 * interface to Encrypted Key Transport for SRTP
 *
 * David McGrew
 * Cisco Systems, Inc.
 *
 * CHANGE LOG
 * ----------
 * 2015-12-11 - Nivedita Melinkeri
 *     - Added structures to support EKT 
 *     - Added functions to support EKT and PRIME
 */
/*
 *	
 * Copyright (c) 2001-2005 Cisco Systems, Inc.
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


#ifndef EKT_H
#define EKT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "srtp.h"
#include "srtp_priv.h"

#define SRTP_MAX_EKT_TAG_LEN              60

#define EKT_IS_TAG_PRESENT   (htons(spi) &0x0001)

typedef uint32_t srtp_roc_t;

typedef struct ekt_tag_contents_t {
    int present;
    uint8_t master_key[MAX_SRTP_KEY_LEN];
    unsigned master_key_len;
    uint32_t ssrc;
    srtp_roc_t roc;
    srtp_ekt_spi_t spi;
} ekt_tag_contents_t;

int srtp_get_ekt_cipher_key_length(srtp_ekt_cipher_t ekt_cipher);

srtp_ekt_spi_t srtp_packet_get_ekt_spi(const uint8_t *packet_start, unsigned pkt_octet_len);

srtp_err_status_t ekt_get_spi_info(srtp_ctx_t_ *ctx, srtp_ekt_spi_t spi, srtp_ekt_spi_info_t **spi_info);

srtp_roc_t srtp_packet_get_roc(const uint8_t *packet_start, unsigned pkt_octet_len);

srtp_err_status_t ekt_parse_tag(srtp_stream_ctx_t *stream, srtp_ctx_t *ctx, const void  *srtp_hdr, int *pkt_octet_len, ekt_tag_contents_t *tag_contents);

srtp_err_status_t ekt_generate_tag(srtp_stream_ctx_t *stream, srtp_ctx_t *ctx, void *srtp_hdr, uint8_t *ekt_cipherText, unsigned int *ekt_cipherTextLength, srtp_service_flags_t flags);

#ifdef __cplusplus
}
#endif

#endif /* EKT_H */
