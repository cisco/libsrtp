/*
 * rtp_decoder.h
 *
 * decoder structures and functions for SRTP pcap decoder
 *
 * Bernardo Torres <bernardo@torresautomacao.com.br>
 */
/*
 *	
 * Copyright (c) 2001-2006 Cisco Systems, Inc.
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
#include <pcap.h>
#include "rtp_decoder.h"

rtp_decoder_t
rtp_decoder_alloc(void) {
  return (rtp_decoder_t)malloc(sizeof(rtp_decoder_ctx_t));
}

void
rtp_decoder_dealloc(rtp_decoder_t rtp_ctx) {
  free(rtp_ctx);
}

err_status_t
rtp_decoder_init_srtp(rtp_decoder_t decoder, unsigned int ssrc) {
  decoder->policy.ssrc.value = htonl(ssrc);
  return srtp_create(&decoder->srtp_ctx, &decoder->policy);
}

int
rtp_decoder_deinit_srtp(rtp_decoder_t decoder) {
  return srtp_dealloc(decoder->srtp_ctx);
}

int
rtp_decoder_init(rtp_decoder_t dcdr, srtp_policy_t policy){
	dcdr->rtp_offset = DEFAULT_RTP_OFFSET;
	dcdr->srtp_ctx = NULL;
	dcdr->start_tv.tv_usec = 0;
	dcdr->start_tv.tv_sec = 0;
	dcdr->frame_nr = -1;
    dcdr->policy = policy;
	dcdr->policy.ssrc.type  = ssrc_specific;
	return 0;
}

/* 
 * decodes key as base64
 */

void hexdump(const void *ptr, size_t size) {
  int i, j;
  const unsigned char *cptr = ptr;

  for (i = 0; i < size; i += 16) {
    fprintf(stdout, "%04x ", i);
    for (j = 0; j < 16 && i+j < size; j++) {
      fprintf(stdout, "%02x ", cptr[i+j]);
    }
    fprintf(stdout, "\n");
  }
}

void
rtp_decoder_handle_pkt(u_char *arg, const struct pcap_pkthdr *hdr,
	const u_char *bytes){
  rtp_decoder_t dcdr = (rtp_decoder_t)arg;
  int pktsize;
  struct timeval delta;
  int octets_recvd;
  err_status_t status;
  dcdr->frame_nr++;

  if (dcdr->start_tv.tv_sec == 0 && dcdr->start_tv.tv_sec == 0) {
    dcdr->start_tv = hdr->ts;
  }

  if (hdr->caplen < dcdr->rtp_offset) {
    return;
  }
  const void *rtp_packet = bytes + dcdr->rtp_offset;

  memcpy((void *)&dcdr->message, rtp_packet, hdr->caplen - dcdr->rtp_offset);
  pktsize = hdr->caplen - dcdr->rtp_offset;
  octets_recvd = pktsize;

  if (octets_recvd == -1) {
    return;
  }

  /* verify rtp header */
  if (dcdr->message.header.version != 2) {
    return; //return -1;
  }
  if(dcdr->srtp_ctx == NULL){
    status = rtp_decoder_init_srtp(dcdr, dcdr->message.header.ssrc);
    if (status) {
      exit(1);
    }
 }
  if(dcdr->srtp_ctx != NULL){
  }
  status = srtp_unprotect(dcdr->srtp_ctx, &dcdr->message, &octets_recvd);
  if (status){
    return;
  }
  timersub(&hdr->ts, &dcdr->start_tv, &delta);
  fprintf(stdout, "%02ld:%02ld.%06lu\n", delta.tv_sec/60, delta.tv_sec%60, delta.tv_usec);
  hexdump(&dcdr->message, pktsize);
}

void rtp_print_error(err_status_t status, char *message){
    fprintf(stderr,
            "error: %s %d%s\n", message, status,
            status == err_status_replay_fail ? " (replay check failed)" :
            status == err_status_bad_param ? " (bad param)" :
            status == err_status_no_ctx ? " (no context)" :
            status == err_status_cipher_fail ? " (cipher failed)" :
            status == err_status_key_expired ? " (key expired)" :
            status == err_status_auth_fail ? " (auth check failed)" : "");
}
