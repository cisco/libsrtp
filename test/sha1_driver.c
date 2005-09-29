/*
 * sha1_driver.c
 *
 * a test driver for SHA-1
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

#include <stdio.h>
#include "sha1.h"

int
hmac_sha1_test(void);

int
main (void) {
  uint32_t hash_value[5];
  uint8_t msg_ref[3] = { 0x61, 0x62, 0x63 };
  uint8_t hash_ref[20] = {
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
    0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 
    0x9c, 0xd0, 0xd8, 0x9d 
  };
  uint8_t msg_ref2[56] = {
    0x61, 0x62, 0x63, 0x64, 0x62, 0x63, 0x64, 0x65, 
    0x63, 0x64, 0x65, 0x66, 0x64, 0x65, 0x66, 0x67,
    0x65, 0x66, 0x67, 0x68, 0x66, 0x67, 0x68, 0x69, 
    0x67, 0x68, 0x69, 0x6a, 0x68, 0x69, 0x6a, 0x6b,
    0x69, 0x6a, 0x6b, 0x6c, 0x6a, 0x6b, 0x6c, 0x6d,
    0x6b, 0x6c, 0x6d, 0x6e, 0x6c, 0x6d, 0x6e, 0x6f,
    0x6d, 0x6e, 0x6f, 0x70, 0x6e, 0x6f, 0x70, 0x71
  };
  uint8_t hash_ref2[20] = {
    0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 
    0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5,
    0xe5, 0x46, 0x70, 0xf1
  };
  sha1_ctx_t ctx;

  printf("sha1 test driver\n"
         "David A. McGrew\n"
         "Cisco Systems, Inc.\n");

  sha1_init(&ctx);
  sha1_update(&ctx, msg_ref, 3);
  sha1_final(&ctx, hash_value);
  printf("reference value: %s\n", 
	 octet_string_hex_string((uint8_t *)hash_ref, 20));
  printf("computed value:  %s\n", 
	 octet_string_hex_string((uint8_t *)hash_value, 20));

  sha1_init(&ctx);
  sha1_update(&ctx, msg_ref2, 56);
  sha1_final(&ctx, hash_value);
  printf("reference value: %s\n", 
	 octet_string_hex_string((uint8_t *)hash_ref2, 20));
  printf("computed value:  %s\n", 
	 octet_string_hex_string((uint8_t *)hash_value, 20));

  return 0;
}
