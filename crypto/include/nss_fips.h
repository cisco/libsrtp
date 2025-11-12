/*
 * Copyright (c) 2024, Red Hat, Inc.
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
 *   Neither the name of the Red Hat, Inc. nor the names of its
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
*/

/*
  Adapted from Red Hat Ceph patch by
  Radoslaw Zarzynski <rzarzyns@redhat.com>

  PK11_ImportSymKey() is a part of NSS API that becomes unavailable
  in the FIPS mode. NSS restricts key material so applications do not
  become burdened with the FIPS key requirements handling. Using this
  code will push that burden back to the application (including
  potentially 3rd party applications) and may result in no longer being
  in FIPS mode. Use this code cautiously and ask your self why you
  needed it in the first place.

  A raw crypto key is in-memory wrapped with fresh, random wrapping
  key just before being imported via PK11_UnwrapSymKey(). Of course,
  this effectively lowers to FIPS level 1. Still, this would be no
  different from what OpenSSL gives in the matter.
*/

#ifndef NSS_FIPS_H
#define NSS_FIPS_H
#include <nss.h>
#include <pk11pub.h>
#include <secerr.h>
#include <nspr.h>

static PK11SymKey *import_sym_key_in_FIPS(
    PK11SlotInfo * const slot,
    const CK_MECHANISM_TYPE type,
    const PK11Origin origin,
    const CK_ATTRIBUTE_TYPE operation,
    SECItem * const raw_key,
    void * const wincx)
{
  PK11SymKey* wrapping_key = NULL;
  PK11Context *wrap_key_crypt_context = NULL;
  SECItem *raw_key_aligned = NULL;
  CK_MECHANISM_TYPE wrap_mechanism = 0;

  struct {
    unsigned char data[256];
    int len;
  } wrapped_key;

  #define SCOPE_DATA_FREE()                               \
  {                                                       \
    PK11_FreeSymKey(wrapping_key);                        \
    PK11_DestroyContext(wrap_key_crypt_context, PR_TRUE); \
    SECITEM_FreeItem(raw_key_aligned, PR_TRUE);           \
  }

  if(raw_key->len > sizeof(wrapped_key.data)) {
    return NULL;
  }

  // getting 306 on my system which is CKM_DES3_ECB.
  wrap_mechanism = PK11_GetBestWrapMechanism(slot);

  // Generate a wrapping key. It will be used exactly twice over the scope:
  //   * to encrypt raw_key giving wrapped_key,
  //   * to decrypt wrapped_key in the internals of PK11_UnwrapSymKey().
  wrapping_key = PK11_KeyGen(slot, wrap_mechanism, NULL,
                             PK11_GetBestKeyLength(slot, wrap_mechanism), NULL);
  if (wrapping_key == NULL) {
    return NULL;
  }

  // Prepare a PK11 context for the raw_key -> wrapped_key encryption.
  SECItem tmp_sec_item;
  memset(&tmp_sec_item, 0, sizeof(tmp_sec_item));
  wrap_key_crypt_context = PK11_CreateContextBySymKey(
   wrap_mechanism,
   CKA_ENCRYPT,
   wrapping_key,
   &tmp_sec_item);
  if (wrap_key_crypt_context == NULL) {
    SCOPE_DATA_FREE();
    return NULL;
  }

  // Finally wrap the key. Important note is that the wrapping mechanism
  // selection (read: just grabbing a cipher) offers, at least in my NSS
  // copy, mostly CKM_*_ECB ciphers (with 3DES as the leading one, see
  // wrapMechanismList[] in pk11mech.c). There is no CKM_*_*_PAD variant
  // which means that plaintext we are providing to PK11_CipherOp() must
  // be aligned to cipher's block size. For 3DES it's 64 bits.
  raw_key_aligned = PK11_BlockData(raw_key, PK11_GetBlockSize(wrap_mechanism, NULL));
  if (raw_key_aligned == NULL) {
    SCOPE_DATA_FREE();
    return NULL;
  }

  if (PK11_CipherOp(wrap_key_crypt_context, wrapped_key.data, &wrapped_key.len,
      sizeof(wrapped_key.data), raw_key_aligned->data,
      raw_key_aligned->len) != SECSuccess) {
    SCOPE_DATA_FREE();
    return NULL;
  }

  if (PK11_Finalize(wrap_key_crypt_context) != SECSuccess) {
    SCOPE_DATA_FREE();
    return NULL;
  }

  // Key is wrapped now so we can acquire the ultimate PK11SymKey through
  // unwrapping it. Of course these two opposite operations form NOP with
  // a side effect: FIPS level 1 compatibility.
  memset(&tmp_sec_item, 0, sizeof(tmp_sec_item));

  SECItem wrapped_key_item;
  memset(&wrapped_key_item, 0, sizeof(wrapped_key_item));
  wrapped_key_item.data = wrapped_key.data;
  wrapped_key_item.len = wrapped_key.len;

  PK11SymKey *ret = PK11_UnwrapSymKey(wrapping_key, wrap_mechanism,
                                      &tmp_sec_item, &wrapped_key_item, type,
                                      operation, raw_key->len);
  SCOPE_DATA_FREE();
  return ret;
 }

#endif // NSS_FIPS_H
