/*
 * srtp.c
 *
 * the secure real-time transport protocol
 *
 * David A. McGrew
 * Cisco Systems, Inc.
 */
/*
 *
 * Copyright (c) 2001-2017, Cisco Systems, Inc.
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

// Leave this as the top level import. Ensures the existence of defines
#include "config.h"

#include "srtp_priv.h"
#include "stream_list_priv.h"
#include "crypto_types.h"
#include "err.h"
#include "alloc.h" /* for srtp_crypto_alloc() */

#ifdef GCM
#include "aes_gcm.h" /* for AES GCM mode */
#endif

#ifdef OPENSSL_KDF
#include <openssl/kdf.h>
#include "aes_icm_ext.h"
#endif

#ifdef WOLFSSL
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>
#ifdef WOLFSSL_KDF
#include <wolfssl/wolfcrypt/kdf.h>
#endif
#endif

#include <limits.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#elif defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#endif

/* the debug module for srtp */
srtp_debug_module_t mod_srtp = {
    false, /* debugging is off by default */
    "srtp" /* printable name for module */
};

static const size_t octets_in_rtp_header = 12;
static const size_t octets_in_rtcp_header = 8;
static const size_t octets_in_rtp_xtn_hdr = 4;

static const uint16_t xtn_hdr_one_byte_profile = 0xbede;
static const uint16_t xtn_hdr_two_byte_profile = 0x1000;

static const uint16_t cryptex_one_byte_profile = 0xc0de;
static const uint16_t cryptex_two_byte_profile = 0xc2de;

static size_t srtp_get_rtp_hdr_len(const srtp_hdr_t *hdr)
{
    return octets_in_rtp_header + 4 * hdr->cc;
}

/*
 * Returns the location of the header extention cast to a srtp_hdr_xtnd_t
 * struct. Will always return a value and assumes that the caller has already
 * verified that a header extension is present by checking the x bit of
 * srtp_hdr_t.
 */
static srtp_hdr_xtnd_t *srtp_get_rtp_xtn_hdr(const srtp_hdr_t *hdr,
                                             uint8_t *rtp)
{
    return (srtp_hdr_xtnd_t *)(rtp + srtp_get_rtp_hdr_len(hdr));
}

/*
 * Returns the length of the extension header including the extension header
 * header so will return a minium of 4. Assumes the srtp_hdr_xtnd_t is a valid
 * pointer and that the caller has already verified that a header extension is
 * valid by checking the x bit of the RTP header.
 */
static size_t srtp_get_rtp_xtn_hdr_len(const srtp_hdr_t *hdr,
                                       const uint8_t *rtp)
{
    const srtp_hdr_xtnd_t *xtn_hdr =
        (const srtp_hdr_xtnd_t *)(rtp + srtp_get_rtp_hdr_len(hdr));
    return (ntohs(xtn_hdr->length) + 1u) * 4u;
}

static uint16_t srtp_get_rtp_xtn_hdr_profile(const srtp_hdr_t *hdr,
                                             const uint8_t *rtp)
{
    const srtp_hdr_xtnd_t *xtn_hdr =
        (const srtp_hdr_xtnd_t *)(rtp + srtp_get_rtp_hdr_len(hdr));
    return ntohs(xtn_hdr->profile_specific);
}

static void srtp_cryptex_adjust_buffer(const srtp_hdr_t *hdr, uint8_t *rtp)
{
    if (hdr->cc) {
        uint8_t tmp[4];
        uint8_t *ptr = rtp + srtp_get_rtp_hdr_len(hdr);
        size_t cc_list_size = hdr->cc * 4;
        memcpy(tmp, ptr, 4);
        ptr -= cc_list_size;
        memmove(ptr + 4, ptr, cc_list_size);
        memcpy(ptr, tmp, 4);
    }
}

static void srtp_cryptex_restore_buffer(const srtp_hdr_t *hdr, uint8_t *rtp)
{
    if (hdr->cc) {
        uint8_t tmp[4];
        uint8_t *ptr = rtp + octets_in_rtp_header;
        size_t cc_list_size = hdr->cc * 4;
        memcpy(tmp, ptr, 4);
        memmove(ptr, ptr + 4, cc_list_size);
        ptr += cc_list_size;
        memcpy(ptr, tmp, 4);
    }
}

static srtp_err_status_t srtp_cryptex_protect_init(
    const srtp_stream_ctx_t *stream,
    const srtp_hdr_t *hdr,
    const uint8_t *rtp,
    const uint8_t *srtp,
    bool *inuse,
    bool *inplace,
    size_t *enc_start)
{
    if (stream->use_cryptex && (stream->rtp_services & sec_serv_conf)) {
        if (hdr->cc && hdr->x == 0) {
            /* Cryptex can only encrypt CSRCs if header extension is present */
            return srtp_err_status_cryptex_err;
        }
        *inuse = hdr->x == 1;
    } else {
        *inuse = false;
    }

    *inplace = *inuse && rtp == srtp;

    if (*inuse) {
        *enc_start -=
            (srtp_get_rtp_xtn_hdr_len(hdr, rtp) - octets_in_rtp_xtn_hdr);
        if (*inplace) {
            *enc_start -= (hdr->cc * 4);
        }
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_cryptex_protect(bool inplace,
                                              const srtp_hdr_t *hdr,
                                              uint8_t *srtp,
                                              srtp_cipher_t *rtp_cipher)
{
    srtp_hdr_xtnd_t *xtn_hdr = srtp_get_rtp_xtn_hdr(hdr, srtp);
    uint16_t profile = ntohs(xtn_hdr->profile_specific);
    if (profile == xtn_hdr_one_byte_profile) {
        xtn_hdr->profile_specific = htons(cryptex_one_byte_profile);
    } else if (profile == xtn_hdr_two_byte_profile) {
        xtn_hdr->profile_specific = htons(cryptex_two_byte_profile);
    } else {
        return srtp_err_status_parse_err;
    }

    if (inplace) {
        srtp_cryptex_adjust_buffer(hdr, srtp);
    } else {
        if (hdr->cc) {
            uint8_t *cc_list = srtp + octets_in_rtp_header;
            size_t cc_list_size = hdr->cc * 4;
            /* CSRCs are in dst header already, enc in place */
            srtp_err_status_t status = srtp_cipher_encrypt(
                rtp_cipher, cc_list, cc_list_size, cc_list, &cc_list_size);
            if (status) {
                return srtp_err_status_cipher_fail;
            }
        }
    }

    return srtp_err_status_ok;
}

static void srtp_cryptex_protect_cleanup(bool inplace,
                                         const srtp_hdr_t *hdr,
                                         uint8_t *srtp)
{
    if (inplace) {
        srtp_cryptex_restore_buffer(hdr, srtp);
    }
}

static srtp_err_status_t srtp_cryptex_unprotect_init(
    const srtp_stream_ctx_t *stream,
    const srtp_hdr_t *hdr,
    const uint8_t *srtp,
    const uint8_t *rtp,
    bool *inuse,
    bool *inplace,
    size_t *enc_start)
{
    if (stream->use_cryptex && hdr->x == 1) {
        uint16_t profile = srtp_get_rtp_xtn_hdr_profile(hdr, rtp);
        *inuse = profile == cryptex_one_byte_profile ||
                 profile == cryptex_two_byte_profile;
    } else {
        *inuse = false;
    }

    *inplace = *inuse && srtp == rtp;

    if (*inuse) {
        *enc_start -=
            (srtp_get_rtp_xtn_hdr_len(hdr, rtp) - octets_in_rtp_xtn_hdr);
        if (*inplace) {
            *enc_start -= (hdr->cc * 4);
        }
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_cryptex_unprotect(bool inplace,
                                                const srtp_hdr_t *hdr,
                                                uint8_t *rtp,
                                                srtp_cipher_t *rtp_cipher)
{
    if (inplace) {
        srtp_cryptex_adjust_buffer(hdr, rtp);
    } else {
        if (hdr->cc) {
            uint8_t *cc_list = rtp + octets_in_rtp_header;
            size_t cc_list_size = hdr->cc * 4;
            /* CSRCs are in dst header already, enc in place */
            srtp_err_status_t status = srtp_cipher_decrypt(
                rtp_cipher, cc_list, cc_list_size, cc_list, &cc_list_size);
            if (status) {
                return srtp_err_status_cipher_fail;
            }
        }
    }

    return srtp_err_status_ok;
}

static void srtp_cryptex_unprotect_cleanup(bool inplace,
                                           const srtp_hdr_t *hdr,
                                           uint8_t *rtp)
{
    if (inplace) {
        srtp_cryptex_restore_buffer(hdr, rtp);
    }

    srtp_hdr_xtnd_t *xtn_hdr = srtp_get_rtp_xtn_hdr(hdr, rtp);
    uint16_t profile = ntohs(xtn_hdr->profile_specific);
    if (profile == cryptex_one_byte_profile) {
        xtn_hdr->profile_specific = htons(xtn_hdr_one_byte_profile);
    } else if (profile == cryptex_two_byte_profile) {
        xtn_hdr->profile_specific = htons(xtn_hdr_two_byte_profile);
    }
}

static srtp_err_status_t srtp_validate_rtp_header(const uint8_t *rtp,
                                                  size_t pkt_octet_len)
{
    const srtp_hdr_t *hdr = (const srtp_hdr_t *)rtp;
    size_t rtp_header_len;

    if (pkt_octet_len < octets_in_rtp_header) {
        return srtp_err_status_bad_param;
    }

    /* Check RTP header length */
    rtp_header_len = srtp_get_rtp_hdr_len(hdr);
    if (pkt_octet_len < rtp_header_len) {
        return srtp_err_status_bad_param;
    }

    /* Verifying profile length. */
    if (hdr->x == 1) {
        if (pkt_octet_len < rtp_header_len + octets_in_rtp_xtn_hdr) {
            return srtp_err_status_bad_param;
        }

        rtp_header_len += srtp_get_rtp_xtn_hdr_len(hdr, rtp);
        if (pkt_octet_len < rtp_header_len) {
            return srtp_err_status_bad_param;
        }
    }

    return srtp_err_status_ok;
}

const char *srtp_get_version_string(void)
{
    /*
     * Simply return the autotools generated string
     */
    return SRTP_VER_STRING;
}

unsigned int srtp_get_version(void)
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

static srtp_err_status_t srtp_stream_dealloc(
    srtp_stream_ctx_t *stream,
    const srtp_stream_ctx_t *stream_template)
{
    srtp_err_status_t status;
    srtp_session_keys_t *session_keys = NULL;
    srtp_session_keys_t *template_session_keys = NULL;

    /*
     * we use a conservative deallocation strategy - if any deallocation
     * fails, then we report that fact without trying to deallocate
     * anything else
     */
    if (stream->session_keys) {
        for (size_t i = 0; i < stream->num_master_keys; i++) {
            session_keys = &stream->session_keys[i];

            if (stream_template &&
                stream->num_master_keys == stream_template->num_master_keys) {
                template_session_keys = &stream_template->session_keys[i];
            } else {
                template_session_keys = NULL;
            }

            /*
             * deallocate cipher, if it is not the same as that in template
             */
            if (template_session_keys &&
                session_keys->rtp_cipher == template_session_keys->rtp_cipher) {
                /* do nothing */
            } else if (session_keys->rtp_cipher) {
                status = srtp_cipher_dealloc(session_keys->rtp_cipher);
                if (status) {
                    return status;
                }
            }

            /*
             * deallocate auth function, if it is not the same as that in
             * template
             */
            if (template_session_keys &&
                session_keys->rtp_auth == template_session_keys->rtp_auth) {
                /* do nothing */
            } else if (session_keys->rtp_auth) {
                status = srtp_auth_dealloc(session_keys->rtp_auth);
                if (status) {
                    return status;
                }
            }

            if (template_session_keys &&
                session_keys->rtp_xtn_hdr_cipher ==
                    template_session_keys->rtp_xtn_hdr_cipher) {
                /* do nothing */
            } else if (session_keys->rtp_xtn_hdr_cipher) {
                status = srtp_cipher_dealloc(session_keys->rtp_xtn_hdr_cipher);
                if (status) {
                    return status;
                }
            }

            /*
             * deallocate rtcp cipher, if it is not the same as that in
             * template
             */
            if (template_session_keys &&
                session_keys->rtcp_cipher ==
                    template_session_keys->rtcp_cipher) {
                /* do nothing */
            } else if (session_keys->rtcp_cipher) {
                status = srtp_cipher_dealloc(session_keys->rtcp_cipher);
                if (status) {
                    return status;
                }
            }

            /*
             * deallocate rtcp auth function, if it is not the same as that in
             * template
             */
            if (template_session_keys &&
                session_keys->rtcp_auth == template_session_keys->rtcp_auth) {
                /* do nothing */
            } else if (session_keys->rtcp_auth) {
                status = srtp_auth_dealloc(session_keys->rtcp_auth);
                if (status) {
                    return status;
                }
            }

            /*
             * zeroize the salt value
             */
            octet_string_set_to_zero(session_keys->salt, SRTP_AEAD_SALT_LEN);
            octet_string_set_to_zero(session_keys->c_salt, SRTP_AEAD_SALT_LEN);

            if (session_keys->mki_id) {
                octet_string_set_to_zero(session_keys->mki_id,
                                         stream->mki_size);
                srtp_crypto_free(session_keys->mki_id);
                session_keys->mki_id = NULL;
            }

            /*
             * deallocate key usage limit, if it is not the same as that in
             * template
             */
            if (template_session_keys &&
                session_keys->limit == template_session_keys->limit) {
                /* do nothing */
            } else if (session_keys->limit) {
                srtp_crypto_free(session_keys->limit);
            }
        }
        srtp_crypto_free(stream->session_keys);
    }

    status = srtp_rdbx_dealloc(&stream->rtp_rdbx);
    if (status) {
        return status;
    }

    if (stream_template &&
        stream->enc_xtn_hdr == stream_template->enc_xtn_hdr) {
        /* do nothing */
    } else if (stream->enc_xtn_hdr) {
        srtp_crypto_free(stream->enc_xtn_hdr);
    }

    /* deallocate srtp stream context */
    srtp_crypto_free(stream);

    return srtp_err_status_ok;
}

/* try to insert stream in list or deallocate it */
static srtp_err_status_t srtp_insert_or_dealloc_stream(srtp_stream_list_t list,
                                                       srtp_stream_t stream,
                                                       srtp_stream_t template)
{
    srtp_err_status_t status = srtp_stream_list_insert(list, stream);
    /* on failure, ownership wasn't transferred and we need to deallocate */
    if (status) {
        srtp_stream_dealloc(stream, template);
    }
    return status;
}

struct remove_and_dealloc_streams_data {
    srtp_err_status_t status;
    srtp_stream_list_t list;
    srtp_stream_t template;
};

static bool remove_and_dealloc_streams_cb(srtp_stream_t stream, void *data)
{
    struct remove_and_dealloc_streams_data *d =
        (struct remove_and_dealloc_streams_data *)data;
    srtp_stream_list_remove(d->list, stream);
    d->status = srtp_stream_dealloc(stream, d->template);
    if (d->status) {
        return false;
    }
    return true;
}

static srtp_err_status_t srtp_remove_and_dealloc_streams(
    srtp_stream_list_t list,
    srtp_stream_t template)
{
    struct remove_and_dealloc_streams_data data = { srtp_err_status_ok, list,
                                                    template };
    srtp_stream_list_for_each(list, remove_and_dealloc_streams_cb, &data);
    return data.status;
}

static srtp_err_status_t srtp_valid_policy(const srtp_policy_t *policy)
{
    if (policy == NULL) {
        return srtp_err_status_bad_param;
    }

    if (policy->key == NULL) {
        if (policy->num_master_keys <= 0) {
            return srtp_err_status_bad_param;
        }

        if (policy->num_master_keys > SRTP_MAX_NUM_MASTER_KEYS) {
            return srtp_err_status_bad_param;
        }

        if (policy->use_mki) {
            if (policy->mki_size == 0 || policy->mki_size > SRTP_MAX_MKI_LEN) {
                return srtp_err_status_bad_param;
            }
        } else if (policy->mki_size != 0) {
            return srtp_err_status_bad_param;
        }

        for (size_t i = 0; i < policy->num_master_keys; i++) {
            if (policy->keys[i]->key == NULL) {
                return srtp_err_status_bad_param;
            }
            if (policy->use_mki && policy->keys[i]->mki_id == NULL) {
                return srtp_err_status_bad_param;
            }
        }
    } else {
        if (policy->use_mki || policy->mki_size != 0) {
            return srtp_err_status_bad_param;
        }
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_stream_alloc(srtp_stream_ctx_t **str_ptr,
                                           const srtp_policy_t *p)
{
    srtp_stream_ctx_t *str;
    srtp_err_status_t stat;
    size_t i = 0;
    srtp_session_keys_t *session_keys = NULL;

    stat = srtp_valid_policy(p);
    if (stat != srtp_err_status_ok) {
        return stat;
    }

    /*
     * This function allocates the stream context, rtp and rtcp ciphers
     * and auth functions, and key limit structure.  If there is a
     * failure during allocation, we free all previously allocated
     * memory and return a failure code.  The code could probably
     * be improved, but it works and should be clear.
     */

    /* allocate srtp stream and set str_ptr */
    str = (srtp_stream_ctx_t *)srtp_crypto_alloc(sizeof(srtp_stream_ctx_t));
    if (str == NULL) {
        return srtp_err_status_alloc_fail;
    }

    *str_ptr = str;

    /*
     *To keep backwards API compatible if someone is using multiple master
     * keys then key should be set to NULL
     */
    if (p->key != NULL) {
        str->num_master_keys = 1;
    } else {
        str->num_master_keys = p->num_master_keys;
    }

    str->session_keys = (srtp_session_keys_t *)srtp_crypto_alloc(
        sizeof(srtp_session_keys_t) * str->num_master_keys);

    if (str->session_keys == NULL) {
        srtp_stream_dealloc(str, NULL);
        return srtp_err_status_alloc_fail;
    }

    for (i = 0; i < str->num_master_keys; i++) {
        session_keys = &str->session_keys[i];

        /* allocate cipher */
        stat = srtp_crypto_kernel_alloc_cipher(
            p->rtp.cipher_type, &session_keys->rtp_cipher,
            p->rtp.cipher_key_len, p->rtp.auth_tag_len);
        if (stat) {
            srtp_stream_dealloc(str, NULL);
            return stat;
        }

        /* allocate auth function */
        stat = srtp_crypto_kernel_alloc_auth(
            p->rtp.auth_type, &session_keys->rtp_auth, p->rtp.auth_key_len,
            p->rtp.auth_tag_len);
        if (stat) {
            srtp_stream_dealloc(str, NULL);
            return stat;
        }

        /*
         * ...and now the RTCP-specific initialization - first, allocate
         * the cipher
         */
        stat = srtp_crypto_kernel_alloc_cipher(
            p->rtcp.cipher_type, &session_keys->rtcp_cipher,
            p->rtcp.cipher_key_len, p->rtcp.auth_tag_len);
        if (stat) {
            srtp_stream_dealloc(str, NULL);
            return stat;
        }

        /* allocate auth function */
        stat = srtp_crypto_kernel_alloc_auth(
            p->rtcp.auth_type, &session_keys->rtcp_auth, p->rtcp.auth_key_len,
            p->rtcp.auth_tag_len);
        if (stat) {
            srtp_stream_dealloc(str, NULL);
            return stat;
        }

        session_keys->mki_id = NULL;

        /* allocate key limit structure */
        session_keys->limit = (srtp_key_limit_ctx_t *)srtp_crypto_alloc(
            sizeof(srtp_key_limit_ctx_t));
        if (session_keys->limit == NULL) {
            srtp_stream_dealloc(str, NULL);
            return srtp_err_status_alloc_fail;
        }
    }

    if (p->enc_xtn_hdr && p->enc_xtn_hdr_count > 0) {
        srtp_cipher_type_id_t enc_xtn_hdr_cipher_type;
        size_t enc_xtn_hdr_cipher_key_len;

        str->enc_xtn_hdr = (uint8_t *)srtp_crypto_alloc(
            p->enc_xtn_hdr_count * sizeof(p->enc_xtn_hdr[0]));
        if (!str->enc_xtn_hdr) {
            srtp_stream_dealloc(str, NULL);
            return srtp_err_status_alloc_fail;
        }
        memcpy(str->enc_xtn_hdr, p->enc_xtn_hdr,
               p->enc_xtn_hdr_count * sizeof(p->enc_xtn_hdr[0]));
        str->enc_xtn_hdr_count = p->enc_xtn_hdr_count;

        /*
         * For GCM ciphers, the corresponding ICM cipher is used for header
         * extensions encryption.
         */
        switch (p->rtp.cipher_type) {
        case SRTP_AES_GCM_128:
            enc_xtn_hdr_cipher_type = SRTP_AES_ICM_128;
            enc_xtn_hdr_cipher_key_len = SRTP_AES_ICM_128_KEY_LEN_WSALT;
            break;
        case SRTP_AES_GCM_256:
            enc_xtn_hdr_cipher_type = SRTP_AES_ICM_256;
            enc_xtn_hdr_cipher_key_len = SRTP_AES_ICM_256_KEY_LEN_WSALT;
            break;
        default:
            enc_xtn_hdr_cipher_type = p->rtp.cipher_type;
            enc_xtn_hdr_cipher_key_len = p->rtp.cipher_key_len;
            break;
        }

        for (i = 0; i < str->num_master_keys; i++) {
            session_keys = &str->session_keys[i];

            /* allocate cipher for extensions header encryption */
            stat = srtp_crypto_kernel_alloc_cipher(
                enc_xtn_hdr_cipher_type, &session_keys->rtp_xtn_hdr_cipher,
                enc_xtn_hdr_cipher_key_len, 0);
            if (stat) {
                srtp_stream_dealloc(str, NULL);
                return stat;
            }
        }
    } else {
        for (i = 0; i < str->num_master_keys; i++) {
            session_keys = &str->session_keys[i];
            session_keys->rtp_xtn_hdr_cipher = NULL;
        }

        str->enc_xtn_hdr = NULL;
        str->enc_xtn_hdr_count = 0;
    }

    str->use_cryptex = p->use_cryptex;

    return srtp_err_status_ok;
}

/*
 * srtp_stream_clone(stream_template, new) allocates a new stream and
 * initializes it using the cipher and auth of the stream_template
 *
 * the only unique data in a cloned stream is the replay database and
 * the SSRC
 */

static srtp_err_status_t srtp_stream_clone(
    const srtp_stream_ctx_t *stream_template,
    uint32_t ssrc,
    srtp_stream_ctx_t **str_ptr)
{
    srtp_err_status_t status;
    srtp_stream_ctx_t *str;
    srtp_session_keys_t *session_keys = NULL;
    const srtp_session_keys_t *template_session_keys = NULL;

    debug_print(mod_srtp, "cloning stream (SSRC: 0x%08x)",
                (unsigned int)ntohl(ssrc));

    /* allocate srtp stream and set str_ptr */
    str = (srtp_stream_ctx_t *)srtp_crypto_alloc(sizeof(srtp_stream_ctx_t));
    if (str == NULL) {
        return srtp_err_status_alloc_fail;
    }
    *str_ptr = str;

    str->num_master_keys = stream_template->num_master_keys;
    str->session_keys = (srtp_session_keys_t *)srtp_crypto_alloc(
        sizeof(srtp_session_keys_t) * str->num_master_keys);

    if (str->session_keys == NULL) {
        srtp_stream_dealloc(*str_ptr, stream_template);
        *str_ptr = NULL;
        return srtp_err_status_alloc_fail;
    }

    for (size_t i = 0; i < stream_template->num_master_keys; i++) {
        session_keys = &str->session_keys[i];
        template_session_keys = &stream_template->session_keys[i];

        /* set cipher and auth pointers to those of the template */
        session_keys->rtp_cipher = template_session_keys->rtp_cipher;
        session_keys->rtp_auth = template_session_keys->rtp_auth;
        session_keys->rtp_xtn_hdr_cipher =
            template_session_keys->rtp_xtn_hdr_cipher;
        session_keys->rtcp_cipher = template_session_keys->rtcp_cipher;
        session_keys->rtcp_auth = template_session_keys->rtcp_auth;

        if (stream_template->mki_size == 0) {
            session_keys->mki_id = NULL;
        } else {
            session_keys->mki_id = srtp_crypto_alloc(stream_template->mki_size);

            if (session_keys->mki_id == NULL) {
                srtp_stream_dealloc(*str_ptr, stream_template);
                *str_ptr = NULL;
                return srtp_err_status_init_fail;
            }
            memcpy(session_keys->mki_id, template_session_keys->mki_id,
                   stream_template->mki_size);
        }
        /* Copy the salt values */
        memcpy(session_keys->salt, template_session_keys->salt,
               SRTP_AEAD_SALT_LEN);
        memcpy(session_keys->c_salt, template_session_keys->c_salt,
               SRTP_AEAD_SALT_LEN);

        /* set key limit to point to that of the template */
        status = srtp_key_limit_clone(template_session_keys->limit,
                                      &session_keys->limit);
        if (status) {
            srtp_stream_dealloc(*str_ptr, stream_template);
            *str_ptr = NULL;
            return status;
        }
    }

    str->use_mki = stream_template->use_mki;
    str->mki_size = stream_template->mki_size;

    /* initialize replay databases */
    status = srtp_rdbx_init(
        &str->rtp_rdbx, srtp_rdbx_get_window_size(&stream_template->rtp_rdbx));
    if (status) {
        srtp_stream_dealloc(*str_ptr, stream_template);
        *str_ptr = NULL;
        return status;
    }
    srtp_rdb_init(&str->rtcp_rdb);
    str->allow_repeat_tx = stream_template->allow_repeat_tx;

    /* set ssrc to that provided */
    str->ssrc = ssrc;

    /* reset pending ROC */
    str->pending_roc = 0;

    /* set direction and security services */
    str->direction = stream_template->direction;
    str->rtp_services = stream_template->rtp_services;
    str->rtcp_services = stream_template->rtcp_services;

    /* copy information about extensions header encryption */
    str->enc_xtn_hdr = stream_template->enc_xtn_hdr;
    str->enc_xtn_hdr_count = stream_template->enc_xtn_hdr_count;
    str->use_cryptex = stream_template->use_cryptex;
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
    label_rtp_encryption = 0x00,
    label_rtp_msg_auth = 0x01,
    label_rtp_salt = 0x02,
    label_rtcp_encryption = 0x03,
    label_rtcp_msg_auth = 0x04,
    label_rtcp_salt = 0x05,
    label_rtp_header_encryption = 0x06,
    label_rtp_header_salt = 0x07
} srtp_prf_label;

#define MAX_SRTP_KEY_LEN 256

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

static srtp_err_status_t srtp_kdf_init(srtp_kdf_t *kdf,
                                       const uint8_t *key,
                                       size_t key_len,
                                       size_t salt_len)
{
    memset(kdf, 0x0, sizeof(srtp_kdf_t));

    /* The NULL cipher has zero key length */
    if (key_len == 0) {
        return srtp_err_status_ok;
    }

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
    memcpy(kdf->master_salt, key + key_len, salt_len);
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_generate(srtp_kdf_t *kdf,
                                           srtp_prf_label label,
                                           uint8_t *key,
                                           size_t length)
{
    int ret;

    /* The NULL cipher will not have an EVP */
    if (!kdf->evp) {
        return srtp_err_status_ok;
    }
    octet_string_set_to_zero(key, length);

    /*
     * Invoke the OpenSSL SRTP KDF function
     * This is useful if OpenSSL is in FIPS mode and FIP
     * compliance is required for SRTP.
     */
    ret = kdf_srtp(kdf->evp, (char *)&kdf->master_key, &kdf->master_salt, NULL,
                   NULL, label, key);
    if (ret == -1) {
        return (srtp_err_status_algo_fail);
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_clear(srtp_kdf_t *kdf)
{
    octet_string_set_to_zero(kdf->master_key, MAX_SRTP_AESKEY_LEN);
    octet_string_set_to_zero(kdf->master_salt, MAX_SRTP_SALT_LEN);
    kdf->evp = NULL;

    return srtp_err_status_ok;
}

#elif defined(WOLFSSL) && defined(WOLFSSL_KDF)
#define MAX_SRTP_AESKEY_LEN AES_256_KEY_SIZE
#define MAX_SRTP_SALT_LEN WC_SRTP_MAX_SALT

/*
 * srtp_kdf_t represents a key derivation function.  The SRTP
 * default KDF is the only one implemented at present.
 */
typedef struct {
    uint8_t master_key[MAX_SRTP_AESKEY_LEN];
    int master_key_len;
    uint8_t master_salt[MAX_SRTP_SALT_LEN];
} srtp_kdf_t;

static srtp_err_status_t srtp_kdf_init(srtp_kdf_t *kdf,
                                       const uint8_t *key,
                                       size_t key_len)
{
    size_t salt_len;

    memset(kdf, 0x0, sizeof(srtp_kdf_t));

    switch (key_len) {
    case SRTP_AES_ICM_256_KEY_LEN_WSALT:
        kdf->master_key_len = AES_256_KEY_SIZE;
        break;
    case SRTP_AES_ICM_192_KEY_LEN_WSALT:
        kdf->master_key_len = AES_192_KEY_SIZE;
        break;
    case SRTP_AES_ICM_128_KEY_LEN_WSALT:
        kdf->master_key_len = AES_128_KEY_SIZE;
        break;
    default:
        return srtp_err_status_bad_param;
        break;
    }

    memcpy(kdf->master_key, key, kdf->master_key_len);
    salt_len = key_len - kdf->master_key_len;
    memcpy(kdf->master_salt, key + kdf->master_key_len, salt_len);
    memset(kdf->master_salt + salt_len, 0, MAX_SRTP_SALT_LEN - salt_len);

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_generate(srtp_kdf_t *kdf,
                                           srtp_prf_label label,
                                           uint8_t *key,
                                           size_t length)
{
    int err;

    if (length == 0) {
        return srtp_err_status_ok;
    }
    if (kdf->master_key_len == 0) {
        return srtp_err_status_ok;
    }
    octet_string_set_to_zero(key, length);

    PRIVATE_KEY_UNLOCK();
    err = wc_SRTP_KDF_label(kdf->master_key, kdf->master_key_len,
                            kdf->master_salt, MAX_SRTP_SALT_LEN, -1, NULL,
                            label, key, length);
    PRIVATE_KEY_LOCK();
    if (err < 0) {
        debug_print(mod_srtp, "wolfSSL SRTP KDF error: %d", err);
        return (srtp_err_status_algo_fail);
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_clear(srtp_kdf_t *kdf)
{
    octet_string_set_to_zero(kdf->master_key, MAX_SRTP_AESKEY_LEN);
    kdf->master_key_len = 0;
    octet_string_set_to_zero(kdf->master_salt, MAX_SRTP_SALT_LEN);

    return srtp_err_status_ok;
}

#else  /* if OPENSSL_KDF || WOLFSSL_KDF */

/*
 * srtp_kdf_t represents a key derivation function.  The SRTP
 * default KDF is the only one implemented at present.
 */
typedef struct {
    srtp_cipher_t *cipher; /* cipher used for key derivation  */
} srtp_kdf_t;

static srtp_err_status_t srtp_kdf_init(srtp_kdf_t *kdf,
                                       const uint8_t *key,
                                       size_t key_len)
{
    srtp_cipher_type_id_t cipher_id;
    srtp_err_status_t stat;

    switch (key_len) {
    case SRTP_AES_ICM_256_KEY_LEN_WSALT:
        cipher_id = SRTP_AES_ICM_256;
        break;
    case SRTP_AES_ICM_192_KEY_LEN_WSALT:
        cipher_id = SRTP_AES_ICM_192;
        break;
    case SRTP_AES_ICM_128_KEY_LEN_WSALT:
        cipher_id = SRTP_AES_ICM_128;
        break;
    default:
        return srtp_err_status_bad_param;
        break;
    }

    stat = srtp_crypto_kernel_alloc_cipher(cipher_id, &kdf->cipher, key_len, 0);
    if (stat) {
        return stat;
    }

    stat = srtp_cipher_init(kdf->cipher, key);
    if (stat) {
        srtp_cipher_dealloc(kdf->cipher);
        return stat;
    }
    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_generate(srtp_kdf_t *kdf,
                                           srtp_prf_label label,
                                           uint8_t *key,
                                           size_t length)
{
    srtp_err_status_t status;
    v128_t nonce;

    /* set eigth octet of nonce to <label>, set the rest of it to zero */
    v128_set_to_zero(&nonce);
    nonce.v8[7] = label;

    status = srtp_cipher_set_iv(kdf->cipher, (uint8_t *)&nonce,
                                srtp_direction_encrypt);
    if (status) {
        return status;
    }

    /* generate keystream output */
    octet_string_set_to_zero(key, length);
    status = srtp_cipher_encrypt(kdf->cipher, key, length, key, &length);
    if (status) {
        return status;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_kdf_clear(srtp_kdf_t *kdf)
{
    srtp_err_status_t status;
    status = srtp_cipher_dealloc(kdf->cipher);
    if (status) {
        return status;
    }
    kdf->cipher = NULL;
    return srtp_err_status_ok;
}
#endif /* else OPENSSL_KDF || WOLFSSL_KDF */

/*
 *  end of key derivation functions
 */

/* Get the base key length corresponding to a given combined key+salt
 * length for the given cipher.
 * TODO: key and salt lengths should be separate fields in the policy.  */
static inline size_t base_key_length(const srtp_cipher_type_t *cipher,
                                     size_t key_length)
{
    switch (cipher->id) {
    case SRTP_NULL_CIPHER:
        return 0;
    case SRTP_AES_ICM_128:
    case SRTP_AES_ICM_192:
    case SRTP_AES_ICM_256:
        /* The legacy modes are derived from
         * the configured key length on the policy */
        return key_length - SRTP_SALT_LEN;
    case SRTP_AES_GCM_128:
        return key_length - SRTP_AEAD_SALT_LEN;
    case SRTP_AES_GCM_256:
        return key_length - SRTP_AEAD_SALT_LEN;
    default:
        return key_length;
    }
}

/* Get the key length that the application should supply for the given cipher */
static inline size_t full_key_length(const srtp_cipher_type_t *cipher)
{
    switch (cipher->id) {
    case SRTP_NULL_CIPHER:
    case SRTP_AES_ICM_128:
        return SRTP_AES_ICM_128_KEY_LEN_WSALT;
    case SRTP_AES_ICM_192:
        return SRTP_AES_ICM_192_KEY_LEN_WSALT;
    case SRTP_AES_ICM_256:
        return SRTP_AES_ICM_256_KEY_LEN_WSALT;
    case SRTP_AES_GCM_128:
        return SRTP_AES_GCM_128_KEY_LEN_WSALT;
    case SRTP_AES_GCM_256:
        return SRTP_AES_GCM_256_KEY_LEN_WSALT;
    default:
        return 0;
    }
}

srtp_err_status_t srtp_get_session_keys(srtp_stream_ctx_t *stream,
                                        size_t mki_index,
                                        srtp_session_keys_t **session_keys)
{
    if (stream->use_mki) {
        if (mki_index >= stream->num_master_keys) {
            return srtp_err_status_bad_mki;
        }
        *session_keys = &stream->session_keys[mki_index];
        return srtp_err_status_ok;
    }

    *session_keys = &stream->session_keys[0];
    return srtp_err_status_ok;
}

void srtp_inject_mki(uint8_t *mki_tag_location,
                     const srtp_session_keys_t *session_keys,
                     size_t mki_size)
{
    if (mki_size > 0) {
        // Write MKI into memory
        memcpy(mki_tag_location, session_keys->mki_id, mki_size);
    }
}

srtp_err_status_t srtp_stream_init_keys(srtp_session_keys_t *session_keys,
                                        const srtp_master_key_t *master_key,
                                        size_t mki_size)
{
    srtp_err_status_t stat;
    srtp_kdf_t kdf;
    uint8_t tmp_key[MAX_SRTP_KEY_LEN];
    size_t input_keylen, input_keylen_rtcp;
    size_t kdf_keylen = 30, rtp_keylen, rtcp_keylen;
    size_t rtp_base_key_len, rtp_salt_len;
    size_t rtcp_base_key_len, rtcp_salt_len;

    /* If RTP or RTCP have a key length > AES-128, assume matching kdf. */
    /* TODO: kdf algorithm, master key length, and master salt length should
     * be part of srtp_policy_t.
     */

    /* initialize key limit to maximum value */
    srtp_key_limit_set(session_keys->limit, 0xffffffffffffLL);

    if (mki_size != 0) {
        if (master_key->mki_id == NULL) {
            return srtp_err_status_bad_param;
        }
        session_keys->mki_id = srtp_crypto_alloc(mki_size);

        if (session_keys->mki_id == NULL) {
            return srtp_err_status_init_fail;
        }
        memcpy(session_keys->mki_id, master_key->mki_id, mki_size);
    } else {
        session_keys->mki_id = NULL;
    }

    input_keylen = full_key_length(session_keys->rtp_cipher->type);
    input_keylen_rtcp = full_key_length(session_keys->rtcp_cipher->type);
    if (input_keylen_rtcp > input_keylen) {
        input_keylen = input_keylen_rtcp;
    }

    rtp_keylen = srtp_cipher_get_key_length(session_keys->rtp_cipher);
    rtcp_keylen = srtp_cipher_get_key_length(session_keys->rtcp_cipher);
    rtp_base_key_len =
        base_key_length(session_keys->rtp_cipher->type, rtp_keylen);
    rtp_salt_len = rtp_keylen - rtp_base_key_len;

    /*
     * We assume that the `key` buffer provided by the caller has a length
     * equal to the greater of `rtp_keylen` and `rtcp_keylen`.  Since we are
     * about to read `input_keylen` bytes from it, we need to check that we will
     * not overrun.
     */
    if ((rtp_keylen < input_keylen) && (rtcp_keylen < input_keylen)) {
        return srtp_err_status_bad_param;
    }

    if (rtp_keylen > kdf_keylen) {
        kdf_keylen = 46; /* AES-CTR mode is always used for KDF */
    }

    if (rtcp_keylen > kdf_keylen) {
        kdf_keylen = 46; /* AES-CTR mode is always used for KDF */
    }

    if (input_keylen > kdf_keylen) {
        kdf_keylen = 46; /* AES-CTR mode is always used for KDF */
    }

    debug_print(mod_srtp, "input key len: %zu", input_keylen);
    debug_print(mod_srtp, "srtp key len: %zu", rtp_keylen);
    debug_print(mod_srtp, "srtcp key len: %zu", rtcp_keylen);
    debug_print(mod_srtp, "base key len: %zu", rtp_base_key_len);
    debug_print(mod_srtp, "kdf key len: %zu", kdf_keylen);
    debug_print(mod_srtp, "rtp salt len: %zu", rtp_salt_len);

    /*
     * Make sure the key given to us is 'zero' appended.  GCM
     * mode uses a shorter master SALT (96 bits), but still relies on
     * the legacy CTR mode KDF, which uses a 112 bit master SALT.
     */
    memset(tmp_key, 0x0, MAX_SRTP_KEY_LEN);
    memcpy(tmp_key, master_key->key, input_keylen);

/* initialize KDF state     */
#if defined(OPENSSL) && defined(OPENSSL_KDF)
    stat = srtp_kdf_init(&kdf, tmp_key, rtp_base_key_len, rtp_salt_len);
#else
    stat = srtp_kdf_init(&kdf, tmp_key, kdf_keylen);
#endif
    if (stat) {
        /* zeroize temp buffer */
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
    }

    /* generate encryption key  */
    stat = srtp_kdf_generate(&kdf, label_rtp_encryption, tmp_key,
                             rtp_base_key_len);
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
        debug_print0(mod_srtp, "found rtp_salt_len > 0, generating salt");

        /* generate encryption salt, put after encryption key */
        stat = srtp_kdf_generate(&kdf, label_rtp_salt,
                                 tmp_key + rtp_base_key_len, rtp_salt_len);
        if (stat) {
            /* zeroize temp buffer */
            octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
            return srtp_err_status_init_fail;
        }
        memcpy(session_keys->salt, tmp_key + rtp_base_key_len,
               SRTP_AEAD_SALT_LEN);
    }
    if (rtp_salt_len > 0) {
        debug_print(mod_srtp, "cipher salt: %s",
                    srtp_octet_string_hex_string(tmp_key + rtp_base_key_len,
                                                 rtp_salt_len));
    }

    /* initialize cipher */
    stat = srtp_cipher_init(session_keys->rtp_cipher, tmp_key);
    if (stat) {
        /* zeroize temp buffer */
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
    }

    if (session_keys->rtp_xtn_hdr_cipher) {
        /* generate extensions header encryption key  */
        size_t rtp_xtn_hdr_keylen;
        size_t rtp_xtn_hdr_base_key_len;
        size_t rtp_xtn_hdr_salt_len;
        srtp_kdf_t tmp_kdf;
        srtp_kdf_t *xtn_hdr_kdf;

        if (session_keys->rtp_xtn_hdr_cipher->type !=
            session_keys->rtp_cipher->type) {
            /*
             * With GCM ciphers, the header extensions are still encrypted using
             * the corresponding ICM cipher.
             * See https://tools.ietf.org/html/rfc7714#section-8.3
             */
            uint8_t tmp_xtn_hdr_key[MAX_SRTP_KEY_LEN];
            rtp_xtn_hdr_keylen =
                srtp_cipher_get_key_length(session_keys->rtp_xtn_hdr_cipher);
            rtp_xtn_hdr_base_key_len = base_key_length(
                session_keys->rtp_xtn_hdr_cipher->type, rtp_xtn_hdr_keylen);
            rtp_xtn_hdr_salt_len =
                rtp_xtn_hdr_keylen - rtp_xtn_hdr_base_key_len;
            if (rtp_xtn_hdr_salt_len > rtp_salt_len) {
                switch (session_keys->rtp_cipher->type->id) {
                case SRTP_AES_GCM_128:
                case SRTP_AES_GCM_256:
                    /*
                     * The shorter GCM salt is padded to the required ICM salt
                     * length.
                     */
                    rtp_xtn_hdr_salt_len = rtp_salt_len;
                    break;
                default:
                    /* zeroize temp buffer */
                    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
                    return srtp_err_status_bad_param;
                }
            }
            memset(tmp_xtn_hdr_key, 0x0, MAX_SRTP_KEY_LEN);
            memcpy(tmp_xtn_hdr_key, master_key->key,
                   (rtp_xtn_hdr_base_key_len + rtp_xtn_hdr_salt_len));
            xtn_hdr_kdf = &tmp_kdf;

/* initialize KDF state */
#if defined(OPENSSL) && defined(OPENSSL_KDF)
            stat =
                srtp_kdf_init(xtn_hdr_kdf, tmp_xtn_hdr_key,
                              rtp_xtn_hdr_base_key_len, rtp_xtn_hdr_salt_len);
#else
            stat = srtp_kdf_init(xtn_hdr_kdf, tmp_xtn_hdr_key, kdf_keylen);
#endif
            octet_string_set_to_zero(tmp_xtn_hdr_key, MAX_SRTP_KEY_LEN);
            if (stat) {
                /* zeroize temp buffer */
                octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
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
        debug_print(
            mod_srtp, "extensions cipher key: %s",
            srtp_octet_string_hex_string(tmp_key, rtp_xtn_hdr_base_key_len));

        /*
         * if the cipher in the srtp context uses a salt, then we need
         * to generate the salt value
         */
        if (rtp_xtn_hdr_salt_len > 0) {
            debug_print0(mod_srtp,
                         "found rtp_xtn_hdr_salt_len > 0, generating salt");

            /* generate encryption salt, put after encryption key */
            stat = srtp_kdf_generate(xtn_hdr_kdf, label_rtp_header_salt,
                                     tmp_key + rtp_xtn_hdr_base_key_len,
                                     rtp_xtn_hdr_salt_len);
            if (stat) {
                /* zeroize temp buffer */
                octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
                return srtp_err_status_init_fail;
            }
        }
        if (rtp_xtn_hdr_salt_len > 0) {
            debug_print(
                mod_srtp, "extensions cipher salt: %s",
                srtp_octet_string_hex_string(tmp_key + rtp_xtn_hdr_base_key_len,
                                             rtp_xtn_hdr_salt_len));
        }

        /* initialize extensions header cipher */
        stat = srtp_cipher_init(session_keys->rtp_xtn_hdr_cipher, tmp_key);
        if (stat) {
            /* zeroize temp buffer */
            octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
            return srtp_err_status_init_fail;
        }

        if (xtn_hdr_kdf != &kdf) {
            /* release memory for custom header extension encryption kdf */
            stat = srtp_kdf_clear(xtn_hdr_kdf);
            if (stat) {
                /* zeroize temp buffer */
                octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
                return srtp_err_status_init_fail;
            }
        }
    }

    /* generate authentication key */
    stat = srtp_kdf_generate(&kdf, label_rtp_msg_auth, tmp_key,
                             srtp_auth_get_key_length(session_keys->rtp_auth));
    if (stat) {
        /* zeroize temp buffer */
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
    }
    debug_print(mod_srtp, "auth key:   %s",
                srtp_octet_string_hex_string(
                    tmp_key, srtp_auth_get_key_length(session_keys->rtp_auth)));

    /* initialize auth function */
    stat = srtp_auth_init(session_keys->rtp_auth, tmp_key);
    if (stat) {
        /* zeroize temp buffer */
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
    }

    /*
     * ...now initialize SRTCP keys
     */

    rtcp_base_key_len =
        base_key_length(session_keys->rtcp_cipher->type, rtcp_keylen);
    rtcp_salt_len = rtcp_keylen - rtcp_base_key_len;
    debug_print(mod_srtp, "rtcp salt len: %zu", rtcp_salt_len);

    /* generate encryption key  */
    stat = srtp_kdf_generate(&kdf, label_rtcp_encryption, tmp_key,
                             rtcp_base_key_len);
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
        debug_print0(mod_srtp, "found rtcp_salt_len > 0, generating rtcp salt");

        /* generate encryption salt, put after encryption key */
        stat = srtp_kdf_generate(&kdf, label_rtcp_salt,
                                 tmp_key + rtcp_base_key_len, rtcp_salt_len);
        if (stat) {
            /* zeroize temp buffer */
            octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
            return srtp_err_status_init_fail;
        }
        memcpy(session_keys->c_salt, tmp_key + rtcp_base_key_len,
               SRTP_AEAD_SALT_LEN);
    }
    debug_print(mod_srtp, "rtcp cipher key: %s",
                srtp_octet_string_hex_string(tmp_key, rtcp_base_key_len));
    if (rtcp_salt_len > 0) {
        debug_print(mod_srtp, "rtcp cipher salt: %s",
                    srtp_octet_string_hex_string(tmp_key + rtcp_base_key_len,
                                                 rtcp_salt_len));
    }

    /* initialize cipher */
    stat = srtp_cipher_init(session_keys->rtcp_cipher, tmp_key);
    if (stat) {
        /* zeroize temp buffer */
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
    }

    /* generate authentication key */
    stat = srtp_kdf_generate(&kdf, label_rtcp_msg_auth, tmp_key,
                             srtp_auth_get_key_length(session_keys->rtcp_auth));
    if (stat) {
        /* zeroize temp buffer */
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
    }

    debug_print(
        mod_srtp, "rtcp auth key:   %s",
        srtp_octet_string_hex_string(
            tmp_key, srtp_auth_get_key_length(session_keys->rtcp_auth)));

    /* initialize auth function */
    stat = srtp_auth_init(session_keys->rtcp_auth, tmp_key);
    if (stat) {
        /* zeroize temp buffer */
        octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
        return srtp_err_status_init_fail;
    }

    /* clear memory then return */
    stat = srtp_kdf_clear(&kdf);
    octet_string_set_to_zero(tmp_key, MAX_SRTP_KEY_LEN);
    if (stat) {
        return srtp_err_status_init_fail;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_stream_init_all_master_keys(srtp_stream_ctx_t *srtp,
                                                   const srtp_policy_t *p)
{
    srtp_err_status_t status = srtp_err_status_ok;
    if (p->key != NULL) {
        if (p->use_mki) {
            return srtp_err_status_bad_param;
        }
        srtp_master_key_t single_master_key;
        srtp->num_master_keys = 1;
        srtp->use_mki = false;
        srtp->mki_size = 0;
        single_master_key.key = p->key;
        single_master_key.mki_id = NULL;
        status = srtp_stream_init_keys(&srtp->session_keys[0],
                                       &single_master_key, 0);
    } else {
        if (p->num_master_keys > SRTP_MAX_NUM_MASTER_KEYS) {
            return srtp_err_status_bad_param;
        }
        if (p->use_mki && p->mki_size == 0) {
            return srtp_err_status_bad_param;
        }

        srtp->num_master_keys = p->num_master_keys;
        srtp->use_mki = p->use_mki;
        srtp->mki_size = p->mki_size;

        for (size_t i = 0; i < srtp->num_master_keys; i++) {
            status = srtp_stream_init_keys(&srtp->session_keys[i], p->keys[i],
                                           srtp->mki_size);
            if (status) {
                return status;
            }
        }
    }

    return status;
}

static srtp_err_status_t srtp_stream_init(srtp_stream_ctx_t *srtp,
                                          const srtp_policy_t *p)
{
    srtp_err_status_t err;

    err = srtp_valid_policy(p);
    if (err != srtp_err_status_ok) {
        return err;
    }

    debug_print(mod_srtp, "initializing stream (SSRC: 0x%08x)",
                (unsigned int)p->ssrc.value);

    /* initialize replay database */
    /*
     * window size MUST be at least 64.  MAY be larger.  Values more than
     * 2^15 aren't meaningful due to how extended sequence numbers are
     * calculated.
     * Let a window size of 0 imply the default value.
     */

    if (p->window_size != 0 &&
        (p->window_size < 64 || p->window_size >= 0x8000))
        return srtp_err_status_bad_param;

    if (p->window_size != 0) {
        err = srtp_rdbx_init(&srtp->rtp_rdbx, p->window_size);
    } else {
        err = srtp_rdbx_init(&srtp->rtp_rdbx, 128);
    }
    if (err) {
        return err;
    }

    /* set the SSRC value */
    srtp->ssrc = htonl(p->ssrc.value);

    /* reset pending ROC */
    srtp->pending_roc = 0;

    /* set the security service flags */
    srtp->rtp_services = p->rtp.sec_serv;
    srtp->rtcp_services = p->rtcp.sec_serv;

    /*
     * set direction to unknown - this flag gets checked in srtp_protect(),
     * srtp_unprotect(), srtp_protect_rtcp(), and srtp_unprotect_rtcp(), and
     * gets set appropriately if it is set to unknown.
     */
    srtp->direction = dir_unknown;

    /* initialize SRTCP replay database */
    srtp_rdb_init(&srtp->rtcp_rdb);

    /* initialize allow_repeat_tx */
    srtp->allow_repeat_tx = p->allow_repeat_tx;

    /* DAM - no RTCP key limit at present */

    /* initialize keys */
    err = srtp_stream_init_all_master_keys(srtp, p);
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

void srtp_event_reporter(srtp_event_data_t *data)
{
    srtp_err_report(srtp_err_level_warning,
                    "srtp: in stream 0x%x: ", (unsigned int)data->ssrc);

    switch (data->event) {
    case event_ssrc_collision:
        srtp_err_report(srtp_err_level_warning, "\tSSRC collision\n");
        break;
    case event_key_soft_limit:
        srtp_err_report(srtp_err_level_warning,
                        "\tkey usage soft limit reached\n");
        break;
    case event_key_hard_limit:
        srtp_err_report(srtp_err_level_warning,
                        "\tkey usage hard limit reached\n");
        break;
    case event_packet_index_limit:
        srtp_err_report(srtp_err_level_warning,
                        "\tpacket index limit reached\n");
        break;
    default:
        srtp_err_report(srtp_err_level_warning,
                        "\tunknown event reported to handler\n");
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

srtp_err_status_t srtp_install_event_handler(srtp_event_handler_func_t func)
{
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
 * Check if the given extension header id is / should be encrypted.
 * Returns true if yes, otherwise false.
 */
static bool srtp_protect_extension_header(srtp_stream_ctx_t *stream, uint8_t id)
{
    uint8_t *enc_xtn_hdr = stream->enc_xtn_hdr;
    size_t count = stream->enc_xtn_hdr_count;

    if (!enc_xtn_hdr || count <= 0) {
        return false;
    }

    while (count > 0) {
        if (*enc_xtn_hdr == id) {
            return true;
        }

        enc_xtn_hdr++;
        count--;
    }
    return false;
}

/*
 * extensions header encryption RFC 6904
 */
static srtp_err_status_t srtp_process_header_encryption(
    srtp_stream_ctx_t *stream,
    srtp_hdr_xtnd_t *xtn_hdr,
    srtp_session_keys_t *session_keys)
{
    srtp_err_status_t status;
    uint8_t keystream[257]; /* Maximum 2 bytes header + 255 bytes data. */
    size_t keystream_pos;
    uint8_t *xtn_hdr_data = ((uint8_t *)xtn_hdr) + octets_in_rtp_xtn_hdr;
    uint8_t *xtn_hdr_end =
        xtn_hdr_data + (ntohs(xtn_hdr->length) * sizeof(uint32_t));

    if (ntohs(xtn_hdr->profile_specific) == xtn_hdr_one_byte_profile) {
        /* RFC 5285, section 4.2. One-Byte Header */
        while (xtn_hdr_data < xtn_hdr_end) {
            uint8_t xid = (*xtn_hdr_data & 0xf0) >> 4;
            size_t xlen = (*xtn_hdr_data & 0x0f) + 1;
            size_t xlen_with_header = 1 + xlen;
            xtn_hdr_data++;

            if (xtn_hdr_data + xlen > xtn_hdr_end) {
                return srtp_err_status_parse_err;
            }

            if (xid == 15) {
                /* found header 15, stop further processing */
                break;
            }

            status = srtp_cipher_output(session_keys->rtp_xtn_hdr_cipher,
                                        keystream, &xlen_with_header);
            if (status) {
                return srtp_err_status_cipher_fail;
            }

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

            /* skip padding bytes */
            while (xtn_hdr_data < xtn_hdr_end && *xtn_hdr_data == 0) {
                xtn_hdr_data++;
            }
        }
    } else if ((ntohs(xtn_hdr->profile_specific) & 0xfff0) ==
               xtn_hdr_two_byte_profile) {
        /* RFC 5285, section 4.3. Two-Byte Header */
        while (xtn_hdr_data + 1 < xtn_hdr_end) {
            uint8_t xid = *xtn_hdr_data;
            size_t xlen = *(xtn_hdr_data + 1);
            size_t xlen_with_header = 2 + xlen;
            xtn_hdr_data += 2;

            if (xtn_hdr_data + xlen > xtn_hdr_end) {
                return srtp_err_status_parse_err;
            }

            status = srtp_cipher_output(session_keys->rtp_xtn_hdr_cipher,
                                        keystream, &xlen_with_header);
            if (status) {
                return srtp_err_status_cipher_fail;
            }

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

/*
 * AEAD uses a new IV formation method.  This function implements
 * section 8.1. (SRTP IV Formation for AES-GCM) of RFC7714.
 * The calculation is defined as, where (+) is the xor operation:
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
 * Input:  *session_keys - pointer to SRTP stream context session keys,
 *                         used to retrieve the SALT
 *         *iv     - Pointer to receive the calculated IV
 *         *seq    - The ROC and SEQ value to use for the
 *                   IV calculation.
 *         *hdr    - The RTP header, used to get the SSRC value
 *
 */

static void srtp_calc_aead_iv(srtp_session_keys_t *session_keys,
                              v128_t *iv,
                              srtp_xtd_seq_num_t *seq,
                              const srtp_hdr_t *hdr)
{
    v128_t in;
    v128_t salt;

    uint32_t local_roc = (uint32_t)(*seq >> 16);
    uint16_t local_seq = (uint16_t)*seq;

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
    memcpy(salt.v8, session_keys->salt, SRTP_AEAD_SALT_LEN);
    debug_print(mod_srtp, "RTP SALT = %s\n", v128_hex_string(&salt));

    /*
     * Finally, apply tyhe SALT to the input
     */
    v128_xor(iv, &in, &salt);
}

static srtp_err_status_t srtp_get_session_keys_for_packet(
    srtp_stream_ctx_t *stream,
    const uint8_t *hdr,
    size_t pkt_octet_len,
    size_t tag_len,
    srtp_session_keys_t **session_keys)
{
    if (!stream->use_mki) {
        *session_keys = &stream->session_keys[0];
        return srtp_err_status_ok;
    }

    size_t mki_start_location = pkt_octet_len;

    if (tag_len > mki_start_location) {
        return srtp_err_status_bad_mki;
    }

    mki_start_location -= tag_len;

    if (stream->mki_size > mki_start_location) {
        return srtp_err_status_bad_mki;
    }

    mki_start_location -= stream->mki_size;

    for (size_t i = 0; i < stream->num_master_keys; i++) {
        if (memcmp(hdr + mki_start_location, stream->session_keys[i].mki_id,
                   stream->mki_size) == 0) {
            *session_keys = &stream->session_keys[i];
            return srtp_err_status_ok;
        }
    }

    return srtp_err_status_bad_mki;
}

static srtp_err_status_t srtp_get_session_keys_for_rtp_packet(
    srtp_stream_ctx_t *stream,
    const uint8_t *hdr,
    size_t pkt_octet_len,
    srtp_session_keys_t **session_keys)
{
    size_t tag_len = 0;

    // Determine the authentication tag size
    if (stream->session_keys[0].rtp_cipher->algorithm == SRTP_AES_GCM_128 ||
        stream->session_keys[0].rtp_cipher->algorithm == SRTP_AES_GCM_256) {
        tag_len = 0;
    } else {
        tag_len = srtp_auth_get_tag_length(stream->session_keys[0].rtp_auth);
    }

    return srtp_get_session_keys_for_packet(stream, hdr, pkt_octet_len, tag_len,
                                            session_keys);
}

static srtp_err_status_t srtp_get_session_keys_for_rtcp_packet(
    srtp_stream_ctx_t *stream,
    const uint8_t *hdr,
    size_t pkt_octet_len,
    srtp_session_keys_t **session_keys)
{
    size_t tag_len = 0;

    // Determine the authentication tag size
    if (stream->session_keys[0].rtcp_cipher->algorithm == SRTP_AES_GCM_128 ||
        stream->session_keys[0].rtcp_cipher->algorithm == SRTP_AES_GCM_256) {
        tag_len = 0;
    } else {
        tag_len = srtp_auth_get_tag_length(stream->session_keys[0].rtcp_auth);
    }

    return srtp_get_session_keys_for_packet(stream, hdr, pkt_octet_len, tag_len,
                                            session_keys);
}

static srtp_err_status_t srtp_estimate_index(srtp_rdbx_t *rdbx,
                                             uint32_t roc,
                                             srtp_xtd_seq_num_t *est,
                                             srtp_sequence_number_t seq,
                                             ssize_t *delta)
{
    *est = (srtp_xtd_seq_num_t)(((uint64_t)roc) << 16) | seq;
    *delta = *est - rdbx->index;

    if (*est > rdbx->index) {
        if (*est - rdbx->index > seq_num_median) {
            *delta = 0;
            return srtp_err_status_pkt_idx_adv;
        }
    } else if (*est < rdbx->index) {
        if (rdbx->index - *est > seq_num_median) {
            *delta = 0;
            return srtp_err_status_pkt_idx_old;
        }
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t srtp_get_est_pkt_index(const srtp_hdr_t *hdr,
                                                srtp_stream_ctx_t *stream,
                                                srtp_xtd_seq_num_t *est,
                                                ssize_t *delta)
{
    srtp_err_status_t result = srtp_err_status_ok;

    if (stream->pending_roc) {
        result = srtp_estimate_index(&stream->rtp_rdbx, stream->pending_roc,
                                     est, ntohs(hdr->seq), delta);
    } else {
        /* estimate packet index from seq. num. in header */
        *delta =
            srtp_rdbx_estimate_index(&stream->rtp_rdbx, est, ntohs(hdr->seq));
    }

    debug_print(mod_srtp, "estimated u_packet index: %016" PRIx64, *est);

    return result;
}

/*
 * This function handles outgoing SRTP packets while in AEAD mode,
 * which currently supports AES-GCM encryption.  All packets are
 * encrypted and authenticated.
 */
static srtp_err_status_t srtp_protect_aead(srtp_ctx_t *ctx,
                                           srtp_stream_ctx_t *stream,
                                           const uint8_t *rtp,
                                           size_t rtp_len,
                                           uint8_t *srtp,
                                           size_t *srtp_len,
                                           srtp_session_keys_t *session_keys)
{
    const srtp_hdr_t *hdr = (const srtp_hdr_t *)rtp;
    size_t enc_start;         /* offset to start of encrypted portion   */
    size_t enc_octet_len = 0; /* number of octets in encrypted portion  */
    srtp_xtd_seq_num_t est;   /* estimated xtd_seq_num_t of *hdr        */
    ssize_t delta;            /* delta of local pkt idx and that in hdr */
    srtp_err_status_t status;
    size_t tag_len;
    v128_t iv;
    size_t aad_len;

    debug_print0(mod_srtp, "function srtp_protect_aead");

    /*
     * update the key usage limit, and check it to make sure that we
     * didn't just hit either the soft limit or the hard limit, and call
     * the event handler if we hit either.
     */
    switch (srtp_key_limit_update(session_keys->limit)) {
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
    tag_len = srtp_auth_get_tag_length(session_keys->rtp_auth);

    /* check output length */
    if (*srtp_len < rtp_len + tag_len + stream->mki_size) {
        return srtp_err_status_buffer_small;
    }

    /*
     * find starting point for encryption and length of data to be
     * encrypted - the encrypted portion starts after the rtp header
     * extension, if present; otherwise, it starts after the last csrc,
     * if any are present
     */
    enc_start = srtp_get_rtp_hdr_len(hdr);
    if (hdr->x == 1) {
        enc_start += srtp_get_rtp_xtn_hdr_len(hdr, rtp);
    }

    bool cryptex_inuse, cryptex_inplace;
    status = srtp_cryptex_protect_init(stream, hdr, rtp, srtp, &cryptex_inuse,
                                       &cryptex_inplace, &enc_start);
    if (status) {
        return status;
    }

    if (cryptex_inuse && !cryptex_inplace && hdr->cc) {
        debug_print0(mod_srtp,
                     "unsupported cryptex mode, AEAD, CC and not inplace io");
        return srtp_err_status_cryptex_err;
    }

    /* note: the passed size is without the auth tag */
    if (enc_start > rtp_len) {
        return srtp_err_status_parse_err;
    }
    enc_octet_len = rtp_len - enc_start;

    /* if not-inplace then need to copy full rtp header */
    if (rtp != srtp) {
        memcpy(srtp, rtp, enc_start);
    }

    /*
     * estimate the packet index using the start of the replay window
     * and the sequence number from the header
     */
    status = srtp_get_est_pkt_index(hdr, stream, &est, &delta);

    if (status && (status != srtp_err_status_pkt_idx_adv)) {
        return status;
    }

    if (status == srtp_err_status_pkt_idx_adv) {
        srtp_rdbx_set_roc_seq(&stream->rtp_rdbx, (uint32_t)(est >> 16),
                              (uint16_t)(est & 0xFFFF));
        stream->pending_roc = 0;
        srtp_rdbx_add_index(&stream->rtp_rdbx, 0);
    } else {
        status = srtp_rdbx_check(&stream->rtp_rdbx, delta);
        if (status) {
            if (status != srtp_err_status_replay_fail ||
                !stream->allow_repeat_tx)
                return status; /* we've been asked to reuse an index */
        }
        srtp_rdbx_add_index(&stream->rtp_rdbx, delta);
    }

    debug_print(mod_srtp, "estimated packet index: %016" PRIx64, est);

    /*
     * AEAD uses a new IV formation method
     */
    srtp_calc_aead_iv(session_keys, &iv, &est, hdr);
    /* shift est, put into network byte order */
    est = be64_to_cpu(est << 16);

    status = srtp_cipher_set_iv(session_keys->rtp_cipher, (uint8_t *)&iv,
                                srtp_direction_encrypt);
    if (!status && session_keys->rtp_xtn_hdr_cipher) {
        iv.v32[0] = 0;
        iv.v32[1] = hdr->ssrc;
        iv.v64[1] = est;
        status = srtp_cipher_set_iv(session_keys->rtp_xtn_hdr_cipher,
                                    (uint8_t *)&iv, srtp_direction_encrypt);
    }
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    if (hdr->x == 1 && session_keys->rtp_xtn_hdr_cipher) {
        /*
         * extensions header encryption RFC 6904
         */
        status = srtp_process_header_encryption(
            stream, srtp_get_rtp_xtn_hdr(hdr, srtp), session_keys);
        if (status) {
            return status;
        }
    }

    if (cryptex_inuse) {
        status = srtp_cryptex_protect(cryptex_inplace, hdr, srtp,
                                      session_keys->rtp_cipher);
        if (status) {
            return status;
        }
    }

    /*
     * Set the AAD over the RTP header
     */
    aad_len = enc_start;
    status = srtp_cipher_set_aad(session_keys->rtp_cipher, srtp, aad_len);
    if (status) {
        return (srtp_err_status_cipher_fail);
    }

    /* Encrypt the payload  */
    size_t outlen = *srtp_len - enc_start;
    status = srtp_cipher_encrypt(session_keys->rtp_cipher, rtp + enc_start,
                                 enc_octet_len, srtp + enc_start, &outlen);
    enc_octet_len = outlen;
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    if (stream->use_mki) {
        srtp_inject_mki(srtp + enc_start + enc_octet_len, session_keys,
                        stream->mki_size);
    }

    if (cryptex_inuse) {
        srtp_cryptex_protect_cleanup(cryptex_inplace, hdr, srtp);
    }

    *srtp_len = enc_start + enc_octet_len;

    /* increase the packet length by the length of the mki_size */
    *srtp_len += stream->mki_size;

    return srtp_err_status_ok;
}

/*
 * This function handles incoming SRTP packets while in AEAD mode,
 * which currently supports AES-GCM encryption.  All packets are
 * encrypted and authenticated.  Note, the auth tag is at the end
 * of the packet stream and is automatically checked by GCM
 * when decrypting the payload.
 */
static srtp_err_status_t srtp_unprotect_aead(srtp_ctx_t *ctx,
                                             srtp_stream_ctx_t *stream,
                                             ssize_t delta,
                                             srtp_xtd_seq_num_t est,
                                             const uint8_t *srtp,
                                             size_t srtp_len,
                                             uint8_t *rtp,
                                             size_t *rtp_len,
                                             srtp_session_keys_t *session_keys,
                                             bool advance_packet_index)
{
    const srtp_hdr_t *hdr = (const srtp_hdr_t *)srtp;
    size_t enc_start;         /* offset to start of encrypted portion  */
    size_t enc_octet_len = 0; /* number of octets in encrypted portion */
    v128_t iv;
    srtp_err_status_t status;
    size_t tag_len;
    size_t aad_len;

    debug_print0(mod_srtp, "function srtp_unprotect_aead");

    debug_print(mod_srtp, "estimated u_packet index: %016" PRIx64, est);

    /* get tag length from stream */
    tag_len = srtp_auth_get_tag_length(session_keys->rtp_auth);

    /*
     * AEAD uses a new IV formation method
     */
    srtp_calc_aead_iv(session_keys, &iv, &est, hdr);
    status = srtp_cipher_set_iv(session_keys->rtp_cipher, (uint8_t *)&iv,
                                srtp_direction_decrypt);
    if (!status && session_keys->rtp_xtn_hdr_cipher) {
        iv.v32[0] = 0;
        iv.v32[1] = hdr->ssrc;
        iv.v64[1] = be64_to_cpu(est << 16);
        status = srtp_cipher_set_iv(session_keys->rtp_xtn_hdr_cipher,
                                    (uint8_t *)&iv, srtp_direction_encrypt);
    }
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    enc_start = srtp_get_rtp_hdr_len(hdr);
    if (hdr->x == 1) {
        enc_start += srtp_get_rtp_xtn_hdr_len(hdr, srtp);
    }

    bool cryptex_inuse, cryptex_inplace;
    status = srtp_cryptex_unprotect_init(stream, hdr, srtp, rtp, &cryptex_inuse,
                                         &cryptex_inplace, &enc_start);
    if (status) {
        return status;
    }

    if (cryptex_inuse && !cryptex_inplace && hdr->cc) {
        debug_print0(mod_srtp,
                     "unsupported cryptex mode, AEAD, CC and not inplace io");
        return srtp_err_status_cryptex_err;
    }

    if (enc_start > srtp_len - tag_len - stream->mki_size) {
        return srtp_err_status_parse_err;
    }

    /*
     * We pass the tag down to the cipher when doing GCM mode
     */
    enc_octet_len = srtp_len - enc_start - stream->mki_size;

    /*
     * Sanity check the encrypted payload length against
     * the tag size.  It must always be at least as large
     * as the tag length.
     */
    if (enc_octet_len < tag_len) {
        return srtp_err_status_cipher_fail;
    }

    /* check output length */
    if (*rtp_len < srtp_len - stream->mki_size - tag_len) {
        return srtp_err_status_buffer_small;
    }

    /* if not-inplace then need to copy full rtp header */
    if (srtp != rtp) {
        memcpy(rtp, srtp, enc_start);
    }

    /*
     * update the key usage limit, and check it to make sure that we
     * didn't just hit either the soft limit or the hard limit, and call
     * the event handler if we hit either.
     */
    switch (srtp_key_limit_update(session_keys->limit)) {
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

    if (cryptex_inuse) {
        status = srtp_cryptex_unprotect(cryptex_inplace, hdr, rtp,
                                        session_keys->rtp_cipher);
        if (status) {
            return status;
        }
    }

    /*
     * Set the AAD for AES-GCM, which is the RTP header
     */
    aad_len = enc_start;
    status = srtp_cipher_set_aad(session_keys->rtp_cipher, srtp, aad_len);
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /* Decrypt the ciphertext.  This also checks the auth tag based
     * on the AAD we just specified above */
    status =
        srtp_cipher_decrypt(session_keys->rtp_cipher, srtp + enc_start,
                            enc_octet_len, rtp + enc_start, &enc_octet_len);
    if (status) {
        return status;
    }

    if (hdr->x == 1 && session_keys->rtp_xtn_hdr_cipher) {
        /*
         * extensions header encryption RFC 6904
         */
        status = srtp_process_header_encryption(
            stream, srtp_get_rtp_xtn_hdr(hdr, rtp), session_keys);
        if (status) {
            return status;
        }
    }

    if (cryptex_inuse) {
        srtp_cryptex_unprotect_cleanup(cryptex_inplace, hdr, rtp);
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
        status =
            srtp_stream_clone(ctx->stream_template, hdr->ssrc, &new_stream);
        if (status) {
            return status;
        }

        /* add new stream to the list */
        status = srtp_insert_or_dealloc_stream(ctx->stream_list, new_stream,
                                               ctx->stream_template);
        if (status) {
            return status;
        }

        /* set stream (the pointer used in this function) */
        stream = new_stream;
    }

    /*
     * the message authentication function passed, so add the packet
     * index into the replay database
     */
    if (advance_packet_index) {
        uint32_t roc_to_set = (uint32_t)(est >> 16);
        uint16_t seq_to_set = (uint16_t)(est & 0xFFFF);
        srtp_rdbx_set_roc_seq(&stream->rtp_rdbx, roc_to_set, seq_to_set);
        stream->pending_roc = 0;
        srtp_rdbx_add_index(&stream->rtp_rdbx, 0);
    } else {
        srtp_rdbx_add_index(&stream->rtp_rdbx, delta);
    }

    *rtp_len = enc_start + enc_octet_len;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_protect(srtp_t ctx,
                               const uint8_t *rtp,
                               size_t rtp_len,
                               uint8_t *srtp,
                               size_t *srtp_len,
                               size_t mki_index)
{
    const srtp_hdr_t *hdr = (const srtp_hdr_t *)rtp;
    size_t enc_start;         /* offset to start of encrypted portion   */
    uint8_t *auth_start;      /* pointer to start of auth. portion      */
    size_t enc_octet_len = 0; /* number of octets in encrypted portion  */
    srtp_xtd_seq_num_t est;   /* estimated xtd_seq_num_t of *hdr        */
    ssize_t delta;            /* delta of local pkt idx and that in hdr */
    uint8_t *auth_tag = NULL; /* location of auth_tag within packet     */
    srtp_err_status_t status;
    size_t tag_len;
    srtp_stream_ctx_t *stream;
    size_t prefix_len;
    srtp_session_keys_t *session_keys = NULL;

    debug_print0(mod_srtp, "function srtp_protect");

    /* Verify RTP header */
    status = srtp_validate_rtp_header(rtp, rtp_len);
    if (status) {
        return status;
    }

    /* check the packet length - it must at least contain a full header */
    if (rtp_len < octets_in_rtp_header) {
        return srtp_err_status_bad_param;
    }

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

            /* allocate and initialize a new stream */
            status =
                srtp_stream_clone(ctx->stream_template, hdr->ssrc, &new_stream);
            if (status) {
                return status;
            }

            /* add new stream to the list */
            status = srtp_insert_or_dealloc_stream(ctx->stream_list, new_stream,
                                                   ctx->stream_template);
            if (status) {
                return status;
            }

            /* set direction to outbound */
            new_stream->direction = dir_srtp_sender;

            /* set stream (the pointer used in this function) */
            stream = new_stream;
        } else {
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
        } else {
            srtp_handle_event(ctx, stream, event_ssrc_collision);
        }
    }

    status = srtp_get_session_keys(stream, mki_index, &session_keys);
    if (status) {
        return status;
    }

    /*
     * Check if this is an AEAD stream (GCM mode).  If so, then dispatch
     * the request to our AEAD handler.
     */
    if (session_keys->rtp_cipher->algorithm == SRTP_AES_GCM_128 ||
        session_keys->rtp_cipher->algorithm == SRTP_AES_GCM_256) {
        return srtp_protect_aead(ctx, stream, rtp, rtp_len, srtp, srtp_len,
                                 session_keys);
    }

    /*
     * update the key usage limit, and check it to make sure that we
     * didn't just hit either the soft limit or the hard limit, and call
     * the event handler if we hit either.
     */
    switch (srtp_key_limit_update(session_keys->limit)) {
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

    /* get tag length from stream */
    tag_len = srtp_auth_get_tag_length(session_keys->rtp_auth);

    /* check output length */
    if (*srtp_len < rtp_len + stream->mki_size + tag_len) {
        return srtp_err_status_buffer_small;
    }

    /*
     * find starting point for encryption and length of data to be
     * encrypted - the encrypted portion starts after the rtp header
     * extension, if present; otherwise, it starts after the last csrc,
     * if any are present
     */
    enc_start = srtp_get_rtp_hdr_len(hdr);
    if (hdr->x == 1) {
        enc_start += srtp_get_rtp_xtn_hdr_len(hdr, rtp);
    }

    bool cryptex_inuse, cryptex_inplace;
    status = srtp_cryptex_protect_init(stream, hdr, rtp, srtp, &cryptex_inuse,
                                       &cryptex_inplace, &enc_start);
    if (status) {
        return status;
    }

    if (enc_start > rtp_len) {
        return srtp_err_status_parse_err;
    }
    enc_octet_len = rtp_len - enc_start;

    /* if not-inplace then need to copy full rtp header */
    if (rtp != srtp) {
        memcpy(srtp, rtp, enc_start);
    }

    if (stream->use_mki) {
        srtp_inject_mki(srtp + rtp_len, session_keys, stream->mki_size);
    }

    /*
     * if we're providing authentication, set the auth_start and auth_tag
     * pointers to the proper locations; otherwise, set auth_start to NULL
     * to indicate that no authentication is needed
     */
    if (stream->rtp_services & sec_serv_auth) {
        auth_start = srtp;
        auth_tag = srtp + rtp_len + stream->mki_size;
    } else {
        auth_start = NULL;
        auth_tag = NULL;
    }

    /*
     * estimate the packet index using the start of the replay window
     * and the sequence number from the header
     */
    status = srtp_get_est_pkt_index(hdr, stream, &est, &delta);

    if (status && (status != srtp_err_status_pkt_idx_adv)) {
        return status;
    }

    if (status == srtp_err_status_pkt_idx_adv) {
        srtp_rdbx_set_roc_seq(&stream->rtp_rdbx, (uint32_t)(est >> 16),
                              (uint16_t)(est & 0xFFFF));
        stream->pending_roc = 0;
        srtp_rdbx_add_index(&stream->rtp_rdbx, 0);
    } else {
        status = srtp_rdbx_check(&stream->rtp_rdbx, delta);
        if (status) {
            if (status != srtp_err_status_replay_fail ||
                !stream->allow_repeat_tx)
                return status; /* we've been asked to reuse an index */
        }
        srtp_rdbx_add_index(&stream->rtp_rdbx, delta);
    }

    debug_print(mod_srtp, "estimated packet index: %016" PRIx64, est);

    /*
     * if we're using rindael counter mode, set nonce and seq
     */
    if (session_keys->rtp_cipher->type->id == SRTP_AES_ICM_128 ||
        session_keys->rtp_cipher->type->id == SRTP_AES_ICM_192 ||
        session_keys->rtp_cipher->type->id == SRTP_AES_ICM_256) {
        v128_t iv;

        iv.v32[0] = 0;
        iv.v32[1] = hdr->ssrc;
        iv.v64[1] = be64_to_cpu(est << 16);
        status = srtp_cipher_set_iv(session_keys->rtp_cipher, (uint8_t *)&iv,
                                    srtp_direction_encrypt);
        if (!status && session_keys->rtp_xtn_hdr_cipher) {
            status = srtp_cipher_set_iv(session_keys->rtp_xtn_hdr_cipher,
                                        (uint8_t *)&iv, srtp_direction_encrypt);
        }
    } else {
        v128_t iv;

        /* otherwise, set the index to est */
        iv.v64[0] = 0;
        iv.v64[1] = be64_to_cpu(est);
        status = srtp_cipher_set_iv(session_keys->rtp_cipher, (uint8_t *)&iv,
                                    srtp_direction_encrypt);
        if (!status && session_keys->rtp_xtn_hdr_cipher) {
            status = srtp_cipher_set_iv(session_keys->rtp_xtn_hdr_cipher,
                                        (uint8_t *)&iv, srtp_direction_encrypt);
        }
    }
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /* shift est, put into network byte order */
    est = be64_to_cpu(est << 16);

    /*
     * if we're authenticating using a universal hash, put the keystream
     * prefix into the authentication tag
     */
    if (auth_start) {
        prefix_len = srtp_auth_get_prefix_length(session_keys->rtp_auth);
        if (prefix_len) {
            status = srtp_cipher_output(session_keys->rtp_cipher, auth_tag,
                                        &prefix_len);
            if (status) {
                return srtp_err_status_cipher_fail;
            }
            debug_print(mod_srtp, "keystream prefix: %s",
                        srtp_octet_string_hex_string(auth_tag, prefix_len));
        }
    }

    if (hdr->x == 1 && session_keys->rtp_xtn_hdr_cipher) {
        /*
         * extensions header encryption RFC 6904
         */
        status = srtp_process_header_encryption(
            stream, srtp_get_rtp_xtn_hdr(hdr, srtp), session_keys);
        if (status) {
            return status;
        }
    }

    if (cryptex_inuse) {
        status = srtp_cryptex_protect(cryptex_inplace, hdr, srtp,
                                      session_keys->rtp_cipher);
        if (status) {
            return status;
        }
    }

    /* if we're encrypting, exor keystream into the message */
    if (stream->rtp_services & sec_serv_conf) {
        status = srtp_cipher_encrypt(session_keys->rtp_cipher, rtp + enc_start,
                                     enc_octet_len, srtp + enc_start,
                                     &enc_octet_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    } else if (rtp != srtp) {
        /* if no encryption and not-inplace then need to copy rest of packet */
        memcpy(srtp + enc_start, rtp + enc_start, enc_octet_len);
    }

    if (cryptex_inuse) {
        srtp_cryptex_protect_cleanup(cryptex_inplace, hdr, srtp);
    }

    /*
     *  if we're authenticating, run authentication function and put result
     *  into the auth_tag
     */
    if (auth_start) {
        /* initialize auth func context */
        status = srtp_auth_start(session_keys->rtp_auth);
        if (status) {
            return status;
        }

        /* run auth func over packet */
        status = srtp_auth_update(session_keys->rtp_auth, auth_start, rtp_len);
        if (status) {
            return status;
        }

        /* run auth func over ROC, put result into auth_tag */
        debug_print(mod_srtp, "estimated packet index: %016" PRIx64, est);
        status = srtp_auth_compute(session_keys->rtp_auth, (uint8_t *)&est, 4,
                                   auth_tag);
        debug_print(mod_srtp, "srtp auth tag:    %s",
                    srtp_octet_string_hex_string(auth_tag, tag_len));
        if (status) {
            return status;
        }
    }

    *srtp_len = enc_start + enc_octet_len;

    /* increase the packet length by the length of the auth tag */
    *srtp_len += tag_len;

    /* increate the packet length by the mki size if used */
    *srtp_len += stream->mki_size;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_unprotect(srtp_t ctx,
                                 const uint8_t *srtp,
                                 size_t srtp_len,
                                 uint8_t *rtp,
                                 size_t *rtp_len)
{
    const srtp_hdr_t *hdr = (const srtp_hdr_t *)srtp;
    size_t enc_start;               /* pointer to start of encrypted portion  */
    const uint8_t *auth_start;      /* pointer to start of auth. portion      */
    size_t enc_octet_len = 0;       /* number of octets in encrypted portion  */
    const uint8_t *auth_tag = NULL; /* location of auth_tag within packet     */
    srtp_xtd_seq_num_t est;         /* estimated xtd_seq_num_t of *hdr        */
    ssize_t delta;                  /* delta of local pkt idx and that in hdr */
    v128_t iv;
    srtp_err_status_t status;
    srtp_stream_ctx_t *stream;
    uint8_t tmp_tag[SRTP_MAX_TAG_LEN];
    size_t tag_len, prefix_len;
    srtp_session_keys_t *session_keys = NULL;
    bool advance_packet_index = false;
    uint32_t roc_to_set = 0;
    uint16_t seq_to_set = 0;

    debug_print0(mod_srtp, "function srtp_unprotect");

    /* Verify RTP header */
    status = srtp_validate_rtp_header(srtp, srtp_len);
    if (status) {
        return status;
    }

    /* check the packet length - it must at least contain a full header */
    if (srtp_len < octets_in_rtp_header) {
        return srtp_err_status_bad_param;
    }

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
            stream = ctx->stream_template;
            debug_print(mod_srtp, "using provisional stream (SSRC: 0x%08x)",
                        (unsigned int)ntohl(hdr->ssrc));

            /*
             * set estimated packet index to sequence number from header,
             * and set delta equal to the same value
             */
            est = (srtp_xtd_seq_num_t)ntohs(hdr->seq);
            delta = (int)est;
        } else {
            /*
             * no stream corresponding to SSRC found, and we don't do
             * key-sharing, so return an error
             */
            return srtp_err_status_no_ctx;
        }
    } else {
        status = srtp_get_est_pkt_index(hdr, stream, &est, &delta);

        if (status && (status != srtp_err_status_pkt_idx_adv)) {
            return status;
        }

        if (status == srtp_err_status_pkt_idx_adv) {
            advance_packet_index = true;
            roc_to_set = (uint32_t)(est >> 16);
            seq_to_set = (uint16_t)(est & 0xFFFF);
        }

        /* check replay database */
        if (!advance_packet_index) {
            status = srtp_rdbx_check(&stream->rtp_rdbx, delta);
            if (status) {
                return status;
            }
        }
    }

    debug_print(mod_srtp, "estimated u_packet index: %016" PRIx64, est);

    /* Determine if MKI is being used and what session keys should be used */
    status = srtp_get_session_keys_for_rtp_packet(stream, srtp, srtp_len,
                                                  &session_keys);
    if (status) {
        return status;
    }

    /*
     * Check if this is an AEAD stream (GCM mode).  If so, then dispatch
     * the request to our AEAD handler.
     */
    if (session_keys->rtp_cipher->algorithm == SRTP_AES_GCM_128 ||
        session_keys->rtp_cipher->algorithm == SRTP_AES_GCM_256) {
        return srtp_unprotect_aead(ctx, stream, delta, est, srtp, srtp_len, rtp,
                                   rtp_len, session_keys, advance_packet_index);
    }

    /* get tag length from stream */
    tag_len = srtp_auth_get_tag_length(session_keys->rtp_auth);

    /*
     * set the cipher's IV properly, depending on whatever cipher we
     * happen to be using
     */
    if (session_keys->rtp_cipher->type->id == SRTP_AES_ICM_128 ||
        session_keys->rtp_cipher->type->id == SRTP_AES_ICM_192 ||
        session_keys->rtp_cipher->type->id == SRTP_AES_ICM_256) {
        /* aes counter mode */
        iv.v32[0] = 0;
        iv.v32[1] = hdr->ssrc; /* still in network order */
        iv.v64[1] = be64_to_cpu(est << 16);
        status = srtp_cipher_set_iv(session_keys->rtp_cipher, (uint8_t *)&iv,
                                    srtp_direction_decrypt);
        if (!status && session_keys->rtp_xtn_hdr_cipher) {
            status = srtp_cipher_set_iv(session_keys->rtp_xtn_hdr_cipher,
                                        (uint8_t *)&iv, srtp_direction_decrypt);
        }
    } else {
        /* no particular format - set the iv to the packet index */
        iv.v64[0] = 0;
        iv.v64[1] = be64_to_cpu(est);
        status = srtp_cipher_set_iv(session_keys->rtp_cipher, (uint8_t *)&iv,
                                    srtp_direction_decrypt);
        if (!status && session_keys->rtp_xtn_hdr_cipher) {
            status = srtp_cipher_set_iv(session_keys->rtp_xtn_hdr_cipher,
                                        (uint8_t *)&iv, srtp_direction_decrypt);
        }
    }
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /* shift est, put into network byte order */
    est = be64_to_cpu(est << 16);

    enc_start = srtp_get_rtp_hdr_len(hdr);
    if (hdr->x == 1) {
        enc_start += srtp_get_rtp_xtn_hdr_len(hdr, srtp);
    }

    bool cryptex_inuse, cryptex_inplace;
    status = srtp_cryptex_unprotect_init(stream, hdr, srtp, rtp, &cryptex_inuse,
                                         &cryptex_inplace, &enc_start);
    if (status) {
        return status;
    }

    if (enc_start > srtp_len - tag_len - stream->mki_size) {
        return srtp_err_status_parse_err;
    }
    enc_octet_len = srtp_len - enc_start - stream->mki_size - tag_len;

    /* check output length */
    if (*rtp_len < srtp_len - stream->mki_size - tag_len) {
        return srtp_err_status_buffer_small;
    }

    /* if not-inplace then need to copy full rtp header */
    if (srtp != rtp) {
        memcpy(rtp, srtp, enc_start);
    }

    /*
     * if we're providing authentication, set the auth_start and auth_tag
     * pointers to the proper locations; otherwise, set auth_start to NULL
     * to indicate that no authentication is needed
     */
    if (stream->rtp_services & sec_serv_auth) {
        auth_start = srtp;
        auth_tag = srtp + srtp_len - tag_len;
    } else {
        auth_start = NULL;
        auth_tag = NULL;
    }

    /*
     * if we expect message authentication, run the authentication
     * function and compare the result with the value of the auth_tag
     */
    if (auth_start) {
        /*
         * if we're using a universal hash, then we need to compute the
         * keystream prefix for encrypting the universal hash output
         *
         * if the keystream prefix length is zero, then we know that
         * the authenticator isn't using a universal hash function
         */
        if (session_keys->rtp_auth->prefix_len != 0) {
            prefix_len = srtp_auth_get_prefix_length(session_keys->rtp_auth);
            status = srtp_cipher_output(session_keys->rtp_cipher, tmp_tag,
                                        &prefix_len);
            debug_print(mod_srtp, "keystream prefix: %s",
                        srtp_octet_string_hex_string(tmp_tag, prefix_len));
            if (status) {
                return srtp_err_status_cipher_fail;
            }
        }

        /* initialize auth func context */
        status = srtp_auth_start(session_keys->rtp_auth);
        if (status) {
            return status;
        }

        /* now compute auth function over packet */
        status = srtp_auth_update(session_keys->rtp_auth, auth_start,
                                  srtp_len - tag_len - stream->mki_size);
        if (status) {
            return status;
        }

        /* run auth func over ROC, then write tmp tag */
        status = srtp_auth_compute(session_keys->rtp_auth, (uint8_t *)&est, 4,
                                   tmp_tag);

        debug_print(mod_srtp, "computed auth tag:    %s",
                    srtp_octet_string_hex_string(tmp_tag, tag_len));
        debug_print(mod_srtp, "packet auth tag:      %s",
                    srtp_octet_string_hex_string(auth_tag, tag_len));
        if (status) {
            return srtp_err_status_auth_fail;
        }

        if (!srtp_octet_string_equal(tmp_tag, auth_tag, tag_len)) {
            return srtp_err_status_auth_fail;
        }
    }

    /*
     * update the key usage limit, and check it to make sure that we
     * didn't just hit either the soft limit or the hard limit, and call
     * the event handler if we hit either.
     */
    switch (srtp_key_limit_update(session_keys->limit)) {
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

    if (hdr->x == 1 && session_keys->rtp_xtn_hdr_cipher) {
        /* extensions header encryption RFC 6904 */
        status = srtp_process_header_encryption(
            stream, srtp_get_rtp_xtn_hdr(hdr, rtp), session_keys);
        if (status) {
            return status;
        }
    }

    if (cryptex_inuse) {
        status = srtp_cryptex_unprotect(cryptex_inplace, hdr, rtp,
                                        session_keys->rtp_cipher);
        if (status) {
            return status;
        }
    }

    /* if we're decrypting, add keystream into ciphertext */
    if (stream->rtp_services & sec_serv_conf) {
        status =
            srtp_cipher_decrypt(session_keys->rtp_cipher, srtp + enc_start,
                                enc_octet_len, rtp + enc_start, &enc_octet_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    } else if (rtp != srtp) {
        /* if no encryption and not-inplace then need to copy rest of packet */
        memcpy(rtp + enc_start, srtp + enc_start, enc_octet_len);
    }

    if (cryptex_inuse) {
        srtp_cryptex_unprotect_cleanup(cryptex_inplace, hdr, rtp);
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
        status =
            srtp_stream_clone(ctx->stream_template, hdr->ssrc, &new_stream);
        if (status) {
            return status;
        }

        /* add new stream to the list */
        status = srtp_insert_or_dealloc_stream(ctx->stream_list, new_stream,
                                               ctx->stream_template);
        if (status) {
            return status;
        }

        /* set stream (the pointer used in this function) */
        stream = new_stream;
    }

    /*
     * the message authentication function passed, so add the packet
     * index into the replay database
     */
    if (advance_packet_index) {
        srtp_rdbx_set_roc_seq(&stream->rtp_rdbx, roc_to_set, seq_to_set);
        stream->pending_roc = 0;
        srtp_rdbx_add_index(&stream->rtp_rdbx, 0);
    } else {
        srtp_rdbx_add_index(&stream->rtp_rdbx, delta);
    }

    *rtp_len = enc_start + enc_octet_len;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_init(void)
{
    srtp_err_status_t status;

    /* initialize crypto kernel */
    status = srtp_crypto_kernel_init();
    if (status) {
        return status;
    }

    /* load srtp debug module into the kernel */
    status = srtp_crypto_kernel_load_debug_module(&mod_srtp);
    if (status) {
        return status;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_shutdown(void)
{
    srtp_err_status_t status;

    /* shut down crypto kernel */
    status = srtp_crypto_kernel_shutdown();
    if (status) {
        return status;
    }

    /* shutting down crypto kernel frees the srtp debug module as well */

    return srtp_err_status_ok;
}

srtp_stream_ctx_t *srtp_get_stream(srtp_t srtp, uint32_t ssrc)
{
    return srtp_stream_list_get(srtp->stream_list, ssrc);
}

srtp_err_status_t srtp_dealloc(srtp_t session)
{
    srtp_err_status_t status;

    /*
     * we take a conservative deallocation strategy - if we encounter an
     * error deallocating a stream, then we stop trying to deallocate
     * memory and just return an error
     */

    /* deallocate streams */
    status = srtp_remove_and_dealloc_streams(session->stream_list,
                                             session->stream_template);
    if (status) {
        return status;
    }

    /* deallocate stream template, if there is one */
    if (session->stream_template != NULL) {
        status = srtp_stream_dealloc(session->stream_template, NULL);
        if (status) {
            return status;
        }
    }

    /* deallocate stream list */
    status = srtp_stream_list_dealloc(session->stream_list);
    if (status) {
        return status;
    }

    /* deallocate session context */
    srtp_crypto_free(session);

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_stream_add(srtp_t session, const srtp_policy_t *policy)
{
    srtp_err_status_t status;
    srtp_stream_t tmp;

    /* sanity check arguments */
    if (session == NULL) {
        return srtp_err_status_bad_param;
    }

    status = srtp_valid_policy(policy);
    if (status != srtp_err_status_ok) {
        return status;
    }

    /* allocate stream  */
    status = srtp_stream_alloc(&tmp, policy);
    if (status) {
        return status;
    }

    /* initialize stream  */
    status = srtp_stream_init(tmp, policy);
    if (status) {
        srtp_stream_dealloc(tmp, NULL);
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
            srtp_stream_dealloc(tmp, NULL);
            return srtp_err_status_bad_param;
        }
        session->stream_template = tmp;
        session->stream_template->direction = dir_srtp_sender;
        break;
    case (ssrc_any_inbound):
        if (session->stream_template) {
            srtp_stream_dealloc(tmp, NULL);
            return srtp_err_status_bad_param;
        }
        session->stream_template = tmp;
        session->stream_template->direction = dir_srtp_receiver;
        break;
    case (ssrc_specific):
        status = srtp_insert_or_dealloc_stream(session->stream_list, tmp,
                                               session->stream_template);
        if (status) {
            return status;
        }
        break;
    case (ssrc_undefined):
    default:
        srtp_stream_dealloc(tmp, NULL);
        return srtp_err_status_bad_param;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_create(srtp_t *session, /* handle for session     */
                              const srtp_policy_t *policy)
{ /* SRTP policy (list)     */
    srtp_err_status_t stat;
    srtp_ctx_t *ctx;

    /* sanity check arguments */
    if (session == NULL) {
        return srtp_err_status_bad_param;
    }

    if (policy) {
        stat = srtp_valid_policy(policy);
        if (stat != srtp_err_status_ok) {
            return stat;
        }
    }

    /* allocate srtp context and set ctx_ptr */
    ctx = (srtp_ctx_t *)srtp_crypto_alloc(sizeof(srtp_ctx_t));
    if (ctx == NULL) {
        return srtp_err_status_alloc_fail;
    }
    *session = ctx;

    ctx->stream_template = NULL;
    ctx->stream_list = NULL;
    ctx->user_data = NULL;

    /* allocate stream list */
    stat = srtp_stream_list_alloc(&ctx->stream_list);
    if (stat) {
        /* clean up everything */
        srtp_dealloc(*session);
        *session = NULL;
        return stat;
    }

    /*
     * loop over elements in the policy list, allocating and
     * initializing a stream for each element
     */
    while (policy != NULL) {
        stat = srtp_stream_add(ctx, policy);
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

srtp_err_status_t srtp_stream_remove(srtp_t session, uint32_t ssrc)
{
    srtp_stream_ctx_t *stream;
    srtp_err_status_t status;

    /* sanity check arguments */
    if (session == NULL) {
        return srtp_err_status_bad_param;
    }

    /* find and remove stream from the list */
    stream = srtp_stream_list_get(session->stream_list, htonl(ssrc));
    if (stream == NULL) {
        return srtp_err_status_no_ctx;
    }

    srtp_stream_list_remove(session->stream_list, stream);

    /* deallocate the stream */
    status = srtp_stream_dealloc(stream, session->stream_template);
    if (status) {
        return status;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_update(srtp_t session, const srtp_policy_t *policy)
{
    srtp_err_status_t stat;

    /* sanity check arguments */
    if (session == NULL) {
        return srtp_err_status_bad_param;
    }

    stat = srtp_valid_policy(policy);
    if (stat != srtp_err_status_ok) {
        return stat;
    }

    while (policy != NULL) {
        stat = srtp_stream_update(session, policy);
        if (stat) {
            return stat;
        }

        /* set policy to next item in list  */
        policy = policy->next;
    }
    return srtp_err_status_ok;
}

struct update_template_stream_data {
    srtp_err_status_t status;
    srtp_t session;
    srtp_stream_t new_stream_template;
    srtp_stream_list_t new_stream_list;
};

static bool update_template_stream_cb(srtp_stream_t stream, void *raw_data)
{
    struct update_template_stream_data *data =
        (struct update_template_stream_data *)raw_data;
    srtp_t session = data->session;
    uint32_t ssrc = stream->ssrc;
    srtp_xtd_seq_num_t old_index;
    srtp_rdb_t old_rtcp_rdb;

    /* old / non-template streams are copied unchanged */
    if (stream->session_keys[0].rtp_auth !=
        session->stream_template->session_keys[0].rtp_auth) {
        srtp_stream_list_remove(session->stream_list, stream);
        data->status = srtp_insert_or_dealloc_stream(
            data->new_stream_list, stream, session->stream_template);
        if (data->status) {
            return false;
        }
        return true;
    }

    /* save old extended seq */
    old_index = stream->rtp_rdbx.index;
    old_rtcp_rdb = stream->rtcp_rdb;

    /* remove stream */
    data->status = srtp_stream_remove(session, ntohl(ssrc));
    if (data->status) {
        return false;
    }

    /* allocate and initialize a new stream */
    data->status = srtp_stream_clone(data->new_stream_template, ssrc, &stream);
    if (data->status) {
        return false;
    }

    /* add new stream to the head of the new_stream_list */
    data->status = srtp_insert_or_dealloc_stream(data->new_stream_list, stream,
                                                 data->new_stream_template);
    if (data->status) {
        return false;
    }

    /* restore old extended seq */
    stream->rtp_rdbx.index = old_index;
    stream->rtcp_rdb = old_rtcp_rdb;

    return true;
}

static srtp_err_status_t is_update_policy_compatable(
    srtp_stream_t stream,
    const srtp_policy_t *policy)
{
    if (stream->use_mki != policy->use_mki) {
        return srtp_err_status_bad_param;
    }

    if (stream->use_mki && stream->mki_size != policy->mki_size) {
        return srtp_err_status_bad_param;
    }

    return srtp_err_status_ok;
}

static srtp_err_status_t update_template_streams(srtp_t session,
                                                 const srtp_policy_t *policy)
{
    srtp_err_status_t status;
    srtp_stream_t new_stream_template;
    srtp_stream_list_t new_stream_list;

    status = srtp_valid_policy(policy);
    if (status != srtp_err_status_ok) {
        return status;
    }

    if (session->stream_template == NULL) {
        return srtp_err_status_bad_param;
    }

    status = is_update_policy_compatable(session->stream_template, policy);
    if (status != srtp_err_status_ok) {
        return status;
    }

    /* allocate new template stream  */
    status = srtp_stream_alloc(&new_stream_template, policy);
    if (status) {
        return status;
    }

    /* initialize new template stream  */
    status = srtp_stream_init(new_stream_template, policy);
    if (status) {
        srtp_crypto_free(new_stream_template);
        return status;
    }

    /* allocate new stream list */
    status = srtp_stream_list_alloc(&new_stream_list);
    if (status) {
        srtp_crypto_free(new_stream_template);
        return status;
    }

    /* process streams */
    struct update_template_stream_data data = { srtp_err_status_ok, session,
                                                new_stream_template,
                                                new_stream_list };
    srtp_stream_list_for_each(session->stream_list, update_template_stream_cb,
                              &data);
    if (data.status) {
        /* free new allocations */
        srtp_remove_and_dealloc_streams(new_stream_list, new_stream_template);
        srtp_stream_list_dealloc(new_stream_list);
        srtp_stream_dealloc(new_stream_template, NULL);
        return data.status;
    }

    /* dealloc old list / template */
    srtp_remove_and_dealloc_streams(session->stream_list,
                                    session->stream_template);
    srtp_stream_list_dealloc(session->stream_list);
    srtp_stream_dealloc(session->stream_template, NULL);

    /* set new list / template */
    session->stream_template = new_stream_template;
    session->stream_list = new_stream_list;
    return srtp_err_status_ok;
}

static srtp_err_status_t stream_update(srtp_t session,
                                       const srtp_policy_t *policy)
{
    srtp_err_status_t status;
    srtp_xtd_seq_num_t old_index;
    srtp_rdb_t old_rtcp_rdb;
    srtp_stream_t stream;

    status = srtp_valid_policy(policy);
    if (status != srtp_err_status_ok) {
        return status;
    }

    stream = srtp_get_stream(session, htonl(policy->ssrc.value));
    if (stream == NULL) {
        return srtp_err_status_bad_param;
    }

    status = is_update_policy_compatable(stream, policy);
    if (status != srtp_err_status_ok) {
        return status;
    }

    /* save old extendard seq */
    old_index = stream->rtp_rdbx.index;
    old_rtcp_rdb = stream->rtcp_rdb;

    status = srtp_stream_remove(session, policy->ssrc.value);
    if (status) {
        return status;
    }

    status = srtp_stream_add(session, policy);
    if (status) {
        return status;
    }

    stream = srtp_get_stream(session, htonl(policy->ssrc.value));
    if (stream == NULL) {
        return srtp_err_status_fail;
    }

    /* restore old extended seq */
    stream->rtp_rdbx.index = old_index;
    stream->rtcp_rdb = old_rtcp_rdb;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_stream_update(srtp_t session,
                                     const srtp_policy_t *policy)
{
    srtp_err_status_t status;

    /* sanity check arguments */
    if (session == NULL) {
        return srtp_err_status_bad_param;
    }

    status = srtp_valid_policy(policy);
    if (status != srtp_err_status_ok) {
        return status;
    }

    switch (policy->ssrc.type) {
    case (ssrc_any_outbound):
    case (ssrc_any_inbound):
        status = update_template_streams(session, policy);
        break;
    case (ssrc_specific):
        status = stream_update(session, policy);
        break;
    case (ssrc_undefined):
    default:
        return srtp_err_status_bad_param;
    }

    return status;
}

/*
 * The default policy - provides a convenient way for callers to use
 * the default security policy
 *
 * The default policy is defined in RFC 3711
 * (Section 5. Default and mandatory-to-implement Transforms)
 *
 */

/*
 * NOTE: cipher_key_len is really key len (128 bits) plus salt len
 *  (112 bits)
 */
/* There are hard-coded 16's for base_key_len in the key generation code */

void srtp_crypto_policy_set_rtp_default(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_ICM_128;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* default 128 bits per RFC 3711 */
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 10; /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_rtcp_default(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_ICM_128;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* default 128 bits per RFC 3711 */
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 10; /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 4568
     *
     * note that this crypto policy is intended for SRTP, but not SRTCP
     */

    p->cipher_type = SRTP_AES_ICM_128;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* 128 bit key, 112 bit salt */
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* 160 bit key               */
    p->auth_tag_len = 4;  /* 32 bit tag                */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_aes_cm_128_null_auth(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 4568
     *
     * note that this crypto policy is intended for SRTP, but not SRTCP
     */

    p->cipher_type = SRTP_AES_ICM_128;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* 128 bit key, 112 bit salt */
    p->auth_type = SRTP_NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_conf;
}

void srtp_crypto_policy_set_null_cipher_hmac_sha1_80(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 4568
     */

    p->cipher_type = SRTP_NULL_CIPHER;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* 128 bit key, 112 bit salt */
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20;
    p->auth_tag_len = 10;
    p->sec_serv = sec_serv_auth;
}

void srtp_crypto_policy_set_null_cipher_hmac_null(srtp_crypto_policy_t *p)
{
    /*
     * Should only be used for testing
     */

    p->cipher_type = SRTP_NULL_CIPHER;
    p->cipher_key_len =
        SRTP_AES_ICM_128_KEY_LEN_WSALT; /* 128 bit key, 112 bit salt */
    p->auth_type = SRTP_NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_none;
}

void srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 6188
     */

    p->cipher_type = SRTP_AES_ICM_256;
    p->cipher_key_len = SRTP_AES_ICM_256_KEY_LEN_WSALT;
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 10; /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 6188
     *
     * note that this crypto policy is intended for SRTP, but not SRTCP
     */

    p->cipher_type = SRTP_AES_ICM_256;
    p->cipher_key_len = SRTP_AES_ICM_256_KEY_LEN_WSALT;
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 4;  /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

/*
 * AES-256 with no authentication.
 */
void srtp_crypto_policy_set_aes_cm_256_null_auth(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_ICM_256;
    p->cipher_key_len = SRTP_AES_ICM_256_KEY_LEN_WSALT;
    p->auth_type = SRTP_NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_conf;
}

void srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 6188
     */

    p->cipher_type = SRTP_AES_ICM_192;
    p->cipher_key_len = SRTP_AES_ICM_192_KEY_LEN_WSALT;
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 10; /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

void srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32(srtp_crypto_policy_t *p)
{
    /*
     * corresponds to RFC 6188
     *
     * note that this crypto policy is intended for SRTP, but not SRTCP
     */

    p->cipher_type = SRTP_AES_ICM_192;
    p->cipher_key_len = SRTP_AES_ICM_192_KEY_LEN_WSALT;
    p->auth_type = SRTP_HMAC_SHA1;
    p->auth_key_len = 20; /* default 160 bits per RFC 3711 */
    p->auth_tag_len = 4;  /* default 80 bits per RFC 3711 */
    p->sec_serv = sec_serv_conf_and_auth;
}

/*
 * AES-192 with no authentication.
 */
void srtp_crypto_policy_set_aes_cm_192_null_auth(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_ICM_192;
    p->cipher_key_len = SRTP_AES_ICM_192_KEY_LEN_WSALT;
    p->auth_type = SRTP_NULL_AUTH;
    p->auth_key_len = 0;
    p->auth_tag_len = 0;
    p->sec_serv = sec_serv_conf;
}

/*
 * AES-128 GCM mode with 16 octet auth tag.
 */
void srtp_crypto_policy_set_aes_gcm_128_16_auth(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_GCM_128;
    p->cipher_key_len = SRTP_AES_GCM_128_KEY_LEN_WSALT;
    p->auth_type = SRTP_NULL_AUTH; /* GCM handles the auth for us */
    p->auth_key_len = 0;
    p->auth_tag_len = 16; /* 16 octet tag length */
    p->sec_serv = sec_serv_conf_and_auth;
}

/*
 * AES-256 GCM mode with 16 octet auth tag.
 */
void srtp_crypto_policy_set_aes_gcm_256_16_auth(srtp_crypto_policy_t *p)
{
    p->cipher_type = SRTP_AES_GCM_256;
    p->cipher_key_len = SRTP_AES_GCM_256_KEY_LEN_WSALT;
    p->auth_type = SRTP_NULL_AUTH; /* GCM handles the auth for us */
    p->auth_key_len = 0;
    p->auth_tag_len = 16; /* 16 octet tag length */
    p->sec_serv = sec_serv_conf_and_auth;
}

/*
 * secure rtcp functions
 */

/*
 * AEAD uses a new IV formation method.  This function implements
 * section 9.1 (SRTCP IV Formation for AES-GCM) from RFC7714.
 * The calculation is defined as, where (+) is the xor operation:
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
 * Input:  *session_keys - pointer to SRTP stream context session keys,
 *                        used to retrieve the SALT
 *         *iv           - Pointer to recieve the calculated IV
 *         seq_num       - The SEQ value to use for the IV calculation.
 *         *hdr          - The RTP header, used to get the SSRC value
 *
 * Returns: srtp_err_status_ok if no error or srtp_err_status_bad_param
 *          if seq_num is invalid
 *
 */
static srtp_err_status_t srtp_calc_aead_iv_srtcp(
    srtp_session_keys_t *session_keys,
    v128_t *iv,
    uint32_t seq_num,
    const srtcp_hdr_t *hdr)
{
    v128_t in;
    v128_t salt;

    memset(&in, 0, sizeof(v128_t));
    memset(&salt, 0, sizeof(v128_t));

    in.v16[0] = 0;
    memcpy(&in.v16[1], &hdr->ssrc, 4); /* still in network order! */
    in.v16[3] = 0;

    /*
     *  The SRTCP index (seq_num) spans bits 0 through 30 inclusive.
     *  The most significant bit should be zero.
     */
    if (seq_num & 0x80000000UL) {
        return srtp_err_status_bad_param;
    }
    in.v32[2] = htonl(seq_num);

    debug_print(mod_srtp, "Pre-salted RTCP IV = %s\n", v128_hex_string(&in));

    /*
     * Get the SALT value from the context
     */
    memcpy(salt.v8, session_keys->c_salt, 12);
    debug_print(mod_srtp, "RTCP SALT = %s\n", v128_hex_string(&salt));

    /*
     * Finally, apply the SALT to the input
     */
    v128_xor(iv, &in, &salt);

    return srtp_err_status_ok;
}

/*
 * This code handles AEAD ciphers for outgoing RTCP.  We currently support
 * AES-GCM mode with 128 or 256 bit keys.
 */
static srtp_err_status_t srtp_protect_rtcp_aead(
    srtp_stream_ctx_t *stream,
    const uint8_t *rtcp,
    size_t rtcp_len,
    uint8_t *srtcp,
    size_t *srtcp_len,
    srtp_session_keys_t *session_keys)
{
    const srtcp_hdr_t *hdr = (const srtcp_hdr_t *)rtcp;
    size_t enc_start;         /* pointer to start of encrypted portion  */
    uint8_t *trailer_p;       /* pointer to start of trailer            */
    uint32_t trailer;         /* trailer value                          */
    size_t enc_octet_len = 0; /* number of octets in encrypted portion  */
    srtp_err_status_t status;
    size_t tag_len;
    uint32_t seq_num;
    v128_t iv;

    /* get tag length from stream context */
    tag_len = srtp_auth_get_tag_length(session_keys->rtcp_auth);

    /*
     * set encryption start and encryption length - if we're not
     * providing confidentiality, set enc_start to NULL
     */
    enc_start = octets_in_rtcp_header;
    enc_octet_len = rtcp_len - enc_start;

    /* check output length */
    if (*srtcp_len <
        rtcp_len + sizeof(srtcp_trailer_t) + stream->mki_size + tag_len) {
        return srtp_err_status_buffer_small;
    }

    /* if not-inplace then need to copy full rtcp header */
    if (rtcp != srtcp) {
        memcpy(srtcp, rtcp, enc_start);
    }

    /* NOTE: hdr->length is not usable - it refers to only the first
     * RTCP report in the compound packet!
     */
    trailer_p = srtcp + enc_start + enc_octet_len + tag_len;

    if (stream->rtcp_services & sec_serv_conf) {
        trailer = htonl(SRTCP_E_BIT); /* set encrypt bit */
    } else {
        /* 0 is network-order independent */
        trailer = 0x00000000; /* set encrypt bit */
    }

    if (stream->use_mki) {
        srtp_inject_mki(srtcp + rtcp_len + tag_len + sizeof(srtcp_trailer_t),
                        session_keys, stream->mki_size);
    }

    /*
     * check sequence number for overruns, and copy it into the packet
     * if its value isn't too big
     */
    status = srtp_rdb_increment(&stream->rtcp_rdb);
    if (status) {
        return status;
    }
    seq_num = srtp_rdb_get_value(&stream->rtcp_rdb);
    trailer |= htonl(seq_num);
    debug_print(mod_srtp, "srtcp index: %x", (unsigned int)seq_num);

    memcpy(trailer_p, &trailer, sizeof(trailer));

    /*
     * Calculate and set the IV
     */
    status = srtp_calc_aead_iv_srtcp(session_keys, &iv, seq_num, hdr);
    if (status) {
        return srtp_err_status_cipher_fail;
    }
    status = srtp_cipher_set_iv(session_keys->rtcp_cipher, (uint8_t *)&iv,
                                srtp_direction_encrypt);
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /*
     * Set the AAD for GCM mode
     */
    if (stream->rtcp_services & sec_serv_conf) {
        /*
         * If payload encryption is enabled, then the AAD consist of
         * the RTCP header and the seq# at the end of the packet
         */
        status = srtp_cipher_set_aad(session_keys->rtcp_cipher, rtcp,
                                     octets_in_rtcp_header);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    } else {
        /*
         * Since payload encryption is not enabled, we must authenticate
         * the entire packet as described in RFC 7714 (Section 9.3. Data
         * Types in Unencrypted SRTCP Compound Packets)
         */
        status = srtp_cipher_set_aad(session_keys->rtcp_cipher, rtcp, rtcp_len);
        if (status) {
            return (srtp_err_status_cipher_fail);
        }
    }
    /*
     * Process the sequence# as AAD
     */
    status = srtp_cipher_set_aad(session_keys->rtcp_cipher, (uint8_t *)&trailer,
                                 sizeof(trailer));
    if (status) {
        return (srtp_err_status_cipher_fail);
    }

    /* if we're encrypting, exor keystream into the message */
    if (stream->rtcp_services & sec_serv_conf) {
        size_t out_len = *srtcp_len - enc_start;
        status =
            srtp_cipher_encrypt(session_keys->rtcp_cipher, rtcp + enc_start,
                                enc_octet_len, srtcp + enc_start, &out_len);
        enc_octet_len = out_len;
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    } else {
        /* if no encryption and not-inplace then need to copy rest of packet */
        if (rtcp != srtcp) {
            memcpy(srtcp + enc_start, rtcp + enc_start, enc_octet_len);
        }

        /*
         * Even though we're not encrypting the payload, we need
         * to run the cipher to get the auth tag.
         */
        uint8_t *auth_tag = srtcp + enc_start + enc_octet_len;
        size_t out_len = *srtcp_len - enc_start - enc_octet_len;
        status = srtp_cipher_encrypt(session_keys->rtcp_cipher, NULL, 0,
                                     auth_tag, &out_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
        enc_octet_len += out_len;
    }

    *srtcp_len = octets_in_rtcp_header + enc_octet_len;

    /* increase the packet length by the length of the seq_num*/
    *srtcp_len += sizeof(srtcp_trailer_t);

    /* increase the packet by the mki_size */
    *srtcp_len += stream->mki_size;

    return srtp_err_status_ok;
}

/*
 * This function handles incoming SRTCP packets while in AEAD mode,
 * which currently supports AES-GCM encryption.  Note, the auth tag is
 * at the end of the packet stream and is automatically checked by GCM
 * when decrypting the payload.
 */
static srtp_err_status_t srtp_unprotect_rtcp_aead(
    srtp_t ctx,
    srtp_stream_ctx_t *stream,
    const uint8_t *srtcp,
    size_t srtcp_len,
    uint8_t *rtcp,
    size_t *rtcp_len,
    srtp_session_keys_t *session_keys)
{
    const srtcp_hdr_t *hdr = (const srtcp_hdr_t *)srtcp;
    size_t enc_start;               /* pointer to start of encrypted portion  */
    const uint8_t *trailer_p;       /* pointer to start of trailer            */
    uint32_t trailer;               /* trailer value                          */
    size_t enc_octet_len = 0;       /* number of octets in encrypted portion  */
    const uint8_t *auth_tag = NULL; /* location of auth_tag within packet     */
    srtp_err_status_t status;
    size_t tag_len;
    size_t tmp_len;
    uint32_t seq_num;
    v128_t iv;

    /* get tag length from stream context */
    tag_len = srtp_auth_get_tag_length(session_keys->rtcp_auth);

    enc_start = octets_in_rtcp_header;

    /*
     * set encryption start, encryption length, and trailer
     */
    /* index & E (encryption) bit follow normal data. hdr->len is the number of
     * words (32-bit) in the normal packet minus 1
     */
    /* This should point trailer to the word past the end of the normal data. */
    /* This would need to be modified for optional mikey data */
    trailer_p = srtcp + srtcp_len - sizeof(srtcp_trailer_t) - stream->mki_size;
    memcpy(&trailer, trailer_p, sizeof(trailer));

    /*
     * We pass the tag down to the cipher when doing GCM mode
     */
    enc_octet_len = srtcp_len - (octets_in_rtcp_header +
                                 sizeof(srtcp_trailer_t) + stream->mki_size);
    auth_tag = srtcp + (srtcp_len - tag_len - stream->mki_size -
                        sizeof(srtcp_trailer_t));

    /*
     * check the sequence number for replays
     */
    /* this is easier than dealing with bitfield access */
    seq_num = ntohl(trailer) & SRTCP_INDEX_MASK;
    debug_print(mod_srtp, "srtcp index: %x", (unsigned int)seq_num);
    status = srtp_rdb_check(&stream->rtcp_rdb, seq_num);
    if (status) {
        return status;
    }

    /*
     * Calculate and set the IV
     */
    status = srtp_calc_aead_iv_srtcp(session_keys, &iv, seq_num, hdr);
    if (status) {
        return srtp_err_status_cipher_fail;
    }
    status = srtp_cipher_set_iv(session_keys->rtcp_cipher, (uint8_t *)&iv,
                                srtp_direction_decrypt);
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /* check output length */
    if (*rtcp_len <
        srtcp_len - sizeof(srtcp_trailer_t) - stream->mki_size - tag_len) {
        return srtp_err_status_buffer_small;
    }

    /* if not inplace need to copy rtcp header */
    if (srtcp != rtcp) {
        memcpy(rtcp, srtcp, enc_start);
    }

    /*
     * Set the AAD for GCM mode
     */
    if (*trailer_p & SRTCP_E_BYTE_BIT) {
        /*
         * If payload encryption is enabled, then the AAD consist of
         * the RTCP header and the seq# at the end of the packet
         */
        status = srtp_cipher_set_aad(session_keys->rtcp_cipher, srtcp,
                                     octets_in_rtcp_header);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    } else {
        /*
         * Since payload encryption is not enabled, we must authenticate
         * the entire packet as described in RFC 7714 (Section 9.3. Data
         * Types in Unencrypted SRTCP Compound Packets)
         */
        status = srtp_cipher_set_aad(
            session_keys->rtcp_cipher, srtcp,
            (srtcp_len - tag_len - sizeof(srtcp_trailer_t) - stream->mki_size));
        if (status) {
            return (srtp_err_status_cipher_fail);
        }
    }

    /*
     * Process the sequence# as AAD
     */
    status = srtp_cipher_set_aad(session_keys->rtcp_cipher, (uint8_t *)&trailer,
                                 sizeof(trailer));
    if (status) {
        return (srtp_err_status_cipher_fail);
    }

    /* if we're decrypting, exor keystream into the message */
    if (*trailer_p & SRTCP_E_BYTE_BIT) {
        status = srtp_cipher_decrypt(session_keys->rtcp_cipher,
                                     srtcp + enc_start, enc_octet_len,
                                     rtcp + enc_start, &enc_octet_len);
        if (status) {
            return status;
        }
    } else {
        /* if no encryption and not-inplace then need to copy rest of packet */
        if (rtcp != srtcp) {
            memcpy(rtcp + enc_start, srtcp + enc_start, enc_octet_len);
        }

        /*
         * Still need to run the cipher to check the tag
         */
        tmp_len = 0;
        status = srtp_cipher_decrypt(session_keys->rtcp_cipher, auth_tag,
                                     tag_len, NULL, &tmp_len);
        if (status) {
            return status;
        }
    }

    *rtcp_len = srtcp_len;

    /* decrease the packet length by the length of the auth tag and seq_num*/
    *rtcp_len -= (tag_len + sizeof(srtcp_trailer_t) + stream->mki_size);

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
        status =
            srtp_stream_clone(ctx->stream_template, hdr->ssrc, &new_stream);
        if (status) {
            return status;
        }

        /* add new stream to the list */
        status = srtp_insert_or_dealloc_stream(ctx->stream_list, new_stream,
                                               ctx->stream_template);
        if (status) {
            return status;
        }

        /* set stream (the pointer used in this function) */
        stream = new_stream;
    }

    /* we've passed the authentication check, so add seq_num to the rdb */
    srtp_rdb_add_index(&stream->rtcp_rdb, seq_num);

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_protect_rtcp(srtp_t ctx,
                                    const uint8_t *rtcp,
                                    size_t rtcp_len,
                                    uint8_t *srtcp,
                                    size_t *srtcp_len,
                                    size_t mki_index)
{
    const srtcp_hdr_t *hdr = (const srtcp_hdr_t *)rtcp;
    size_t enc_start;         /* pointer to start of encrypted portion  */
    uint8_t *auth_start;      /* pointer to start of auth. portion      */
    uint8_t *trailer_p;       /* pointer to start of trailer            */
    uint32_t trailer;         /* trailer value                          */
    size_t enc_octet_len = 0; /* number of octets in encrypted portion  */
    uint8_t *auth_tag = NULL; /* location of auth_tag within packet     */
    srtp_err_status_t status;
    size_t tag_len;
    srtp_stream_ctx_t *stream;
    size_t prefix_len;
    uint32_t seq_num;
    srtp_session_keys_t *session_keys = NULL;

    /* check the packet length - it must at least contain a full header */
    if (rtcp_len < octets_in_rtcp_header) {
        return srtp_err_status_bad_param;
    }

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
            status =
                srtp_stream_clone(ctx->stream_template, hdr->ssrc, &new_stream);
            if (status) {
                return status;
            }

            /* add new stream to the list */
            status = srtp_insert_or_dealloc_stream(ctx->stream_list, new_stream,
                                                   ctx->stream_template);
            if (status) {
                return status;
            }

            /* set stream (the pointer used in this function) */
            stream = new_stream;
        } else {
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
        } else {
            srtp_handle_event(ctx, stream, event_ssrc_collision);
        }
    }

    status = srtp_get_session_keys(stream, mki_index, &session_keys);
    if (status) {
        return status;
    }

    /*
     * Check if this is an AEAD stream (GCM mode).  If so, then dispatch
     * the request to our AEAD handler.
     */
    if (session_keys->rtp_cipher->algorithm == SRTP_AES_GCM_128 ||
        session_keys->rtp_cipher->algorithm == SRTP_AES_GCM_256) {
        return srtp_protect_rtcp_aead(stream, rtcp, rtcp_len, srtcp, srtcp_len,
                                      session_keys);
    }

    /* get tag length from stream context */
    tag_len = srtp_auth_get_tag_length(session_keys->rtcp_auth);

    /*
     * set encryption start and encryption length
     */
    enc_start = octets_in_rtcp_header;
    enc_octet_len = rtcp_len - enc_start;

    /* check output length */
    if (*srtcp_len <
        rtcp_len + sizeof(srtcp_trailer_t) + stream->mki_size + tag_len) {
        return srtp_err_status_buffer_small;
    }

    /* if not in place then need to copy rtcp header */
    if (rtcp != srtcp) {
        memcpy(srtcp, rtcp, enc_start);
    }

    /* all of the packet, except the header, gets encrypted */
    /*
     * NOTE: hdr->length is not usable - it refers to only the first RTCP report
     * in the compound packet!
     */
    trailer_p = srtcp + enc_start + enc_octet_len;

    if (stream->rtcp_services & sec_serv_conf) {
        trailer = htonl(SRTCP_E_BIT); /* set encrypt bit */
    } else {
        /* 0 is network-order independant */
        trailer = 0x00000000; /* set encrypt bit */
    }

    if (stream->use_mki) {
        srtp_inject_mki(srtcp + rtcp_len + sizeof(srtcp_trailer_t),
                        session_keys, stream->mki_size);
    }

    /*
     * set the auth_start and auth_tag pointers to the proper locations
     * (note that srtpc *always* provides authentication, unlike srtp)
     */
    /* Note: This would need to change for optional mikey data */
    auth_start = srtcp;
    auth_tag = srtcp + rtcp_len + sizeof(srtcp_trailer_t) + stream->mki_size;

    /*
     * check sequence number for overruns, and copy it into the packet
     * if its value isn't too big
     */
    status = srtp_rdb_increment(&stream->rtcp_rdb);
    if (status) {
        return status;
    }
    seq_num = srtp_rdb_get_value(&stream->rtcp_rdb);
    trailer |= htonl(seq_num);
    debug_print(mod_srtp, "srtcp index: %x", (unsigned int)seq_num);

    memcpy(trailer_p, &trailer, sizeof(trailer));

    /*
     * if we're using rindael counter mode, set nonce and seq
     */
    if (session_keys->rtcp_cipher->type->id == SRTP_AES_ICM_128 ||
        session_keys->rtcp_cipher->type->id == SRTP_AES_ICM_192 ||
        session_keys->rtcp_cipher->type->id == SRTP_AES_ICM_256) {
        v128_t iv;

        iv.v32[0] = 0;
        iv.v32[1] = hdr->ssrc; /* still in network order! */
        iv.v32[2] = htonl(seq_num >> 16);
        iv.v32[3] = htonl(seq_num << 16);
        status = srtp_cipher_set_iv(session_keys->rtcp_cipher, (uint8_t *)&iv,
                                    srtp_direction_encrypt);

    } else {
        v128_t iv;

        /* otherwise, just set the index to seq_num */
        iv.v32[0] = 0;
        iv.v32[1] = 0;
        iv.v32[2] = 0;
        iv.v32[3] = htonl(seq_num);
        status = srtp_cipher_set_iv(session_keys->rtcp_cipher, (uint8_t *)&iv,
                                    srtp_direction_encrypt);
    }
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /*
     * if we're authenticating using a universal hash, put the keystream
     * prefix into the authentication tag
     */

    /* if auth_start is non-null, then put keystream into tag  */
    if (auth_start) {
        /* put keystream prefix into auth_tag */
        prefix_len = srtp_auth_get_prefix_length(session_keys->rtcp_auth);
        status = srtp_cipher_output(session_keys->rtcp_cipher, auth_tag,
                                    &prefix_len);

        debug_print(mod_srtp, "keystream prefix: %s",
                    srtp_octet_string_hex_string(auth_tag, prefix_len));

        if (status) {
            return srtp_err_status_cipher_fail;
        }
    }

    /* if we're encrypting, exor keystream into the message */
    if (stream->rtcp_services & sec_serv_conf) {
        status = srtp_cipher_encrypt(session_keys->rtcp_cipher,
                                     rtcp + enc_start, enc_octet_len,
                                     srtcp + enc_start, &enc_octet_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    } else if (rtcp != srtcp) {
        /* if no encryption and not-inplace then need to copy rest of packet */
        memcpy(srtcp + enc_start, rtcp + enc_start, enc_octet_len);
    }

    /* initialize auth func context */
    status = srtp_auth_start(session_keys->rtcp_auth);
    if (status) {
        return status;
    }

    /*
     * run auth func over packet (including trailer), and write the
     * result at auth_tag
     */
    status = srtp_auth_compute(session_keys->rtcp_auth, auth_start,
                               rtcp_len + sizeof(srtcp_trailer_t), auth_tag);
    debug_print(mod_srtp, "srtcp auth tag:    %s",
                srtp_octet_string_hex_string(auth_tag, tag_len));
    if (status) {
        return srtp_err_status_auth_fail;
    }

    *srtcp_len = enc_start + enc_octet_len;

    /* increase the packet length by the length of the auth tag and seq_num*/
    *srtcp_len += (tag_len + sizeof(srtcp_trailer_t));

    /* increase the packet by the mki_size */
    *srtcp_len += stream->mki_size;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_unprotect_rtcp(srtp_t ctx,
                                      const uint8_t *srtcp,
                                      size_t srtcp_len,
                                      uint8_t *rtcp,
                                      size_t *rtcp_len)
{
    const srtcp_hdr_t *hdr = (const srtcp_hdr_t *)srtcp;
    size_t enc_start;               /* pointer to start of encrypted portion  */
    const uint8_t *auth_start;      /* pointer to start of auth. portion      */
    const uint8_t *trailer_p;       /* pointer to start of trailer            */
    uint32_t trailer;               /* trailer value                          */
    size_t enc_octet_len = 0;       /* number of octets in encrypted portion  */
    const uint8_t *auth_tag = NULL; /* location of auth_tag within packet     */
    uint8_t tmp_tag[SRTP_MAX_TAG_LEN];
    srtp_err_status_t status;
    size_t auth_len;
    size_t tag_len;
    srtp_stream_ctx_t *stream;
    size_t prefix_len;
    uint32_t seq_num;
    bool e_bit_in_packet;          /* E-bit was found in the packet */
    bool sec_serv_confidentiality; /* whether confidentiality was requested */
    srtp_session_keys_t *session_keys = NULL;

    /*
     * check that the length value is sane; we'll check again once we
     * know the tag length, but we at least want to know that it is
     * a positive value
     */
    if (srtcp_len < octets_in_rtcp_header + sizeof(srtcp_trailer_t)) {
        return srtp_err_status_bad_param;
    }

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
            stream = ctx->stream_template;

            debug_print(mod_srtp,
                        "srtcp using provisional stream (SSRC: 0x%08x)",
                        (unsigned int)ntohl(hdr->ssrc));
        } else {
            /* no template stream, so we return an error */
            return srtp_err_status_no_ctx;
        }
    }

    /*
     * Determine if MKI is being used and what session keys should be used
     */
    status = srtp_get_session_keys_for_rtcp_packet(stream, srtcp, srtcp_len,
                                                   &session_keys);
    if (status) {
        return status;
    }

    /* get tag length from stream context */
    tag_len = srtp_auth_get_tag_length(session_keys->rtcp_auth);

    /* check the packet length - it must contain at least a full RTCP
       header, an auth tag (if applicable), and the SRTCP encrypted flag
       and 31-bit index value */
    if (srtcp_len < octets_in_rtcp_header + sizeof(srtcp_trailer_t) +
                        stream->mki_size + tag_len) {
        return srtp_err_status_bad_param;
    }

    /*
     * Check if this is an AEAD stream (GCM mode).  If so, then dispatch
     * the request to our AEAD handler.
     */
    if (session_keys->rtp_cipher->algorithm == SRTP_AES_GCM_128 ||
        session_keys->rtp_cipher->algorithm == SRTP_AES_GCM_256) {
        return srtp_unprotect_rtcp_aead(ctx, stream, srtcp, srtcp_len, rtcp,
                                        rtcp_len, session_keys);
    }

    sec_serv_confidentiality = stream->rtcp_services == sec_serv_conf ||
                               stream->rtcp_services == sec_serv_conf_and_auth;

    /*
     * set encryption start, encryption length, and trailer
     */
    enc_start = octets_in_rtcp_header;
    enc_octet_len = srtcp_len - (octets_in_rtcp_header + tag_len +
                                 stream->mki_size + sizeof(srtcp_trailer_t));
    /*
     *index & E (encryption) bit follow normal data. hdr->len is the number of
     * words (32-bit) in the normal packet minus 1
     */
    /* This should point trailer to the word past the end of the normal data. */
    /* This would need to be modified for optional mikey data */
    trailer_p = srtcp + srtcp_len -
                (tag_len + stream->mki_size + sizeof(srtcp_trailer_t));
    memcpy(&trailer, trailer_p, sizeof(trailer));

    e_bit_in_packet = (*trailer_p & SRTCP_E_BYTE_BIT) == SRTCP_E_BYTE_BIT;
    if (e_bit_in_packet != sec_serv_confidentiality) {
        return srtp_err_status_cant_check;
    }

    /*
     * set the auth_start and auth_tag pointers to the proper locations
     * (note that srtcp *always* uses authentication, unlike srtp)
     */
    auth_start = srtcp;

    /*
     * The location of the auth tag in the packet needs to know MKI
     * could be present.  The data needed to calculate the Auth tag
     * must not include the MKI
     */
    auth_len = srtcp_len - tag_len - stream->mki_size;
    auth_tag = srtcp + auth_len + stream->mki_size;

    /*
     * check the sequence number for replays
     */
    /* this is easier than dealing with bitfield access */
    seq_num = ntohl(trailer) & SRTCP_INDEX_MASK;
    debug_print(mod_srtp, "srtcp index: %x", (unsigned int)seq_num);
    status = srtp_rdb_check(&stream->rtcp_rdb, seq_num);
    if (status) {
        return status;
    }

    /*
     * if we're using aes counter mode, set nonce and seq
     */
    if (session_keys->rtcp_cipher->type->id == SRTP_AES_ICM_128 ||
        session_keys->rtcp_cipher->type->id == SRTP_AES_ICM_192 ||
        session_keys->rtcp_cipher->type->id == SRTP_AES_ICM_256) {
        v128_t iv;

        iv.v32[0] = 0;
        iv.v32[1] = hdr->ssrc; /* still in network order! */
        iv.v32[2] = htonl(seq_num >> 16);
        iv.v32[3] = htonl(seq_num << 16);
        status = srtp_cipher_set_iv(session_keys->rtcp_cipher, (uint8_t *)&iv,
                                    srtp_direction_decrypt);

    } else {
        v128_t iv;

        /* otherwise, just set the index to seq_num */
        iv.v32[0] = 0;
        iv.v32[1] = 0;
        iv.v32[2] = 0;
        iv.v32[3] = htonl(seq_num);
        status = srtp_cipher_set_iv(session_keys->rtcp_cipher, (uint8_t *)&iv,
                                    srtp_direction_decrypt);
    }
    if (status) {
        return srtp_err_status_cipher_fail;
    }

    /*
     * if we're authenticating using a universal hash, put the keystream
     * prefix into the authentication tag
     */
    prefix_len = srtp_auth_get_prefix_length(session_keys->rtcp_auth);
    if (prefix_len) {
        status =
            srtp_cipher_output(session_keys->rtcp_cipher, tmp_tag, &prefix_len);
        debug_print(mod_srtp, "keystream prefix: %s",
                    srtp_octet_string_hex_string(tmp_tag, prefix_len));
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    }

    /* initialize auth func context */
    status = srtp_auth_start(session_keys->rtcp_auth);
    if (status) {
        return status;
    }

    /* run auth func over packet, put result into tmp_tag */
    status = srtp_auth_compute(session_keys->rtcp_auth, auth_start, auth_len,
                               tmp_tag);
    debug_print(mod_srtp, "srtcp computed tag:       %s",
                srtp_octet_string_hex_string(tmp_tag, tag_len));
    if (status) {
        return srtp_err_status_auth_fail;
    }

    /* compare the tag just computed with the one in the packet */
    debug_print(mod_srtp, "srtcp tag from packet:    %s",
                srtp_octet_string_hex_string(auth_tag, tag_len));
    if (!srtp_octet_string_equal(tmp_tag, auth_tag, tag_len)) {
        return srtp_err_status_auth_fail;
    }

    /* check output length */
    if (*rtcp_len <
        srtcp_len - sizeof(srtcp_trailer_t) - stream->mki_size - tag_len) {
        return srtp_err_status_buffer_small;
    }

    /* if not inplace need to copy rtcp header */
    if (srtcp != rtcp) {
        memcpy(rtcp, srtcp, enc_start);
    }

    /* if we're decrypting, exor keystream into the message */
    if (sec_serv_confidentiality) {
        status = srtp_cipher_decrypt(session_keys->rtcp_cipher,
                                     srtcp + enc_start, enc_octet_len,
                                     rtcp + enc_start, &enc_octet_len);
        if (status) {
            return srtp_err_status_cipher_fail;
        }
    } else if (srtcp != rtcp) {
        /* if no encryption and not-inplace then need to copy rest of packet */
        memcpy(rtcp + enc_start, srtcp + enc_start, enc_octet_len);
    }

    *rtcp_len = srtcp_len;

    /* decrease the packet length by the length of the auth tag and seq_num */
    *rtcp_len -= (tag_len + sizeof(srtcp_trailer_t));

    /* decrease the packet length by the length of the mki_size */
    *rtcp_len -= stream->mki_size;

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
        status =
            srtp_stream_clone(ctx->stream_template, hdr->ssrc, &new_stream);
        if (status) {
            return status;
        }

        /* add new stream to the list */
        status = srtp_insert_or_dealloc_stream(ctx->stream_list, new_stream,
                                               ctx->stream_template);
        if (status) {
            return status;
        }

        /* set stream (the pointer used in this function) */
        stream = new_stream;
    }

    /* we've passed the authentication check, so add seq_num to the rdb */
    srtp_rdb_add_index(&stream->rtcp_rdb, seq_num);

    return srtp_err_status_ok;
}

/*
 * user data within srtp_t context
 */

void srtp_set_user_data(srtp_t ctx, void *data)
{
    ctx->user_data = data;
}

void *srtp_get_user_data(srtp_t ctx)
{
    return ctx->user_data;
}

srtp_err_status_t srtp_crypto_policy_set_from_profile_for_rtp(
    srtp_crypto_policy_t *policy,
    srtp_profile_t profile)
{
    /* set SRTP policy from the SRTP profile in the key set */
    switch (profile) {
    case srtp_profile_aes128_cm_sha1_80:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(policy);
        break;
    case srtp_profile_aes128_cm_sha1_32:
        srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(policy);
        break;
    case srtp_profile_null_sha1_80:
        srtp_crypto_policy_set_null_cipher_hmac_sha1_80(policy);
        break;
#ifdef GCM
    case srtp_profile_aead_aes_128_gcm:
        srtp_crypto_policy_set_aes_gcm_128_16_auth(policy);
        break;
    case srtp_profile_aead_aes_256_gcm:
        srtp_crypto_policy_set_aes_gcm_256_16_auth(policy);
        break;
#endif
    /* the following profiles are not (yet) supported */
    case srtp_profile_null_sha1_32:
    default:
        return srtp_err_status_bad_param;
    }

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_crypto_policy_set_from_profile_for_rtcp(
    srtp_crypto_policy_t *policy,
    srtp_profile_t profile)
{
    /* set SRTP policy from the SRTP profile in the key set */
    switch (profile) {
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
#ifdef GCM
    case srtp_profile_aead_aes_128_gcm:
        srtp_crypto_policy_set_aes_gcm_128_16_auth(policy);
        break;
    case srtp_profile_aead_aes_256_gcm:
        srtp_crypto_policy_set_aes_gcm_256_16_auth(policy);
        break;
#endif
    /* the following profiles are not (yet) supported */
    case srtp_profile_null_sha1_32:
    default:
        return srtp_err_status_bad_param;
    }

    return srtp_err_status_ok;
}

void srtp_append_salt_to_key(uint8_t *key,
                             size_t bytes_in_key,
                             uint8_t *salt,
                             size_t bytes_in_salt)
{
    memcpy(key + bytes_in_key, salt, bytes_in_salt);
}

size_t srtp_profile_get_master_key_length(srtp_profile_t profile)
{
    switch (profile) {
    case srtp_profile_aes128_cm_sha1_80:
        return SRTP_AES_128_KEY_LEN;
        break;
    case srtp_profile_aes128_cm_sha1_32:
        return SRTP_AES_128_KEY_LEN;
        break;
    case srtp_profile_null_sha1_80:
        return SRTP_AES_128_KEY_LEN;
        break;
    case srtp_profile_aead_aes_128_gcm:
        return SRTP_AES_128_KEY_LEN;
        break;
    case srtp_profile_aead_aes_256_gcm:
        return SRTP_AES_256_KEY_LEN;
        break;
    /* the following profiles are not (yet) supported */
    case srtp_profile_null_sha1_32:
    default:
        return 0; /* indicate error by returning a zero */
    }
}

size_t srtp_profile_get_master_salt_length(srtp_profile_t profile)
{
    switch (profile) {
    case srtp_profile_aes128_cm_sha1_80:
        return SRTP_SALT_LEN;
        break;
    case srtp_profile_aes128_cm_sha1_32:
        return SRTP_SALT_LEN;
        break;
    case srtp_profile_null_sha1_80:
        return SRTP_SALT_LEN;
        break;
    case srtp_profile_aead_aes_128_gcm:
        return SRTP_AEAD_SALT_LEN;
        break;
    case srtp_profile_aead_aes_256_gcm:
        return SRTP_AEAD_SALT_LEN;
        break;
    /* the following profiles are not (yet) supported */
    case srtp_profile_null_sha1_32:
    default:
        return 0; /* indicate error by returning a zero */
    }
}

srtp_err_status_t stream_get_protect_trailer_length(srtp_stream_ctx_t *stream,
                                                    bool is_rtp,
                                                    size_t mki_index,
                                                    size_t *length)
{
    srtp_session_keys_t *session_key;

    *length = 0;

    if (stream->use_mki) {
        if (mki_index >= stream->num_master_keys) {
            return srtp_err_status_bad_mki;
        }
        session_key = &stream->session_keys[mki_index];

        *length += stream->mki_size;

    } else {
        session_key = &stream->session_keys[0];
    }
    if (is_rtp) {
        *length += srtp_auth_get_tag_length(session_key->rtp_auth);
    } else {
        *length += srtp_auth_get_tag_length(session_key->rtcp_auth);
        *length += sizeof(srtcp_trailer_t);
    }

    return srtp_err_status_ok;
}

struct get_protect_trailer_length_data {
    bool found_stream; /* whether at least one matching stream was found */
    size_t length;     /* maximum trailer length found so far */
    bool is_rtp;
    size_t mki_index;
};

static bool get_protect_trailer_length_cb(srtp_stream_t stream, void *raw_data)
{
    struct get_protect_trailer_length_data *data =
        (struct get_protect_trailer_length_data *)raw_data;
    size_t temp_length;

    if (stream_get_protect_trailer_length(stream, data->is_rtp, data->mki_index,
                                          &temp_length) == srtp_err_status_ok) {
        data->found_stream = true;
        if (temp_length > data->length) {
            data->length = temp_length;
        }
    }

    return true;
}

srtp_err_status_t get_protect_trailer_length(srtp_t session,
                                             bool is_rtp,
                                             size_t mki_index,
                                             size_t *length)
{
    srtp_stream_ctx_t *stream;
    struct get_protect_trailer_length_data data = { false, 0, is_rtp,
                                                    mki_index };

    if (session == NULL) {
        return srtp_err_status_bad_param;
    }

    stream = session->stream_template;

    if (stream != NULL) {
        data.found_stream = true;
        stream_get_protect_trailer_length(stream, is_rtp, mki_index,
                                          &data.length);
    }

    srtp_stream_list_for_each(session->stream_list,
                              get_protect_trailer_length_cb, &data);

    if (!data.found_stream) {
        return srtp_err_status_bad_param;
    }

    *length = data.length;
    return srtp_err_status_ok;
}

srtp_err_status_t srtp_get_protect_trailer_length(srtp_t session,
                                                  size_t mki_index,
                                                  size_t *length)
{
    return get_protect_trailer_length(session, true, mki_index, length);
}

srtp_err_status_t srtp_get_protect_rtcp_trailer_length(srtp_t session,
                                                       size_t mki_index,
                                                       size_t *length)
{
    return get_protect_trailer_length(session, false, mki_index, length);
}

/*
 * SRTP debug interface
 */
srtp_err_status_t srtp_set_debug_module(const char *mod_name, bool v)
{
    return srtp_crypto_kernel_set_debug_module(mod_name, v);
}

srtp_err_status_t srtp_list_debug_modules(void)
{
    return srtp_crypto_kernel_list_debug_modules();
}

/*
 * srtp_log_handler is a global variable holding a pointer to the
 * log handler function; this function is called for any log
 * output.
 */

static srtp_log_handler_func_t *srtp_log_handler = NULL;
static void *srtp_log_handler_data = NULL;

static void srtp_err_handler(srtp_err_reporting_level_t level, const char *msg)
{
    if (srtp_log_handler) {
        srtp_log_level_t log_level = srtp_log_level_error;
        switch (level) {
        case srtp_err_level_error:
            log_level = srtp_log_level_error;
            break;
        case srtp_err_level_warning:
            log_level = srtp_log_level_warning;
            break;
        case srtp_err_level_info:
            log_level = srtp_log_level_info;
            break;
        case srtp_err_level_debug:
            log_level = srtp_log_level_debug;
            break;
        }

        srtp_log_handler(log_level, msg, srtp_log_handler_data);
    }
}

srtp_err_status_t srtp_install_log_handler(srtp_log_handler_func_t func,
                                           void *data)
{
    /*
     * note that we accept NULL arguments intentionally - calling this
     * function with a NULL arguments removes a log handler that's
     * been previously installed
     */

    if (srtp_log_handler) {
        srtp_install_err_report_handler(NULL);
    }
    srtp_log_handler = func;
    srtp_log_handler_data = data;
    if (srtp_log_handler) {
        srtp_install_err_report_handler(srtp_err_handler);
    }
    return srtp_err_status_ok;
}

srtp_err_status_t srtp_stream_set_roc(srtp_t session,
                                      uint32_t ssrc,
                                      uint32_t roc)
{
    srtp_stream_t stream;

    stream = srtp_get_stream(session, htonl(ssrc));
    if (stream == NULL) {
        return srtp_err_status_bad_param;
    }

    stream->pending_roc = roc;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_stream_get_roc(srtp_t session,
                                      uint32_t ssrc,
                                      uint32_t *roc)
{
    srtp_stream_t stream;

    stream = srtp_get_stream(session, htonl(ssrc));
    if (stream == NULL) {
        return srtp_err_status_bad_param;
    }

    *roc = srtp_rdbx_get_roc(&stream->rtp_rdbx);

    return srtp_err_status_ok;
}

#ifndef SRTP_NO_STREAM_LIST

#define INITIAL_STREAM_INDEX_SIZE 2

typedef struct list_entry {
    uint32_t ssrc;
    srtp_stream_t stream;
} list_entry;

typedef struct srtp_stream_list_ctx_t_ {
    list_entry *entries;
    size_t capacity;
    size_t size;
} srtp_stream_list_ctx_t_;

srtp_err_status_t srtp_stream_list_alloc(srtp_stream_list_t *list_ptr)
{
    srtp_stream_list_t list =
        srtp_crypto_alloc(sizeof(srtp_stream_list_ctx_t_));
    if (list == NULL) {
        return srtp_err_status_alloc_fail;
    }

    list->entries =
        srtp_crypto_alloc(sizeof(list_entry) * INITIAL_STREAM_INDEX_SIZE);
    if (list->entries == NULL) {
        srtp_crypto_free(list);
        return srtp_err_status_alloc_fail;
    }

    list->capacity = INITIAL_STREAM_INDEX_SIZE;
    list->size = 0;

    *list_ptr = list;

    return srtp_err_status_ok;
}

srtp_err_status_t srtp_stream_list_dealloc(srtp_stream_list_t list)
{
    /* list must be empty */
    if (list->size != 0) {
        return srtp_err_status_fail;
    }

    srtp_crypto_free(list->entries);
    srtp_crypto_free(list);

    return srtp_err_status_ok;
}

/*
 * inserting a new entry in the list may require reallocating memory in order
 * to keep all the items in a contiguous memory block.
 */
srtp_err_status_t srtp_stream_list_insert(srtp_stream_list_t list,
                                          srtp_stream_t stream)
{
    /*
     * there is no space to hold the new entry in the entries buffer,
     * double the size of the buffer.
     */
    if (list->size == list->capacity) {
        size_t new_capacity = list->capacity * 2;

        // Check for capacity overflow.
        if (new_capacity < list->capacity ||
            new_capacity > SIZE_MAX / sizeof(list_entry)) {
            return srtp_err_status_alloc_fail;
        }

        list_entry *new_entries =
            srtp_crypto_alloc(sizeof(list_entry) * new_capacity);
        if (new_entries == NULL) {
            return srtp_err_status_alloc_fail;
        }

        // Copy previous entries into the new buffer.
        memcpy(new_entries, list->entries, sizeof(list_entry) * list->capacity);

        // Release previous entries.
        srtp_crypto_free(list->entries);

        // Assign new entries to the list.
        list->entries = new_entries;

        // Update list capacity.
        list->capacity = new_capacity;
    }

    // fill the first available entry
    size_t next_index = list->size;
    list->entries[next_index].ssrc = stream->ssrc;
    list->entries[next_index].stream = stream;

    // update size value
    list->size++;

    return srtp_err_status_ok;
}

/*
 * removing an entry from the list performs a memory move of the following
 * entries one position back in order to keep all the entries in the buffer
 * contiguous.
 */
void srtp_stream_list_remove(srtp_stream_list_t list,
                             srtp_stream_t stream_to_remove)
{
    size_t end = list->size;

    for (size_t i = 0; i < end; i++) {
        if (list->entries[i].ssrc == stream_to_remove->ssrc) {
            size_t entries_to_move = list->size - i - 1;
            memmove(&list->entries[i], &list->entries[i + 1],
                    sizeof(list_entry) * entries_to_move);
            list->size--;

            break;
        }
    }
}

srtp_stream_t srtp_stream_list_get(srtp_stream_list_t list, uint32_t ssrc)
{
    size_t end = list->size;

    list_entry *entries = list->entries;

    for (size_t i = 0; i < end; i++) {
        if (entries[i].ssrc == ssrc) {
            return entries[i].stream;
        }
    }

    return NULL;
}

void srtp_stream_list_for_each(srtp_stream_list_t list,
                               bool (*callback)(srtp_stream_t, void *),
                               void *data)
{
    list_entry *entries = list->entries;

    size_t size = list->size;

    /*
     * the second statement of the expression needs to be recalculated on each
     * iteration as the available number of entries may change within the given
     * callback.
     * Ie: in case the callback calls srtp_stream_list_remove().
     */
    for (size_t i = 0; i < list->size;) {
        if (!callback(entries[i].stream, data)) {
            break;
        }

        // the entry was not removed, increase the counter.
        if (size == list->size) {
            ++i;
        }

        size = list->size;
    }
}

#endif
