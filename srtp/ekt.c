/*
 * ekt.c
 *
 * Encrypted Key Transport for SRTP
 * 
 * David McGrew
 * Cisco Systems, Inc.
 *
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


#include "srtp.h"
#include "srtp_priv.h"
#include "err.h"
#include "ekt.h"
#include "rdbx.h"
#include "ekt_tag_utils.h"

extern srtp_debug_module_t mod_srtp;

inline int
srtp_get_ekt_cipher_key_length(srtp_ekt_cipher_t ekt_cipher)
{
    int key_len;

    /* The key length depends on the EKT cipher employed */
    switch (ekt_cipher)
    {
    case ekt_cipher_aeskw_128:
        key_len = 16;
        break;
    case ekt_cipher_aeskw_192:
        key_len = 24;
        break;
    case ekt_cipher_aeskw_256:
        key_len = 32;
        break;
    default:
        key_len = 0;
        break;
    }

    return key_len;
}

srtp_err_status_t ekt_get_spi_info(srtp_ctx_t_ *ctx, srtp_ekt_spi_t spi, srtp_ekt_spi_info_t **spi_info)
{
    srtp_ekt_spi_info_t *pSpiInfo;

    pSpiInfo = ctx->spi_info;

    while (pSpiInfo != NULL)
    {
        if (pSpiInfo->spi == spi)
        {
            *spi_info = pSpiInfo;
            return srtp_err_status_ok;

        }
        pSpiInfo = pSpiInfo->next;
    }
    spi_info = NULL;
    return srtp_err_status_spi_not_found;
}

unsigned int ekt_get_tag_length(srtp_ekt_mode_t ektMode, int master_key_len) {

    unsigned int plaintext_length,
                 ciphertext_length,
                 data_blocks,
                 ekt_tag_length;

    /* The EKT Plaintext contents depends on the EKT mode */
    if (ektMode == ekt_mode_prime_end_to_end) {
        /* Plaintext is: SRTP_Master_Key || SSRC */
        plaintext_length = master_key_len + sizeof(uint32_t);
    }
    else {
        /* Plaintext is: SRTP_Master_Key || SSRC || ROC */
        plaintext_length =
            master_key_len + sizeof(uint32_t) + sizeof(srtp_roc_t);
    }

    /* Determine the length of the AES Key Wrap ciphertext */
    data_blocks = plaintext_length / 8;
    if (plaintext_length % 8) {
        data_blocks++;
    }
    if (data_blocks < 2) {
        ciphertext_length = 16;
    }
    else {
        ciphertext_length = data_blocks * 8 + 8;
    }

    /* Compute the EKT Tag length as the ciphertext length + SPI field */
    ekt_tag_length = ciphertext_length + sizeof(srtp_ekt_spi_t);

    /* For PRIME mode, the ROC is outside the plaintext in EKT tag */
    if (ektMode == ekt_mode_prime_end_to_end) {
        ekt_tag_length += sizeof(srtp_roc_t);
    }

    return ekt_tag_length;
}

srtp_ekt_spi_t
srtp_packet_get_ekt_spi(const uint8_t *packet_start, unsigned pkt_octet_len) {
    const uint8_t *spi_location;
    srtp_ekt_spi_t spi;

    spi_location = packet_start + (pkt_octet_len - sizeof(srtp_ekt_spi_t));
    spi = *((srtp_ekt_spi_t *)(spi_location));
    spi = ntohs(spi);
    return spi;
}

/*
 * srtp_packet_get_roc will retrieve the ROC from the plaintext portion of
 * the EKT field for PRIME.  This function is not used in regular EKT.
 */
srtp_roc_t
srtp_packet_get_roc(const uint8_t *packet_start, unsigned pkt_octet_len) {
    srtp_roc_t *roc_location;

    roc_location =
        (srtp_roc_t *)(packet_start + (pkt_octet_len - sizeof(srtp_roc_t)));

    return ntohl(*((srtp_roc_t *)(roc_location)));
}

srtp_err_status_t ekt_parse_tag(srtp_stream_ctx_t *stream,
                                srtp_ctx_t *ctx,
                                const void  *srtp_hdr,
                                int *pkt_octet_len,
                                ekt_tag_contents_t *tag_contents)
{
    uint8_t *ektTag,
            ektTag_plainText[SRTP_MAX_EKT_TAG_LEN];
    int ektTagLength;
    unsigned int ektTag_plainTextLength,
                 ektTag_plainTextExpectedLength,
                 ektTag_offset;
    int kek_len,
        master_salt_len;
    int master_key_len,
        master_key_base_len;
    srtp_err_status_t rc;
    srtp_ekt_spi_info_t *spi_info = NULL;
    srtp_hdr_t *hdr = (srtp_hdr_t *)srtp_hdr;

    /* Check the final octet for a short EKT tag octet, returning if present */
    tag_contents->present =
        *((uint8_t *)srtp_hdr + *pkt_octet_len - 1) & 0x01;
    if (!(tag_contents->present)) {
       (*pkt_octet_len)--;
        return srtp_err_no_ekt;
    }

    /* Retrieve the SPI from the full EKT tag (in plaintext) */
    tag_contents->spi = srtp_packet_get_ekt_spi(srtp_hdr, *pkt_octet_len);
    *pkt_octet_len -= sizeof(srtp_ekt_spi_t);
    tag_contents->spi = (tag_contents->spi & 0xfffe) >> 1;

    /*
     * Get SPI info for SPI received. SPI info will contain EKT key required
     * to decrypt the EKT tag.
     */
    rc = ekt_get_spi_info(ctx, tag_contents->spi, &spi_info);
    if (rc != srtp_err_status_ok || spi_info == NULL)
        return rc;

    /* Compute the key lengths */
    kek_len = srtp_get_ekt_cipher_key_length(spi_info->ekt_cipher);
    master_key_len = srtp_cipher_get_key_length(stream->rtp_cipher);
    if (stream->rtp_xtn_hdr_cipher)
    {
        int xtn_hdr_key_len =
            srtp_cipher_get_key_length(stream->rtp_xtn_hdr_cipher);
        if (xtn_hdr_key_len > master_key_len) {
            master_key_len = xtn_hdr_key_len;
        }
    }
    master_key_base_len = base_key_length(stream->rtp_cipher->type,
                                          master_key_len);

    /*
     * For PRIME, ROC is in plaintext. Therefore, retrieve ROC here.
     * Also compute the expected plain encrypted EKT tag lengths.
     */
    if (stream->ektMode == ekt_mode_prime_end_to_end) {
        tag_contents->roc = srtp_packet_get_roc(srtp_hdr, *pkt_octet_len);
        *pkt_octet_len -= sizeof(srtp_roc_t);

        ektTag_plainTextExpectedLength = master_key_base_len + sizeof(uint32_t);
        ektTagLength = ekt_get_tag_length(stream->ektMode, master_key_base_len) - sizeof(srtp_ekt_spi_t) - sizeof(srtp_roc_t);
    }
    else {
        ektTag_plainTextExpectedLength = master_key_base_len + sizeof(uint32_t) + sizeof (srtp_roc_t);
        ektTagLength = ekt_get_tag_length(stream->ektMode, master_key_base_len) - sizeof(srtp_ekt_spi_t);

        /*
         * Set ROC = 0 to ensure that srtp_ekt_ciphertext_decrypt does
         * not change the default IV used in AES Key Wrap
         */
        tag_contents->roc = 0;
    }

    /* Check to ensure that the EKT tag is properly bounded */
    if ((ektTagLength > SRTP_MAX_EKT_TAG_LEN) || (ektTagLength == 0) ||
        (ektTagLength >= *pkt_octet_len)) {
        return srtp_err_status_parse_err;
    }

    /* Retrieve the EKT cipher text and decrypt to obtain the plain text. */
    ektTag = (uint8_t *)((uint8_t *)srtp_hdr + *pkt_octet_len - ektTagLength);

    /* Decrypt the EKT ciphertext */
    rc = srtp_ekt_ciphertext_decrypt((void*)spi_info->ekt_key, (kek_len << 3), ektTag, ektTagLength, tag_contents->roc, ektTag_plainText, &ektTag_plainTextLength);
    if (rc != srtp_err_status_ok)
        return rc;

    /* Check if the EKT tag length is valid */
    if (ektTag_plainTextExpectedLength != ektTag_plainTextLength)
        return srtp_err_status_bad_param;

    /* Retrieve the the master key */
    master_salt_len = master_key_len - master_key_base_len;
    memcpy(tag_contents->master_key, ektTag_plainText, master_key_base_len);
    ektTag_offset = master_key_base_len;

    /*
     * Copy the salt in the key. All EKT keys use the salt from assosciated
     * SPI info and the computed length should match the value in spi_info.
     */
    if (master_salt_len != spi_info->ekt_salt_length)
        return srtp_err_status_bad_param;
    memcpy((void *)(tag_contents->master_key + master_key_base_len), (const void *)(spi_info->ekt_key + master_key_base_len), master_salt_len);

    /* Set the length = key length + master salt length */
    tag_contents->master_key_len = master_key_base_len + master_salt_len;

    /* Retrieve the SSRC */
    memcpy((void *)&tag_contents->ssrc, (void *)(ektTag_plainText + ektTag_offset), sizeof(uint32_t));
    ektTag_offset += sizeof(uint32_t);
    if (tag_contents->ssrc != hdr->ssrc)
        return srtp_err_status_ekt_tag_ssrc_mismatch;
    tag_contents->ssrc = ntohl(tag_contents->ssrc);

    /* For non-PRIME ROC is in the decrypted text */
    if (stream->ektMode == ekt_mode_regular) {
        memcpy((void *)&tag_contents->roc, (void *)(ektTag_plainText + ektTag_offset), sizeof(srtp_roc_t));
        ektTag_offset += sizeof(srtp_roc_t);
        tag_contents->roc = ntohl(tag_contents->roc);
    }

    *pkt_octet_len -= ektTagLength;

    return srtp_err_status_ok;
}

srtp_err_status_t
ekt_generate_tag(srtp_stream_ctx_t *stream,
                 srtp_ctx_t   *ctx,
                 void         *srtp_hdr,
                 uint8_t      *ekt_cipherText,
                 unsigned int *ekt_cipherTextLength,
                 srtp_service_flags_t flags)
{
    srtp_hdr_t *hdr = (srtp_hdr_t *)srtp_hdr;
    srtp_roc_t roc;
    srtp_ekt_spi_info_t *spi_info = NULL;
    uint8_t ektTag[SRTP_MAX_EKT_TAG_LEN],
            ektTagLen,
            *ektTagPtr;
    int kek_len,
        key_len,
        base_key_len;
    srtp_err_status_t rc;
    srtp_ekt_spi_t spi;

    *ekt_cipherTextLength = 0;

    /*
     * For EKT, the application will configure the stream to generate EKT tag
     * for n packets after every ROC change. Therefore check if ROC has just
     * changed and set tag generation.
     */
    if (ntohs(hdr->seq) == 0 && (stream->ekt_data.total_ekt_tags_to_generate_after_rollover > 0))
        stream->ekt_data.auto_ekt_pkts_left = stream->ekt_data.total_ekt_tags_to_generate_after_rollover;

    /*
     * Full EKT tag is generated if:
     *  - Application has requested to generate EKT tag.
     *  - auto_ekt_pkts_left is greater than 0. (auto_ekt_pkts_left is set to
     *    n every time the ROC changes.)
     *  - packets_left_to_generate_auto_ekt is equal to 0. (An EKT tag is
     *    generated every packets_left_to_generate_auto_ekt packets.)
     *
     * If full EKT tag is not to be generated then add short EKT tag.
     */
    if (!(flags & srtp_service_ekt_tag) &&
        stream->ekt_data.auto_ekt_pkts_left == 0 &&
        stream->ekt_data.packets_left_to_generate_auto_ekt > 0)
    {
        stream->ekt_data.packets_left_to_generate_auto_ekt--;

        /* Insert a short EKT tag */
        *ekt_cipherText = 0x00;
        (*ekt_cipherTextLength)++;
        return srtp_err_status_ok;
    }

    /*
     * Get SPI info for SPI received. SPI info will contain KEK required to
     * decrypt the EKT tag. Get the kek length
     */
    rc = ekt_get_spi_info(ctx, stream->ekt_data.spi, &spi_info);
    if (rc != srtp_err_status_ok)
        return rc;

    /* Determine the EKT Key length */
    kek_len = srtp_get_ekt_cipher_key_length(spi_info->ekt_cipher);

    /* Copy master key into ekt tag */
    key_len = srtp_cipher_get_key_length(stream->rtp_cipher);
    base_key_len = base_key_length(stream->rtp_cipher->type, key_len);

    memcpy((void *)ektTag, stream->master_key, base_key_len);
    debug_print(mod_srtp, "writing EKT EMK: %s",
                srtp_octet_string_hex_string(ektTag, base_key_len));
    ektTagLen = base_key_len;

    /* copy SSRC into packet */
    memcpy((void *)(ektTag + ektTagLen), &stream->ssrc, sizeof(stream->ssrc));
    debug_print(mod_srtp, "writing EKT SSRC: %s",
                srtp_octet_string_hex_string(ektTag + ektTagLen, sizeof(stream->ssrc)));
    ektTagLen += sizeof(stream->ssrc);

    /* Get the ROC for the stream */
    if (stream->rtp_rdbx_prime) {
        roc = htonl(srtp_rdbx_get_roc(stream->rtp_rdbx_prime));
    }
    else {
        roc = htonl(srtp_rdbx_get_roc(&stream->rtp_rdbx));
    }

    /*
     * For non-PRIME ROC is in the ciphertext. Therefore insert ROC here.
     */
    if (stream->ektMode == ekt_mode_regular) {
        /* copy ROC into packet */
        memcpy((void *)(ektTag + ektTagLen), (void *)&roc, sizeof(roc));
        debug_print(mod_srtp, "writing EKT ROC: %s",
            srtp_octet_string_hex_string(&roc, sizeof(roc)));
        ektTagLen += sizeof(roc);
    }

    /* Encrypt the EKT tag */
    debug_print(mod_srtp, "EKT_TAG: %s",
                srtp_octet_string_hex_string(ektTag, ektTagLen));
    debug_print(mod_srtp, "EKT_TAGLEN: %i", ektTagLen);
    if (stream->ektMode == ekt_mode_prime_end_to_end) {
        srtp_ekt_plaintext_encrypt((void*)(spi_info->ekt_key), (kek_len << 3), ektTag, ektTagLen, ntohl(roc), ekt_cipherText, ekt_cipherTextLength);
    } else {
        srtp_ekt_plaintext_encrypt((void*)(spi_info->ekt_key), (kek_len << 3), ektTag, ektTagLen, 0, ekt_cipherText, ekt_cipherTextLength);
    }
    ektTagPtr = ekt_cipherText + *ekt_cipherTextLength;

    /*
     * For PRIME ROC is in plain text. Therefore insert ROC here.
     * Also compute the expected plain encrypted EKT tag lengths.
     */
    if (stream->ektMode == ekt_mode_prime_end_to_end) {
        /* copy ROC into packet */
        memcpy(ektTagPtr, (void *)&roc, sizeof(roc));
        debug_print(mod_srtp, "writing EKT ROC: %s",
            srtp_octet_string_hex_string(&roc, sizeof(roc)));
        ektTagPtr += sizeof(roc);
        *ekt_cipherTextLength += sizeof(roc);
    }

    /* copy SPI into packet */
    spi = (stream->ekt_data.spi << 1) | 0x0001;
    *((srtp_ekt_spi_t *)ektTagPtr) = htons(spi);
    debug_print(mod_srtp, "writing EKT SPI: %s",
                srtp_octet_string_hex_string(   ektTagPtr,
                                                sizeof(stream->ekt_data.spi)));
    *ekt_cipherTextLength += sizeof(stream->ekt_data.spi);

    if (stream->ekt_data.auto_ekt_pkts_left > 0)
        stream->ekt_data.auto_ekt_pkts_left--;

    stream->ekt_data.packets_left_to_generate_auto_ekt =
                        stream->ekt_data.auto_ekt_packet_interval;

    return srtp_err_status_ok;
}
