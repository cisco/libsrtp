/*
 * ekt.c
 *
 * Encrypted Key Transport for SRTP
 * 
 * David McGrew
 * Cisco Systems, Inc.
 *
 * CHANGE LOG
 * ----------
 * 2015-12-11 - Nivedita Melinkeri
 *     - Added functions to support current EKT and PRIME specs
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

int
srtp_get_ekt_cipher_key_length(srtp_ekt_cipher_t ekt_cipher)
{
    int key_len;

    /* The key length depends on the EKT cipher employed */
    switch (ekt_cipher)
    {
    case EKT_CIPHER_AESKW_128:
        key_len = 16;
        break;
    case EKT_CIPHER_AESKW_192:
        key_len = 24;
        break;
    case EKT_CIPHER_AESKW_256:
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

unsigned int ekt_get_tag_length(srtp_ekt_mode_t ektMode, srtp_ekt_spi_info_t *spi_info) {

    unsigned int tag_len, padding_len;

    /*
     * if the pointer ekt is NULL, then EKT is not in effect, so we
     * indicate this by returning zero
     */
    if (!spi_info)
        return 0;

    if (ektMode == EKT_MODE_PRIME_END_TO_END) {
        tag_len = srtp_get_ekt_cipher_key_length(spi_info->ekt_cipher) + sizeof(srtp_ssrc_t);
        padding_len = tag_len % 8;
        tag_len += padding_len;
        tag_len += 8;
        tag_len = tag_len + sizeof(srtp_roc_t) + sizeof(srtp_ekt_spi_t);
    }
    else {
        tag_len = srtp_get_ekt_cipher_key_length(spi_info->ekt_cipher) + sizeof(srtp_roc_t) + sizeof(srtp_ssrc_t);
        padding_len = tag_len % 8;
        tag_len += padding_len;
        tag_len += 8;
        tag_len = tag_len + sizeof(srtp_ekt_spi_t);
    }

    return tag_len;
}

srtp_ekt_spi_t
srtp_packet_get_ekt_spi(const uint8_t *packet_start, unsigned pkt_octet_len) {
    const uint8_t *spi_location;
    srtp_ekt_spi_t spi;

    spi_location = packet_start + (pkt_octet_len - sizeof(srtp_ekt_spi_t));
    spi = *((unsigned short *)(spi_location));
    spi = ntohs(spi);
    return spi;
}

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
                                uint8_t *master_key,
                                int *pkt_octet_len,
                                int *ektTagPresent)
{
    uint8_t *ektTag,
            ektTag_plainText[SRTP_MAX_EKT_TAG_LEN],
            ektTagLength;
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
    uint32_t ssrc;
    srtp_roc_t roc;
    srtp_ekt_spi_t spi;

    /*
     * Retrieve the SPI and then check if it is short EKT tag or full EKT tag.
     * If short EKT tag then return else process the tag. SPI is sent in
     * plaintext.
     */
    spi = srtp_packet_get_ekt_spi(srtp_hdr, *pkt_octet_len);
    *pkt_octet_len -= sizeof(srtp_ekt_spi_t);

    *ektTagPresent = spi & 0x0001;
    if (!(*ektTagPresent))
        return srtp_err_no_ekt;
    spi = (spi & 0xfffe) >> 1;

    /*
     * Get SPI info for SPI received. SPI info will contain EKT key required
     * to decrypt the EKT tag.
     */
    rc = ekt_get_spi_info(ctx, spi, &spi_info);
    if (rc != srtp_err_status_ok || spi_info == NULL)
        return rc;

    /* Compute the key lengths */
    kek_len = srtp_get_ekt_cipher_key_length(spi_info->ekt_cipher);
    master_key_len = srtp_cipher_get_key_length(stream->rtp_cipher);
    master_key_base_len = base_key_length(stream->rtp_cipher->type, master_key_len);

    /*
     * For PRIME ROC is in plain text. Therefore retrieve ROC here.
     * Also compute the expected plain encrypted EKT tag lengths.
     */
    if (stream->ektMode == EKT_MODE_PRIME_END_TO_END) {
        roc = srtp_packet_get_roc(srtp_hdr, *pkt_octet_len);
        *pkt_octet_len -= sizeof(srtp_roc_t);

        ektTag_plainTextExpectedLength = master_key_base_len + sizeof(uint32_t);
        ektTagLength = ekt_get_tag_length(stream->ektMode, spi_info) - sizeof(srtp_ekt_spi_t) - sizeof(srtp_roc_t);
    }
    else {
        ektTag_plainTextExpectedLength = master_key_base_len + sizeof(uint32_t) + sizeof (srtp_roc_t);
        ektTagLength = ekt_get_tag_length(stream->ektMode, spi_info) - sizeof(srtp_ekt_spi_t);
        /*
         * Set ROC = 0 to ensure that srtp_ekt_ciphertext_decrypt does
         * not change the default IV used in AES Key Wrap
         */
        roc = 0;
    }

    /* Check to ensure that the EKT tag is properly bounded */
    if ((ektTagLength > SRTP_MAX_EKT_TAG_LEN) || (ektTagLength == 0)) {
        return srtp_err_status_parse_err;
    }

    /* Retrieve the EKT cipher text and decrypt to obtain the plain text. */
    ektTag = (uint8_t *)((uint8_t *)srtp_hdr + *pkt_octet_len - ektTagLength);

    /* Decrypt the EKT cipher text */
    rc = srtp_ekt_ciphertext_decrypt((void*)spi_info->ekt_key, (kek_len << 3), ektTag, ektTagLength, roc, ektTag_plainText, &ektTag_plainTextLength);
    if (rc != srtp_err_status_ok)
        return rc;

    /* Check if the EKT tag length is valid */
    if (ektTag_plainTextExpectedLength != ektTag_plainTextLength)
        return srtp_err_status_bad_param;

    /* Retrieve the the master key */
    master_salt_len = master_key_len - master_key_base_len;
    memcpy(master_key, ektTag_plainText, master_key_base_len);
    ektTag_offset = master_key_base_len;

    /*
     * Copy the salt in the key. All EKT keys use the salt from assosciated
     * SPI info and the computed length should match the value in spi_info.
     */
    if (master_salt_len != spi_info->ekt_salt_length)
        return srtp_err_status_bad_param;
    memcpy((void *)(master_key + master_key_base_len), (const void *)(spi_info->ekt_key + master_key_base_len), master_salt_len);

    /* Retrieve the SSRC */
    memcpy((void *)&ssrc, (void *)(ektTag_plainText + ektTag_offset), sizeof(uint32_t));
    ektTag_offset += sizeof(uint32_t);
    ssrc = ntohl(ssrc);
    if (ssrc != hdr->ssrc)
        return srtp_err_status_ekt_tag_ssrc_mismatch;

    /* For non-PRIME ROC is in the decrypted text */
    if (stream->ektMode == EKT_MODE_REGULAR) {
        memcpy((void *)&roc, (void *)(ektTag_plainText + ektTag_offset), sizeof(srtp_roc_t));
        ektTag_offset += sizeof(srtp_roc_t);
        roc = ntohl(roc);
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
    uint32_t ssrc;
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
     *  - If full EKT tag is not to be generated then add short EKT tag.
     */
    if (!(flags & SRTP_SERVICE_EKT_TAG) && stream->ekt_data.auto_ekt_pkts_left == 0 && stream->ekt_data.packets_left_to_generate_auto_ekt > 0)
    {
        stream->ekt_data.packets_left_to_generate_auto_ekt--;
        /* Set SPI value to 0 in the packet */
        *((srtp_ekt_spi_t *)ekt_cipherText) = 0;
        *ekt_cipherTextLength += sizeof(stream->ekt_data.spi);
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
    debug_print(mod_srtp, "writing EKT EMK: %s,",
                srtp_octet_string_hex_string(ektTag, base_key_len));
    ektTagLen = base_key_len;

    /* copy SSRC into packet */
    ssrc = htonl(stream->ssrc);
    memcpy((void *)(ektTag + ektTagLen), &ssrc, sizeof(ssrc));
    debug_print(mod_srtp, "writing EKT SSRC: %s,",
                srtp_octet_string_hex_string(ektTag + ektTagLen, sizeof(stream->ssrc)));
    ektTagLen += sizeof(stream->ssrc);

    roc = htonl(srtp_rdbx_get_roc(&stream->rtp_rdbx));

    /*
     * For non-PRIME ROC is in the ciphertext. Therefore insert ROC here.
     */
    if (stream->ektMode == EKT_MODE_REGULAR) {
        /* copy ROC into packet */
        memcpy((void *)(ektTag + ektTagLen), (void *)&roc, sizeof(roc));
        debug_print(mod_srtp, "writing EKT ROC: %s,",
            srtp_octet_string_hex_string(&roc, sizeof(roc)));
        ektTagLen += sizeof(roc);
    }

    /* Encrypt the EKT tag */
    srtp_ekt_plaintext_encrypt((void*)(spi_info->ekt_key), (kek_len << 3), ektTag, ektTagLen, roc, ekt_cipherText, ekt_cipherTextLength);
    ektTagPtr = ekt_cipherText + *ekt_cipherTextLength;

    /*
     * For PRIME ROC is in plain text. Therefore insert ROC here.
     * Also compute the expected plain encrypted EKT tag lengths.
     */
    if (stream->ektMode == EKT_MODE_PRIME_END_TO_END) {
        /* copy ROC into packet */
        memcpy(ektTagPtr, (void *)&roc, sizeof(roc));
        *((srtp_roc_t *)ektTagPtr) = htonl(roc); // >> 1;
        roc = *((srtp_roc_t *)(ektTagPtr));
        roc = ntohl(roc);
        debug_print(mod_srtp, "writing EKT ROC: %s,",
            srtp_octet_string_hex_string(&roc, sizeof(roc)));
        ektTagPtr += sizeof(roc);
        *ekt_cipherTextLength += sizeof(roc);
    }

    /* copy SPI into packet */
    spi = (stream->ekt_data.spi << 1) | 0x0001;
    *((srtp_ekt_spi_t *)ektTagPtr) = htons(spi);
    debug_print(mod_srtp, "writing EKT SPI: %s,",
                srtp_octet_string_hex_string(   ektTagPtr,
                                                sizeof(stream->ekt_data.spi)));
    *ekt_cipherTextLength += sizeof(stream->ekt_data.spi);

    if (stream->ekt_data.auto_ekt_pkts_left > 0)
        stream->ekt_data.auto_ekt_pkts_left--;

    stream->ekt_data.packets_left_to_generate_auto_ekt =
                        stream->ekt_data.auto_ekt_packet_interval;

    return srtp_err_status_ok;
}
