/*
 * Standalone round-trip tests for the RFC 4771 RCC (Roll-over Counter Carrying)
 * support added to libsrtp.
 *
 * The mode 1 and mode 2 tests work with the native crypto backend.  The GCM
 * mode 3 tests (RFC 4771 NULL-MAC carried over AES-GCM, RFC 7714) require a
 * crypto backend that provides AES-GCM, so build with one enabled (e.g.
 * OpenSSL).
 */

/*
 *
 * Copyright (c) 2026
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
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "srtp.h"

static uint8_t key[30] = { 0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
                           0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
                           0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
                           0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6 };

#define SSRC 0xcafebabe

static void make_policy_rate(srtp_policy_t *p,
                             srtp_rcc_mode_t mode,
                             srtp_ssrc_type_t dir,
                             uint16_t rate)
{
    srtp_ssrc_t ssrc = { dir, SSRC };
    srtp_policy_create(p);
    srtp_policy_set_profile(*p, srtp_profile_aes128_cm_sha1_80);
    srtp_policy_set_sec_serv(*p, sec_serv_conf_and_auth,
                             sec_serv_conf_and_auth);
    srtp_policy_set_ssrc(*p, ssrc);
    srtp_policy_set_rcc_mode_tx_rate(*p, mode, rate);
    srtp_policy_set_window_size(*p, 128);
    srtp_policy_add_key(*p, key, SRTP_AES_128_KEY_LEN,
                        key + SRTP_AES_128_KEY_LEN, SRTP_SALT_LEN, NULL, 0);
}

static void make_policy(srtp_policy_t *p,
                        srtp_rcc_mode_t mode,
                        srtp_ssrc_type_t dir)
{
    make_policy_rate(p, mode, dir, 1);
}

/* AES-GCM-128 key (16 octets) + salt (12 octets) = 28 octets */
static uint8_t gcm_key[28] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
                               0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                               0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
                               0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b };

#ifdef GCM
static void make_gcm_policy_rate(srtp_policy_t *p,
                                 srtp_rcc_mode_t mode,
                                 srtp_ssrc_type_t dir,
                                 uint16_t rate)
{
    srtp_ssrc_t ssrc = { dir, SSRC };
    srtp_policy_create(p);
    srtp_policy_set_profile(*p, srtp_profile_aead_aes_128_gcm);
    srtp_policy_set_sec_serv(*p, sec_serv_conf_and_auth,
                             sec_serv_conf_and_auth);
    srtp_policy_set_ssrc(*p, ssrc);
    srtp_policy_set_rcc_mode_tx_rate(*p, mode, rate);
    srtp_policy_set_window_size(*p, 128);
    srtp_policy_add_key(*p, gcm_key, SRTP_AES_128_KEY_LEN,
                        gcm_key + SRTP_AES_128_KEY_LEN, SRTP_AEAD_SALT_LEN,
                        NULL, 0);
}
#endif

/* build an RTP packet with given seq and a fixed payload */
static size_t make_rtp(uint8_t *buf, uint16_t seq, const char *payload)
{
    buf[0] = 0x80; /* V=2 */
    buf[1] = 0x00; /* PT=0 */
    uint16_t nseq = htons(seq);
    memcpy(buf + 2, &nseq, 2);
    uint32_t ts = htonl(0x1234);
    memcpy(buf + 4, &ts, 4);
    uint32_t ssrc = htonl(SSRC);
    memcpy(buf + 8, &ssrc, 4);
    size_t plen = strlen(payload);
    memcpy(buf + 12, payload, plen);
    return 12 + plen;
}

static int roundtrip(srtp_t snd, srtp_t rcv, uint16_t seq, const char *msg)
{
    uint8_t pkt[256];
    size_t len = make_rtp(pkt, seq, msg);
    uint8_t enc[256];
    size_t enc_len = sizeof(enc);
    srtp_err_status_t s = srtp_protect(snd, pkt, len, enc, &enc_len, 0);
    if (s) {
        printf("  protect seq=%u failed: %d\n", seq, s);
        return 1;
    }

    uint8_t dec[256];
    size_t dec_len = sizeof(dec);
    s = srtp_unprotect(rcv, enc, enc_len, dec, &dec_len);
    if (s) {
        printf("  unprotect seq=%u failed: %d\n", seq, s);
        return 1;
    }

    if (dec_len != len || memcmp(dec, pkt, len) != 0) {
        printf("  payload mismatch seq=%u (dec_len=%zu, exp=%zu)\n", seq,
               dec_len, len);
        return 1;
    }
    return 0;
}

int main(void)
{
    if (srtp_init() != srtp_err_status_ok) {
        printf("init fail\n");
        return 1;
    }

    int fails = 0;

    /* ---- Test 1: mode 2, basic round trip several packets ---- */
    {
        srtp_t snd, rcv;
        srtp_policy_t sp, rp;
        uint16_t rate =
            3; /* carry every 3rd packet, arbitrary non-power-of-2 */
        make_policy_rate(&sp, srtp_rcc_mode_2, ssrc_specific, rate);
        make_policy_rate(&rp, srtp_rcc_mode_2, ssrc_specific, rate);
        srtp_create(&snd, sp);
        srtp_create(&rcv, rp);
        int f = 0;
        for (uint16_t seq = 1; seq <= 50; seq++)
            f += roundtrip(snd, rcv, seq, "hello world");
        printf("Test1 mode2 basic: %s\n", f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 2: mode 1, basic round trip ---- */
    {
        srtp_t snd, rcv;
        srtp_policy_t sp, rp;
        uint16_t rate =
            3; /* carry every 3rd packet, arbitrary non-power-of-2 */
        make_policy_rate(&sp, srtp_rcc_mode_1, ssrc_specific, rate);
        make_policy_rate(&rp, srtp_rcc_mode_1, ssrc_specific, rate);
        srtp_create(&snd, sp);
        srtp_create(&rcv, rp);
        int f = 0;
        for (uint16_t seq = 1; seq <= 50; seq++)
            f += roundtrip(snd, rcv, seq, "mode one data");
        printf("Test2 mode1 basic: %s\n", f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 3: late-joining receiver after ROC advanced (mode 2) ----
     * sender wraps seq past 65535 so ROC becomes 1, then a brand-new
     * receiver must adopt the ROC carried in the packet (R=1 every packet).
     */
    {
        srtp_t snd;
        srtp_policy_t sp;
        make_policy(&sp, srtp_rcc_mode_2, ssrc_specific);
        srtp_create(&snd, sp);

        uint8_t pkt[256], enc[256];
        size_t len, enc_len;

        /* push sender's ROC to 1 by walking the sequence number around */
        for (uint32_t i = 0; i < 70000; i += 4096) {
            len = make_rtp(pkt, (uint16_t)i, "x");
            enc_len = sizeof(enc);
            srtp_protect(snd, pkt, len, enc, &enc_len, 0);
        }
        uint32_t roc = 0;
        srtp_stream_get_roc(snd, SSRC, &roc);
        printf("Test3: sender ROC after wrap = %u\n", roc);

        /* now a fresh receiver joins and must sync via in-band ROC */
        srtp_t rcv;
        srtp_policy_t rp;
        make_policy(&rp, srtp_rcc_mode_2, ssrc_specific);
        srtp_create(&rcv, rp);

        uint16_t seq = 5000; /* arbitrary, ROC still 1 */
        len = make_rtp(pkt, seq, "late join payload");
        enc_len = sizeof(enc);
        srtp_err_status_t s = srtp_protect(snd, pkt, len, enc, &enc_len, 0);
        uint8_t dec[256];
        size_t dec_len = sizeof(dec);
        s = srtp_unprotect(rcv, enc, enc_len, dec, &dec_len);
        int f = 0;
        if (s) {
            printf("  late-join unprotect failed: %d\n", s);
            f = 1;
        } else if (dec_len != len || memcmp(dec, pkt, len)) {
            printf("  late-join payload mismatch\n");
            f = 1;
        }
        uint32_t rroc = 0;
        srtp_stream_get_roc(rcv, SSRC, &rroc);
        if (rroc != roc) {
            printf("  receiver ROC=%u != sender ROC=%u\n", rroc, roc);
            f = 1;
        }
        printf("Test3 mode2 late-join ROC sync: %s\n", f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 4: GCM + RCC mode 2 rejected at create ----
     * Modes 1 and 2 embed the ROC in a truncated HMAC and are not defined for
     * AEAD/GCM, so srtp_create() must reject them.  (Mode 3 over GCM is the
     * supported combination and is exercised by the GCM tests below.)
     */
    {
        srtp_t s;
        srtp_policy_t p;
        make_gcm_policy_rate(&p, srtp_rcc_mode_2, ssrc_specific, 1);
        srtp_err_status_t st = srtp_create(&s, p);
        int f = (st == srtp_err_status_ok) ? 1 : 0;
        printf("Test4 GCM+RCC mode2 rejected: %s (status=%d)\n",
               f ? "FAIL" : "PASS", st);
        fails += f;
        if (st == srtp_err_status_ok)
            srtp_dealloc(s);
    }

    /* ---- Test 5: mode 2, R=4 ----
     * Only seq % 4 == 0 carries the ROC (constant tag length); the other
     * packets use the default full-length MAC computed over the local ROC.
     * Walk a contiguous run starting at seq 0 so every packet type is hit.
     */
    {
        srtp_t snd, rcv;
        srtp_policy_t sp, rp;
        make_policy_rate(&sp, srtp_rcc_mode_2, ssrc_specific, 4);
        make_policy_rate(&rp, srtp_rcc_mode_2, ssrc_specific, 4);
        srtp_create(&snd, sp);
        srtp_create(&rcv, rp);
        int f = 0;
        for (uint16_t seq = 0; seq <= 12; seq++)
            f += roundtrip(snd, rcv, seq, "mode2 rate4 payload");
        printf("Test5 mode2 R=4 (carry + non-carry): %s\n",
               f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 6: mode 1, R=4 ----
     * Carry packets (seq % 4 == 0) get TAG = ROC || MAC_tr; the other packets
     * carry no tag at all (variable packet length, no authentication).
     */
    {
        srtp_t snd, rcv;
        srtp_policy_t sp, rp;
        make_policy_rate(&sp, srtp_rcc_mode_1, ssrc_specific, 4);
        make_policy_rate(&rp, srtp_rcc_mode_1, ssrc_specific, 4);
        srtp_create(&snd, sp);
        srtp_create(&rcv, rp);
        int f = 0;
        for (uint16_t seq = 0; seq <= 12; seq++)
            f += roundtrip(snd, rcv, seq, "mode1 rate4 payload");
        printf("Test6 mode1 R=4 (carry + untagged): %s\n", f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 7: mode 2, R=4, late-joining receiver after a wrap ----
     * The sender advances its ROC to 1, then a fresh receiver joins. The next
     * ROC-carrying packet (seq % 4 == 0) must resynchronize the receiver.
     */
    {
        srtp_t snd;
        srtp_policy_t sp;
        make_policy_rate(&sp, srtp_rcc_mode_2, ssrc_specific, 4);
        srtp_create(&snd, sp);

        uint8_t pkt[256], enc[256];
        size_t len, enc_len;
        for (uint32_t i = 0; i < 70000; i += 4096) {
            len = make_rtp(pkt, (uint16_t)(i & ~0x3u), "x"); /* keep carry */
            enc_len = sizeof(enc);
            srtp_protect(snd, pkt, len, enc, &enc_len, 0);
        }
        uint32_t roc = 0;
        srtp_stream_get_roc(snd, SSRC, &roc);
        printf("Test7: sender ROC after wrap = %u\n", roc);

        srtp_t rcv;
        srtp_policy_t rp;
        make_policy_rate(&rp, srtp_rcc_mode_2, ssrc_specific, 4);
        srtp_create(&rcv, rp);

        uint16_t seq = 5000; /* 5000 % 4 == 0 -> carry packet */
        len = make_rtp(pkt, seq, "late join r4 payload");
        enc_len = sizeof(enc);
        srtp_protect(snd, pkt, len, enc, &enc_len, 0);
        uint8_t dec[256];
        size_t dec_len = sizeof(dec);
        srtp_err_status_t s = srtp_unprotect(rcv, enc, enc_len, dec, &dec_len);
        int f = 0;
        if (s) {
            printf("  late-join unprotect failed: %d\n", s);
            f = 1;
        } else if (dec_len != len || memcmp(dec, pkt, len)) {
            printf("  late-join payload mismatch\n");
            f = 1;
        }
        uint32_t rroc = 0;
        srtp_stream_get_roc(rcv, SSRC, &rroc);
        if (rroc != roc) {
            printf("  receiver ROC=%u != sender ROC=%u\n", rroc, roc);
            f = 1;
        }
        printf("Test7 mode2 R=4 late-join ROC sync: %s\n", f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

#ifdef GCM
    /* ---- Test 8: GCM + RCC mode 3 accepted at create ---- */
    {
        srtp_t s;
        srtp_policy_t p;
        make_gcm_policy_rate(&p, srtp_rcc_mode_3, ssrc_specific, 1);
        srtp_err_status_t st = srtp_create(&s, p);
        int f = (st == srtp_err_status_ok) ? 0 : 1;
        printf("Test8 GCM+RCC mode3 accepted: %s (status=%d)\n",
               f ? "FAIL" : "PASS", st);
        fails += f;
        if (st == srtp_err_status_ok)
            srtp_dealloc(s);
    }

    /* ---- Test 9: GCM mode 3, basic round trip (R=1, every packet carries
     * the ROC in the SRTP auth tag field per RFC 7714 section 8.2) ---- */
    {
        srtp_t snd, rcv;
        srtp_policy_t sp, rp;
        make_gcm_policy_rate(&sp, srtp_rcc_mode_3, ssrc_specific, 1);
        make_gcm_policy_rate(&rp, srtp_rcc_mode_3, ssrc_specific, 1);
        srtp_create(&snd, sp);
        srtp_create(&rcv, rp);
        int f = 0;
        for (uint16_t seq = 1; seq <= 5; seq++)
            f += roundtrip(snd, rcv, seq, "gcm mode3 payload");
        printf("Test9 GCM mode3 basic round trip: %s\n", f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 10: GCM mode 3, R=4 (carry and non-carry packets) ----
     * Only seq % 4 == 0 carries the 4-octet ROC in the SRTP auth tag field;
     * the other packets are plain RFC 7714 GCM packets.  Both must round-trip.
     */
    {
        srtp_t snd, rcv;
        srtp_policy_t sp, rp;
        make_gcm_policy_rate(&sp, srtp_rcc_mode_3, ssrc_specific, 4);
        make_gcm_policy_rate(&rp, srtp_rcc_mode_3, ssrc_specific, 4);
        srtp_create(&snd, sp);
        srtp_create(&rcv, rp);
        int f = 0;
        for (uint16_t seq = 0; seq <= 12; seq++)
            f += roundtrip(snd, rcv, seq, "gcm mode3 rate4 payload");
        printf("Test10 GCM mode3 R=4 (carry + non-carry): %s\n",
               f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 11: GCM mode 3, verify the ROC is carried in the SRTP auth
     * tag field (the last 4 octets, after the GCM tag and the optional MKI per
     * RFC 7714 section 8.2), and that a fresh receiver resynchronizes from the
     * in-band ROC ----
     */
    {
        srtp_t snd;
        srtp_policy_t sp;
        make_gcm_policy_rate(&sp, srtp_rcc_mode_3, ssrc_specific, 1);
        srtp_create(&snd, sp);

        uint8_t pkt[256], enc[256];
        size_t len, enc_len;

        /* advance the sender's ROC to 1 by walking the sequence number */
        for (uint32_t i = 0; i < 70000; i += 4096) {
            len = make_rtp(pkt, (uint16_t)i, "x");
            enc_len = sizeof(enc);
            srtp_protect(snd, pkt, len, enc, &enc_len, 0);
        }
        uint32_t roc = 0;
        srtp_stream_get_roc(snd, SSRC, &roc);
        printf("Test11: sender ROC after wrap = %u\n", roc);

        uint16_t seq = 5000;
        len = make_rtp(pkt, seq, "gcm late join");
        enc_len = sizeof(enc);
        srtp_protect(snd, pkt, len, enc, &enc_len, 0);

        /* expected layout (no MKI): header + ciphertext + 16-octet GCM tag
         * + 4-octet ROC.  The last four octets are the SRTP auth tag field
         * carrying the sender's ROC in network order (RFC 7714 section 8.2).
         */
        int f = 0;
        uint32_t carried = 0;
        memcpy(&carried, enc + enc_len - 4, 4);
        carried = ntohl(carried);
        if (carried != roc) {
            printf("  carried ROC=%u != sender ROC=%u\n", carried, roc);
            f = 1;
        }
        if (enc_len != len + 16 + 4) {
            printf("  unexpected enc_len=%zu (exp=%zu)\n", enc_len,
                   len + 16 + 4);
            f = 1;
        }

        /* a fresh receiver must sync via the in-band ROC */
        srtp_t rcv;
        srtp_policy_t rp;
        make_gcm_policy_rate(&rp, srtp_rcc_mode_3, ssrc_specific, 1);
        srtp_create(&rcv, rp);
        uint8_t dec[256];
        size_t dec_len = sizeof(dec);
        srtp_err_status_t s = srtp_unprotect(rcv, enc, enc_len, dec, &dec_len);
        if (s) {
            printf("  late-join unprotect failed: %d\n", s);
            f = 1;
        } else if (dec_len != len || memcmp(dec, pkt, len)) {
            printf("  late-join payload mismatch\n");
            f = 1;
        }
        uint32_t rroc = 0;
        srtp_stream_get_roc(rcv, SSRC, &rroc);
        if (rroc != roc) {
            printf("  receiver ROC=%u != sender ROC=%u\n", rroc, roc);
            f = 1;
        }
        printf("Test11 GCM mode3 ROC-after-tag + late-join sync: %s\n",
               f ? "FAIL" : "PASS");
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 12: GCM mode 3, tampering with the carried ROC is detected ----
     * Because the ROC feeds the GCM IV, flipping a ROC bit yields a wrong IV
     * and GCM tag verification must fail (implicit ROC integrity).
     */
    {
        srtp_t snd, rcv;
        srtp_policy_t sp, rp;
        make_gcm_policy_rate(&sp, srtp_rcc_mode_3, ssrc_specific, 1);
        make_gcm_policy_rate(&rp, srtp_rcc_mode_3, ssrc_specific, 1);
        srtp_create(&snd, sp);
        srtp_create(&rcv, rp);

        uint8_t pkt[256], enc[256], dec[256];
        size_t len = make_rtp(pkt, 100, "tamper test");
        size_t enc_len = sizeof(enc);
        srtp_protect(snd, pkt, len, enc, &enc_len, 0);

        /* flip a bit in the carried ROC (last 4 octets) */
        enc[enc_len - 1] ^= 0x01;

        size_t dec_len = sizeof(dec);
        srtp_err_status_t s = srtp_unprotect(rcv, enc, enc_len, dec, &dec_len);
        int f = (s == srtp_err_status_ok) ? 1 : 0;
        printf("Test12 GCM mode3 ROC tamper detected: %s (status=%d)\n",
               f ? "FAIL" : "PASS", s);
        fails += f;
        srtp_dealloc(snd);
        srtp_dealloc(rcv);
    }

    /* ---- Test 13: GCM mode 3 with MKI, verifying the RFC 7714 section 8.2
     * field order: ciphertext (incl. GCM tag), then SRTP MKI, then the SRTP
     * authentication tag field (carrying the ROC).  The MKI must be located
     * correctly even though the ROC follows it, and the packet must round
     * trip.
     */
    {
        static uint8_t mki_id[4] = { 0xde, 0xad, 0xbe, 0xef };

        srtp_policy_t sp, rp;
        srtp_ssrc_t ssrc = { ssrc_specific, SSRC };
        srtp_policy_create(&sp);
        srtp_policy_set_profile(sp, srtp_profile_aead_aes_128_gcm);
        srtp_policy_set_sec_serv(sp, sec_serv_conf_and_auth,
                                 sec_serv_conf_and_auth);
        srtp_policy_set_ssrc(sp, ssrc);
        srtp_policy_set_rcc_mode_tx_rate(sp, srtp_rcc_mode_3, 1);
        srtp_policy_set_window_size(sp, 128);
        srtp_policy_use_mki(sp, sizeof(mki_id));
        srtp_policy_add_key(sp, gcm_key, SRTP_AES_128_KEY_LEN,
                            gcm_key + SRTP_AES_128_KEY_LEN, SRTP_AEAD_SALT_LEN,
                            mki_id, sizeof(mki_id));
        srtp_policy_clone(sp, &rp);

        srtp_t snd, rcv;
        srtp_err_status_t cs = srtp_create(&snd, sp);
        srtp_err_status_t cr = srtp_create(&rcv, rp);
        int f = 0;
        if (cs || cr) {
            printf("  create with MKI failed: snd=%d rcv=%d\n", cs, cr);
            f = 1;
        } else {
            uint8_t pkt[256], enc[256], dec[256];
            size_t len = make_rtp(pkt, 42, "gcm mode3 mki payload");
            size_t enc_len = sizeof(enc);
            srtp_err_status_t s = srtp_protect(snd, pkt, len, enc, &enc_len, 0);
            if (s) {
                printf("  protect failed: %d\n", s);
                f = 1;
            }

            /* layout: header + cipher + GCM tag (16) + MKI (4) + ROC (4) */
            if (!f && enc_len != len + 16 + 4 + 4) {
                printf("  unexpected enc_len=%zu (exp=%zu)\n", enc_len,
                       len + 16 + 4 + 4);
                f = 1;
            }
            /* MKI must sit immediately before the trailing 4-octet ROC */
            if (!f && memcmp(enc + enc_len - 4 - 4, mki_id, 4) != 0) {
                printf("  MKI not found before ROC\n");
                f = 1;
            }
            size_t dec_len = sizeof(dec);
            if (!f) {
                s = srtp_unprotect(rcv, enc, enc_len, dec, &dec_len);
                if (s) {
                    printf("  unprotect failed: %d\n", s);
                    f = 1;
                } else if (dec_len != len || memcmp(dec, pkt, len)) {
                    printf("  payload mismatch\n");
                    f = 1;
                }
            }
        }
        printf("Test13 GCM mode3 with MKI (RFC 7714 field order): %s\n",
               f ? "FAIL" : "PASS");
        fails += f;
        if (!cs)
            srtp_dealloc(snd);
        if (!cr)
            srtp_dealloc(rcv);
    }
#endif /* GCM */

    srtp_shutdown();
    printf("\n%s\n", fails ? "SOME TESTS FAILED" : "ALL TESTS PASSED");
    return fails ? 1 : 0;
}
