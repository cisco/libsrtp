/*
 * rcc_test.c
 *
 * Unit tests for the RFC 4771 RCC (Roll-over Counter Carrying) integrity
 * transform support added to libSRTP.
 *
 * Modes 1 and 2 use the AES-CM + HMAC-SHA1 transform and work with any crypto
 * backend.  Mode 3 (RFC 4771 NULL-MAC carried over AES-GCM, RFC 7714) requires
 * a backend that provides AES-GCM; those tests are compiled only when GCM is
 * available (config.h defines GCM).
 *
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#elif defined(HAVE_WINSOCK2_H)
#include <winsock2.h>
#endif

#include "cutest.h"

#include "srtp.h"
#include "util.h"

#include <string.h>

#define TEST_SSRC 0xcafebabe

static const uint8_t cm_master_key[16] = {
    0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0,
    0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39,
};
static const uint8_t cm_master_salt[14] = {
    0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe,
    0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6,
};

#ifdef GCM
static const uint8_t gcm_master_key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};
static const uint8_t gcm_master_salt[12] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
};

static const uint8_t mki4[4] = { 0xde, 0xad, 0xbe, 0xef };
#endif

static void create_cm_rcc_policy_ssrc(srtp_policy_t *policy,
                                      srtp_rcc_mode_t mode,
                                      uint16_t rate,
                                      srtp_ssrc_type_t ssrc_type)
{
    CHECK_OK(srtp_policy_create(policy));
    CHECK_OK(srtp_policy_set_profile(*policy, srtp_profile_aes128_cm_sha1_80));
    CHECK_OK(srtp_policy_set_sec_serv(*policy, sec_serv_conf_and_auth,
                                      sec_serv_conf_and_auth));
    CHECK_OK(
        srtp_policy_set_ssrc(*policy, (srtp_ssrc_t){ ssrc_type, TEST_SSRC }));
    CHECK_OK(srtp_policy_set_rcc_mode_tx_rate(*policy, mode, rate));
    CHECK_OK(srtp_policy_set_window_size(*policy, 128));
    CHECK_OK(srtp_policy_add_key(*policy, cm_master_key, sizeof(cm_master_key),
                                 cm_master_salt, sizeof(cm_master_salt), NULL,
                                 0));
}

static void create_cm_rcc_policy(srtp_policy_t *policy,
                                 srtp_rcc_mode_t mode,
                                 uint16_t rate)
{
    create_cm_rcc_policy_ssrc(policy, mode, rate, ssrc_specific);
}

static void create_cm_rcc_policy_mki(srtp_policy_t *policy,
                                     srtp_rcc_mode_t mode,
                                     uint16_t rate)
{
    CHECK_OK(srtp_policy_create(policy));
    CHECK_OK(srtp_policy_set_profile(*policy, srtp_profile_aes128_cm_sha1_80));
    CHECK_OK(srtp_policy_set_sec_serv(*policy, sec_serv_conf_and_auth,
                                      sec_serv_conf_and_auth));
    CHECK_OK(srtp_policy_set_ssrc(*policy,
                                  (srtp_ssrc_t){ ssrc_specific, TEST_SSRC }));
    CHECK_OK(srtp_policy_set_rcc_mode_tx_rate(*policy, mode, rate));
    CHECK_OK(srtp_policy_set_window_size(*policy, 128));
    CHECK_OK(srtp_policy_use_mki(*policy, sizeof(mki4)));
    CHECK_OK(srtp_policy_add_key(*policy, cm_master_key, sizeof(cm_master_key),
                                 cm_master_salt, sizeof(cm_master_salt), mki4,
                                 sizeof(mki4)));
}

#ifdef GCM
static void create_gcm_rcc_policy_ssrc(srtp_policy_t *policy,
                                       srtp_rcc_mode_t mode,
                                       uint16_t rate,
                                       srtp_ssrc_type_t ssrc_type)
{
    CHECK_OK(srtp_policy_create(policy));
    CHECK_OK(srtp_policy_set_profile(*policy, srtp_profile_aead_aes_128_gcm));
    CHECK_OK(srtp_policy_set_sec_serv(*policy, sec_serv_conf_and_auth,
                                      sec_serv_conf_and_auth));
    CHECK_OK(
        srtp_policy_set_ssrc(*policy, (srtp_ssrc_t){ ssrc_type, TEST_SSRC }));
    CHECK_OK(srtp_policy_set_rcc_mode_tx_rate(*policy, mode, rate));
    CHECK_OK(srtp_policy_set_window_size(*policy, 128));
    CHECK_OK(srtp_policy_add_key(*policy, gcm_master_key,
                                 sizeof(gcm_master_key), gcm_master_salt,
                                 sizeof(gcm_master_salt), NULL, 0));
}

static void create_gcm_rcc_policy(srtp_policy_t *policy,
                                  srtp_rcc_mode_t mode,
                                  uint16_t rate)
{
    create_gcm_rcc_policy_ssrc(policy, mode, rate, ssrc_specific);
}
#endif

/* build an RTP packet with the given sequence number and a fixed payload */
static size_t make_rtp(uint8_t *buf, uint16_t seq, const char *payload)
{
    uint16_t nseq = htons(seq);
    uint32_t ts = htonl(0x1234);
    uint32_t ssrc = htonl(TEST_SSRC);
    size_t plen = strlen(payload);

    buf[0] = 0x80; /* V=2 */
    buf[1] = 0x00; /* PT=0 */
    memcpy(buf + 2, &nseq, 2);
    memcpy(buf + 4, &ts, 4);
    memcpy(buf + 8, &ssrc, 4);
    memcpy(buf + 12, payload, plen);

    return 12 + plen;
}

static void rcc_roundtrip(srtp_t snd, srtp_t rcv, uint16_t seq, const char *msg)
{
    uint8_t pkt[256], enc[256], dec[256];
    size_t len = make_rtp(pkt, seq, msg);
    size_t enc_len = sizeof(enc);
    size_t dec_len = sizeof(dec);

    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    CHECK(dec_len == len);
    CHECK_BUFFER_EQUAL(dec, pkt, len);
}

/*
 * Protect a packet on policy, then try to unprotect it on the same session.
 * After srtp_protect() the stream is a sender, so unprotect must report an
 * SSRC collision rather than decrypting the packet.
 */
static void rcc_sender_must_reject_unprotect(srtp_policy_t policy, uint16_t seq)
{
    srtp_t sess;
    uint8_t pkt[256], enc[256], dec[256];
    size_t len, enc_len, dec_len;

    CHECK_OK(srtp_create(&sess, policy));
    len = make_rtp(pkt, seq, "sender unprotect");
    enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(sess, pkt, len, enc, &enc_len, 0));
    dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect(sess, enc, enc_len, dec, &dec_len),
                 srtp_err_status_direction_mismatch);
    CHECK_OK(srtp_dealloc(sess));
}

/* advance the sender's ROC to 1 by walking the sequence number past a wrap */
static void advance_sender_roc(srtp_t snd)
{
    uint8_t pkt[256], enc[256];
    uint32_t roc = 0;

    for (uint32_t i = 0; i < 70000; i += 4096) {
        size_t len = make_rtp(pkt, (uint16_t)i, "x");
        size_t enc_len = sizeof(enc);
        CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    }
    CHECK_OK(srtp_stream_get_roc(snd, TEST_SSRC, &roc));
    CHECK(roc == 1);
}

/*
 * policy-level validation
 */

/*
 * The transmission rate R selects which packets carry the ROC (those whose
 * sequence number is 0 modulo R), so R == 0 is meaningless once RCC is
 * enabled.  srtp_policy_set_rcc_mode_tx_rate() must therefore accept R == 0
 * only for srtp_rcc_mode_none and reject it for every active mode, while a
 * rate of 1 remains valid for any mode.
 */
static void rcc_set_mode_rejects_zero_rate(void)
{
    srtp_policy_t policy;
    CHECK_OK(srtp_policy_create(&policy));

    /* rate 0 is only meaningful when RCC is disabled */
    CHECK_OK(srtp_policy_set_rcc_mode_tx_rate(policy, srtp_rcc_mode_none, 0));
    CHECK_RETURN(srtp_policy_set_rcc_mode_tx_rate(policy, srtp_rcc_mode_1, 0),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_rcc_mode_tx_rate(policy, srtp_rcc_mode_2, 0),
                 srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_rcc_mode_tx_rate(policy, srtp_rcc_mode_3, 0),
                 srtp_err_status_bad_param);
    CHECK_OK(srtp_policy_set_rcc_mode_tx_rate(policy, srtp_rcc_mode_2, 1));

    srtp_policy_destroy(policy);
}

/*
 * Only the four enumerated RCC modes are valid.  An out-of-range mode value
 * and a NULL policy handle must both be rejected with bad_param.
 */
static void rcc_set_mode_rejects_invalid_mode(void)
{
    srtp_policy_t policy;
    CHECK_OK(srtp_policy_create(&policy));
    CHECK_RETURN(
        srtp_policy_set_rcc_mode_tx_rate(policy, (srtp_rcc_mode_t)99, 1),
        srtp_err_status_bad_param);
    CHECK_RETURN(srtp_policy_set_rcc_mode_tx_rate(NULL, srtp_rcc_mode_1, 1),
                 srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
}

/*
 * Modes 1 and 2 embed the ROC inside a truncated HMAC-SHA1 tag and are defined
 * only for the AES-CM ciphers, not for AEAD/GCM.  srtp_policy_validate() must
 * accept them with an AES-CM profile and reject them with a GCM profile.  The
 * cipher/mode consistency is checked by validate() rather than by the setter
 * because the profile may be assigned after the mode.
 */
static void rcc_validate_modes_1_2_require_aes_cm(void)
{
    srtp_policy_t policy;

    create_cm_rcc_policy(&policy, srtp_rcc_mode_1, 1);
    CHECK_OK(srtp_policy_validate(policy));
    srtp_policy_destroy(policy);

    create_cm_rcc_policy(&policy, srtp_rcc_mode_2, 1);
    CHECK_OK(srtp_policy_validate(policy));
    srtp_policy_destroy(policy);

#ifdef GCM
    /* modes 1 and 2 are not defined for AEAD/GCM */
    create_gcm_rcc_policy(&policy, srtp_rcc_mode_1, 1);
    CHECK_RETURN(srtp_policy_validate(policy), srtp_err_status_bad_param);
    srtp_policy_destroy(policy);

    create_gcm_rcc_policy(&policy, srtp_rcc_mode_2, 1);
    CHECK_RETURN(srtp_policy_validate(policy), srtp_err_status_bad_param);
    srtp_policy_destroy(policy);
#endif
}

/*
 * Mode 3 is the RFC 4771 NULL-MAC variant carried over AES-GCM (RFC 7714); it
 * has no MAC of its own, so it is only meaningful with an AEAD/GCM profile.
 * srtp_policy_validate() must reject it with an AES-CM profile and accept it
 * with a GCM profile.
 */
static void rcc_validate_mode3_requires_gcm(void)
{
    srtp_policy_t policy;

    /* mode 3 (NULL-MAC) is only defined over AES-GCM */
    create_cm_rcc_policy(&policy, srtp_rcc_mode_3, 1);
    CHECK_RETURN(srtp_policy_validate(policy), srtp_err_status_bad_param);
    srtp_policy_destroy(policy);

#ifdef GCM
    create_gcm_rcc_policy(&policy, srtp_rcc_mode_3, 1);
    CHECK_OK(srtp_policy_validate(policy));
    srtp_policy_destroy(policy);
#endif
}

/*
 * AES-CM round trips (modes 1 and 2)
 */

/*
 * Mode 2, R == 1: every packet carries the ROC (TAG = ROC || MAC_tr), so this
 * exercises the ROC-carrying path exclusively, over a long run of sequential
 * packets.  The complementary case, where only some packets carry the ROC and
 * the rest fall back to the default full-length MAC, is covered by the R == 4
 * test below.  All packets must decrypt back to the original payload.
 */
static void rcc_mode2_rate1_roundtrip(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_2, 1);
    create_cm_rcc_policy(&rp, srtp_rcc_mode_2, 1);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    for (uint16_t seq = 1; seq <= 50; seq++) {
        rcc_roundtrip(snd, rcv, seq, "hello world");
    }

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 1, R == 1: every packet carries the ROC (TAG = ROC || MAC_tr), so all
 * packets are authenticated.  This exercises the mode 1 carry path
 * exclusively; the distinctive mode 1 behaviour where non-carry packets are
 * sent completely untagged (no authentication) is covered by the R == 4 test
 * below.  All packets must round trip.
 */
static void rcc_mode1_rate1_roundtrip(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_1, 1);
    create_cm_rcc_policy(&rp, srtp_rcc_mode_1, 1);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    for (uint16_t seq = 1; seq <= 50; seq++) {
        rcc_roundtrip(snd, rcv, seq, "mode one data");
    }

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 2, R == 4: this is the mode 2 test that exercises the non-carry branch.
 * Walking a contiguous run starting at sequence number 0 hits both packet
 * types: packets with seq % 4 == 0 carry the ROC (a constant-length tag),
 * while the other three out of four use the default full-length MAC computed
 * over the locally maintained ROC.  All must round trip.
 */
static void rcc_mode2_rate4_carry_and_noncarry(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_2, 4);
    create_cm_rcc_policy(&rp, srtp_rcc_mode_2, 4);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    /* seq % 4 == 0 carries the ROC; the rest use the default full-length MAC */
    for (uint16_t seq = 0; seq <= 12; seq++) {
        rcc_roundtrip(snd, rcv, seq, "mode2 rate4 payload");
    }

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 1, R == 4: this is the mode 1 test that exercises the untagged branch.
 * Carry packets (seq % 4 == 0) get TAG = ROC || MAC_tr, while the other three
 * out of four carry no tag at all (variable packet length, no authentication).
 * Both kinds must round trip.
 */
static void rcc_mode1_rate4_carry_and_untagged(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_1, 4);
    create_cm_rcc_policy(&rp, srtp_rcc_mode_1, 4);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    /* carry packets get TAG = ROC || MAC_tr; other packets carry no tag */
    for (uint16_t seq = 0; seq <= 12; seq++) {
        rcc_roundtrip(snd, rcv, seq, "mode1 rate4 payload");
    }

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 1, R == 4, with an MKI.  A packet that does not carry the ROC has no
 * authentication tag, so the MKI is its last field; the receiver must locate
 * it there rather than a tag length before the end.
 */
static void rcc_mode1_rate4_mki_untagged(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy_mki(&sp, srtp_rcc_mode_1, 4);
    create_cm_rcc_policy_mki(&rp, srtp_rcc_mode_1, 4);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    for (uint16_t seq = 0; seq <= 12; seq++) {
        rcc_roundtrip(snd, rcv, seq, "mode1 rate4 mki payload");
    }

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 2, R == 1, late-joining receiver.  The sender first wraps its sequence
 * number past 65535 so its ROC becomes 1.  A brand-new receiver (ROC 0) then
 * joins: because every packet carries the ROC at R == 1, the very first
 * packet it sees must let it adopt the sender's ROC (RFC 4771 fast
 * resynchronization) and decrypt successfully.
 */
static void rcc_mode2_late_join_roc_sync(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[256], enc[256], dec[256];
    size_t len, enc_len, dec_len;
    uint32_t sender_roc = 0, receiver_roc = 0;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_2, 1);
    CHECK_OK(srtp_create(&snd, sp));

    /* push the sender's ROC to 1 */
    advance_sender_roc(snd);
    CHECK_OK(srtp_stream_get_roc(snd, TEST_SSRC, &sender_roc));

    /* a fresh receiver must synchronize via the in-band ROC (R == 1) */
    create_cm_rcc_policy(&rp, srtp_rcc_mode_2, 1);
    CHECK_OK(srtp_create(&rcv, rp));

    len = make_rtp(pkt, 5000, "late join payload");
    enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    CHECK(dec_len == len);
    CHECK_BUFFER_EQUAL(dec, pkt, len);

    CHECK_OK(srtp_stream_get_roc(rcv, TEST_SSRC, &receiver_roc));
    CHECK(receiver_roc == sender_roc);

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 2, R == 4, late-joining receiver.  The sender advances its ROC to 1
 * (the ROC advances on the sequence-number wrap regardless of whether packets
 * are ROC-carrying, so the shared helper's plain sequential walk is enough).
 * A fresh receiver then joins and receives a ROC-carrying packet (seq 5000,
 * and 5000 % 4 == 0), which must resynchronize it to the sender's ROC.
 */
static void rcc_mode2_rate4_late_join(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[256], enc[256], dec[256];
    size_t len, enc_len, dec_len;
    uint32_t sender_roc = 0, receiver_roc = 0;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_2, 4);
    CHECK_OK(srtp_create(&snd, sp));

    /* push the sender's ROC to 1 */
    advance_sender_roc(snd);
    CHECK_OK(srtp_stream_get_roc(snd, TEST_SSRC, &sender_roc));

    create_cm_rcc_policy(&rp, srtp_rcc_mode_2, 4);
    CHECK_OK(srtp_create(&rcv, rp));

    /*
     * 5000 % 4 == 0, so this is a ROC-carrying packet: the fresh receiver must
     * adopt the sender's ROC from it (RFC 4771 fast resynchronization).
     */
    len = make_rtp(pkt, 5000, "late join r4 payload");
    enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    CHECK(dec_len == len);
    CHECK_BUFFER_EQUAL(dec, pkt, len);

    CHECK_OK(srtp_stream_get_roc(rcv, TEST_SSRC, &receiver_roc));
    CHECK(receiver_roc == sender_roc);

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 2, R == 1, receiver using a wildcard ssrc_any_inbound policy.  The
 * receiver has no stream for the SSRC yet, so the first packet is processed
 * against the provisional template stream; the RCC transform must still be
 * applied there (the tag is ROC || MAC_tr, not a plain MAC) and, once it
 * authenticates, the template must be instantiated into a real stream that
 * has adopted the sender's ROC.  The sender's ROC is advanced past a wrap
 * first, so a receiver that fell back to the default transform (assuming
 * ROC 0) would fail authentication.
 */
static void rcc_mode2_wildcard_inbound_late_join(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[256], enc[256], dec[256];
    size_t len, enc_len, dec_len;
    uint32_t sender_roc = 0, receiver_roc = 0;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_2, 1);
    CHECK_OK(srtp_create(&snd, sp));

    advance_sender_roc(snd);
    CHECK_OK(srtp_stream_get_roc(snd, TEST_SSRC, &sender_roc));

    create_cm_rcc_policy_ssrc(&rp, srtp_rcc_mode_2, 1, ssrc_any_inbound);
    CHECK_OK(srtp_create(&rcv, rp));

    len = make_rtp(pkt, 5000, "wildcard inbound payload");
    enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    CHECK(dec_len == len);
    CHECK_BUFFER_EQUAL(dec, pkt, len);

    /* the template must have been instantiated with the sender's ROC */
    CHECK_OK(srtp_stream_get_roc(rcv, TEST_SSRC, &receiver_roc));
    CHECK(receiver_roc == sender_roc);

    /* subsequent packets are handled by the newly created stream */
    rcc_roundtrip(snd, rcv, 5001, "wildcard inbound follow up");

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 1, R == 4, receiver using a wildcard ssrc_any_inbound policy.  Mode 1
 * sends non-carry packets with no authentication tag at all, so the template
 * stream must go through the RCC transform to parse them correctly.  Starting
 * at seq 0 exercises both the carry and the untagged packet through the
 * provisional stream.
 */
static void rcc_mode1_wildcard_inbound(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_1, 4);
    CHECK_OK(srtp_create(&snd, sp));
    create_cm_rcc_policy_ssrc(&rp, srtp_rcc_mode_1, 4, ssrc_any_inbound);
    CHECK_OK(srtp_create(&rcv, rp));

    for (uint16_t seq = 0; seq <= 8; seq++) {
        rcc_roundtrip(snd, rcv, seq, "wildcard inbound mode1");
    }

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 2, R == 1: a ROC-carrying packet must not bypass replay detection.
 * Every packet carries the ROC here, so replaying one that was already
 * accepted has to be rejected rather than silently resetting the replay
 * window (which would then let the whole tail of the stream be replayed).
 */
static void rcc_mode2_carry_replay_rejected(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[256], enc[256], saved[256], dec[256];
    size_t len, enc_len, saved_len = 0, dec_len;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_2, 1);
    create_cm_rcc_policy(&rp, srtp_rcc_mode_2, 1);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    /* keep a copy of the packet with seq 3 as it goes over the wire */
    for (uint16_t seq = 1; seq <= 5; seq++) {
        len = make_rtp(pkt, seq, "replay me");
        enc_len = sizeof(enc);
        CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
        if (seq == 3) {
            memcpy(saved, enc, enc_len);
            saved_len = enc_len;
        }
        dec_len = sizeof(dec);
        CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    }

    dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect(rcv, saved, saved_len, dec, &dec_len),
                 srtp_err_status_replay_fail);

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 2, R == 1: a ROC-carrying packet that is new but falls inside the
 * currently tracked window must only mark itself in the window, not reset it.
 * Delivering 10, then the still-missing 8 and 9, must all succeed, and a
 * second copy of 8 must then be rejected -- which only holds if accepting 8
 * and 9 left the window (and the already-set bits) intact.
 */
static void rcc_mode2_carry_out_of_order_keeps_window(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[3][256], enc[3][256], dec[256];
    size_t len[3], enc_len[3], dec_len;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&sp, srtp_rcc_mode_2, 1);
    create_cm_rcc_policy(&rp, srtp_rcc_mode_2, 1);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    for (uint16_t i = 0; i < 3; i++) {
        len[i] = make_rtp(pkt[i], (uint16_t)(8 + i), "out of order");
        enc_len[i] = sizeof(enc[i]);
        CHECK_OK(srtp_protect(snd, pkt[i], len[i], enc[i], &enc_len[i], 0));
    }

    /* deliver 10 first, then the earlier 8 and 9 that are still in flight */
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc[2], enc_len[2], dec, &dec_len));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc[0], enc_len[0], dec, &dec_len));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc[1], enc_len[1], dec, &dec_len));

    /* the window must have been updated, not reset, so 8 is now a replay */
    dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect(rcv, enc[0], enc_len[0], dec, &dec_len),
                 srtp_err_status_replay_fail);

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * An RCC-enabled sender stream must still reject unprotect as an SSRC
 * collision.  ROC-carrying packets (and every mode-3 packet) used to skip
 * that check because their index is estimated later.
 */
static void rcc_mode2_sender_rejects_unprotect(void)
{
    srtp_policy_t p;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&p, srtp_rcc_mode_2, 1);
    /* R == 1: every packet carries the ROC */
    rcc_sender_must_reject_unprotect(p, 4);
    srtp_policy_destroy(p);
    CHECK_OK(srtp_shutdown());
}

static void rcc_mode1_sender_rejects_unprotect(void)
{
    srtp_policy_t p;

    CHECK_OK(srtp_init());
    create_cm_rcc_policy(&p, srtp_rcc_mode_1, 4);
    /* seq 0 is ROC-carrying; seq 1 is untagged.  Both must collide. */
    rcc_sender_must_reject_unprotect(p, 0);
    rcc_sender_must_reject_unprotect(p, 1);
    srtp_policy_destroy(p);
    CHECK_OK(srtp_shutdown());
}

#ifdef GCM
/*
 * AES-GCM round trips (mode 3, RFC 7714 layout)
 */

/*
 * Modes 1 and 2 embed the ROC in a truncated HMAC and are not defined for
 * AEAD/GCM.  Setting mode 2 on a GCM policy succeeds (the setter does not know
 * the cipher yet), but srtp_create() validates the policy and must reject the
 * GCM/mode-2 combination.  (Mode 3 over GCM is the supported pairing and is
 * exercised by the tests below.)
 */
static void rcc_gcm_mode2_rejected_at_create(void)
{
    srtp_policy_t p;
    srtp_t s;

    CHECK_OK(srtp_init());
    /* setting the mode succeeds; the GCM/mode-2 conflict is caught at create */
    create_gcm_rcc_policy(&p, srtp_rcc_mode_2, 1);
    CHECK_RETURN(srtp_create(&s, p), srtp_err_status_bad_param);
    srtp_policy_destroy(p);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 3, R == 1: every packet carries the 4-octet ROC in the SRTP
 * authentication tag field (RFC 7714 section 8.2).  A basic round trip over
 * several packets must succeed.
 */
static void rcc_gcm_mode3_basic_roundtrip(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    CHECK_OK(srtp_init());
    create_gcm_rcc_policy(&sp, srtp_rcc_mode_3, 1);
    create_gcm_rcc_policy(&rp, srtp_rcc_mode_3, 1);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    for (uint16_t seq = 1; seq <= 5; seq++) {
        rcc_roundtrip(snd, rcv, seq, "gcm mode3 payload");
    }

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 3, R == 4: only packets with seq % 4 == 0 carry the 4-octet ROC as the
 * last field of the packet; the others are plain RFC 7714 GCM packets.  Both
 * packet types must round trip.
 */
static void rcc_gcm_mode3_rate4(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;

    CHECK_OK(srtp_init());
    create_gcm_rcc_policy(&sp, srtp_rcc_mode_3, 4);
    create_gcm_rcc_policy(&rp, srtp_rcc_mode_3, 4);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    /* seq % 4 == 0 carries the trailing ROC; others are plain RFC 7714 */
    for (uint16_t seq = 0; seq <= 12; seq++) {
        rcc_roundtrip(snd, rcv, seq, "gcm mode3 rate4 payload");
    }

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 3: verify the on-the-wire field order and late-join resynchronization.
 * After advancing the sender's ROC to 1, a protected packet must have the
 * layout header + ciphertext + 16-octet GCM tag + 4-octet ROC, with the
 * trailing four octets carrying the sender's ROC in network order (RFC 7714
 * section 8.2).  A fresh receiver must then adopt that in-band ROC and decrypt
 * the packet successfully.
 */
static void rcc_gcm_mode3_roc_after_tag_and_late_join(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[256], enc[256], dec[256];
    size_t len, enc_len, dec_len;
    uint32_t sender_roc = 0, receiver_roc = 0, carried = 0;

    CHECK_OK(srtp_init());
    create_gcm_rcc_policy(&sp, srtp_rcc_mode_3, 1);
    CHECK_OK(srtp_create(&snd, sp));

    advance_sender_roc(snd);
    CHECK_OK(srtp_stream_get_roc(snd, TEST_SSRC, &sender_roc));

    len = make_rtp(pkt, 5000, "gcm late join");
    enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));

    /*
     * expected layout (no MKI): header + ciphertext + 16-octet GCM tag +
     * 4-octet ROC.  The trailing four octets are the SRTP authentication tag
     * field carrying the sender's ROC in network order (RFC 7714 section 8.2).
     */
    CHECK(enc_len == len + 16 + 4);
    memcpy(&carried, enc + enc_len - 4, 4);
    carried = ntohl(carried);
    CHECK(carried == sender_roc);

    /* a fresh receiver must synchronize via the in-band ROC */
    create_gcm_rcc_policy(&rp, srtp_rcc_mode_3, 1);
    CHECK_OK(srtp_create(&rcv, rp));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    CHECK(dec_len == len);
    CHECK_BUFFER_EQUAL(dec, pkt, len);

    CHECK_OK(srtp_stream_get_roc(rcv, TEST_SSRC, &receiver_roc));
    CHECK(receiver_roc == sender_roc);

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 3: the carried ROC is implicitly authenticated because it feeds the GCM
 * IV.  Flipping a bit in the trailing ROC yields a wrong IV, so GCM tag
 * verification must fail and srtp_unprotect() must return auth_fail.
 */
static void rcc_gcm_mode3_roc_tamper_detected(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[256], enc[256], dec[256];
    size_t len, enc_len, dec_len;

    CHECK_OK(srtp_init());
    create_gcm_rcc_policy(&sp, srtp_rcc_mode_3, 1);
    create_gcm_rcc_policy(&rp, srtp_rcc_mode_3, 1);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    len = make_rtp(pkt, 100, "tamper test");
    enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));

    /*
     * flip a bit in the carried ROC (last 4 octets).  The ROC feeds the GCM
     * IV, so a tampered ROC yields a wrong IV and GCM tag verification fails.
     */
    enc[enc_len - 1] ^= 0x01;

    dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len),
                 srtp_err_status_auth_fail);

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 3 with MKI: verify the RFC 7714 section 8.2 field order, which places
 * the ROC after the optional MKI: header + ciphertext (incl. GCM tag) + MKI +
 * 4-octet ROC.  Even though the ROC follows the MKI, the receiver must still
 * locate the MKI correctly and the packet must round trip.
 */
static void rcc_gcm_mode3_with_mki_field_order(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[256], enc[256], dec[256];
    size_t len, enc_len, dec_len;

    CHECK_OK(srtp_init());

    CHECK_OK(srtp_policy_create(&sp));
    CHECK_OK(srtp_policy_set_profile(sp, srtp_profile_aead_aes_128_gcm));
    CHECK_OK(srtp_policy_set_sec_serv(sp, sec_serv_conf_and_auth,
                                      sec_serv_conf_and_auth));
    CHECK_OK(
        srtp_policy_set_ssrc(sp, (srtp_ssrc_t){ ssrc_specific, TEST_SSRC }));
    CHECK_OK(srtp_policy_set_rcc_mode_tx_rate(sp, srtp_rcc_mode_3, 1));
    CHECK_OK(srtp_policy_set_window_size(sp, 128));
    CHECK_OK(srtp_policy_use_mki(sp, sizeof(mki4)));
    CHECK_OK(srtp_policy_add_key(sp, gcm_master_key, sizeof(gcm_master_key),
                                 gcm_master_salt, sizeof(gcm_master_salt), mki4,
                                 sizeof(mki4)));
    CHECK_OK(srtp_policy_clone(sp, &rp));

    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    len = make_rtp(pkt, 42, "gcm mode3 mki payload");
    enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));

    /* layout: header + ciphertext + GCM tag (16) + MKI (4) + ROC (4) */
    CHECK(enc_len == len + 16 + 4 + 4);
    /* the MKI must sit immediately before the trailing 4-octet ROC */
    CHECK_BUFFER_EQUAL(enc + enc_len - 4 - 4, mki4, sizeof(mki4));

    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    CHECK(dec_len == len);
    CHECK_BUFFER_EQUAL(dec, pkt, len);

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 3, receiver using a wildcard ssrc_any_inbound policy.  The AEAD path
 * already instantiates the template once the GCM tag verifies; this pins that
 * behaviour so the provisional stream keeps adopting the carried ROC.
 */
static void rcc_gcm_mode3_wildcard_inbound_late_join(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[256], enc[256], dec[256];
    size_t len, enc_len, dec_len;
    uint32_t sender_roc = 0, receiver_roc = 0;

    CHECK_OK(srtp_init());
    create_gcm_rcc_policy(&sp, srtp_rcc_mode_3, 1);
    CHECK_OK(srtp_create(&snd, sp));

    advance_sender_roc(snd);
    CHECK_OK(srtp_stream_get_roc(snd, TEST_SSRC, &sender_roc));

    create_gcm_rcc_policy_ssrc(&rp, srtp_rcc_mode_3, 1, ssrc_any_inbound);
    CHECK_OK(srtp_create(&rcv, rp));

    len = make_rtp(pkt, 5000, "gcm wildcard inbound");
    enc_len = sizeof(enc);
    CHECK_OK(srtp_protect(snd, pkt, len, enc, &enc_len, 0));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc, enc_len, dec, &dec_len));
    CHECK(dec_len == len);
    CHECK_BUFFER_EQUAL(dec, pkt, len);

    /* the template must have been instantiated with the sender's ROC */
    CHECK_OK(srtp_stream_get_roc(rcv, TEST_SSRC, &receiver_roc));
    CHECK(receiver_roc == sender_roc);

    /* subsequent packets are handled by the newly created stream */
    rcc_roundtrip(snd, rcv, 5001, "gcm wildcard follow up");

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

/*
 * Mode 3, R == 1: the trailing carried ROC must not bypass replay detection
 * either.  A replayed ROC-carrying packet has to be rejected, and an
 * out-of-order but still unseen packet must update the window rather than
 * reset it.
 */
static void rcc_gcm_mode3_carry_replay_rejected(void)
{
    srtp_policy_t sp, rp;
    srtp_t snd, rcv;
    uint8_t pkt[3][256], enc[3][256], dec[256];
    size_t len[3], enc_len[3], dec_len;

    CHECK_OK(srtp_init());
    create_gcm_rcc_policy(&sp, srtp_rcc_mode_3, 1);
    create_gcm_rcc_policy(&rp, srtp_rcc_mode_3, 1);
    CHECK_OK(srtp_create(&snd, sp));
    CHECK_OK(srtp_create(&rcv, rp));

    for (uint16_t i = 0; i < 3; i++) {
        len[i] = make_rtp(pkt[i], (uint16_t)(8 + i), "gcm replay");
        enc_len[i] = sizeof(enc[i]);
        CHECK_OK(srtp_protect(snd, pkt[i], len[i], enc[i], &enc_len[i], 0));
    }

    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc[2], enc_len[2], dec, &dec_len));
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc[0], enc_len[0], dec, &dec_len));

    /* replaying the packet just accepted must fail */
    dec_len = sizeof(dec);
    CHECK_RETURN(srtp_unprotect(rcv, enc[0], enc_len[0], dec, &dec_len),
                 srtp_err_status_replay_fail);

    /* the still-unseen 9 must remain acceptable */
    dec_len = sizeof(dec);
    CHECK_OK(srtp_unprotect(rcv, enc[1], enc_len[1], dec, &dec_len));

    CHECK_OK(srtp_dealloc(snd));
    CHECK_OK(srtp_dealloc(rcv));
    srtp_policy_destroy(sp);
    srtp_policy_destroy(rp);
    CHECK_OK(srtp_shutdown());
}

static void rcc_gcm_mode3_sender_rejects_unprotect(void)
{
    srtp_policy_t p;

    CHECK_OK(srtp_init());
    create_gcm_rcc_policy(&p, srtp_rcc_mode_3, 4);
    /* seq 0 carries the ROC; seq 1 does not.  Mode 3 skipped the check on
     * both. */
    rcc_sender_must_reject_unprotect(p, 0);
    rcc_sender_must_reject_unprotect(p, 1);
    srtp_policy_destroy(p);
    CHECK_OK(srtp_shutdown());
}
#endif /* GCM */

TEST_LIST = {
    { "rcc_set_mode_rejects_zero_rate()", rcc_set_mode_rejects_zero_rate },
    { "rcc_set_mode_rejects_invalid_mode()",
      rcc_set_mode_rejects_invalid_mode },
    { "rcc_validate_modes_1_2_require_aes_cm()",
      rcc_validate_modes_1_2_require_aes_cm },
    { "rcc_validate_mode3_requires_gcm()", rcc_validate_mode3_requires_gcm },
    { "rcc_mode2_rate1_roundtrip()", rcc_mode2_rate1_roundtrip },
    { "rcc_mode1_rate1_roundtrip()", rcc_mode1_rate1_roundtrip },
    { "rcc_mode2_rate4_carry_and_noncarry()",
      rcc_mode2_rate4_carry_and_noncarry },
    { "rcc_mode1_rate4_carry_and_untagged()",
      rcc_mode1_rate4_carry_and_untagged },
    { "rcc_mode1_rate4_mki_untagged()", rcc_mode1_rate4_mki_untagged },
    { "rcc_mode2_late_join_roc_sync()", rcc_mode2_late_join_roc_sync },
    { "rcc_mode2_rate4_late_join()", rcc_mode2_rate4_late_join },
    { "rcc_mode2_wildcard_inbound_late_join()",
      rcc_mode2_wildcard_inbound_late_join },
    { "rcc_mode1_wildcard_inbound()", rcc_mode1_wildcard_inbound },
    { "rcc_mode2_carry_replay_rejected()", rcc_mode2_carry_replay_rejected },
    { "rcc_mode2_carry_out_of_order_keeps_window()",
      rcc_mode2_carry_out_of_order_keeps_window },
    { "rcc_mode2_sender_rejects_unprotect()",
      rcc_mode2_sender_rejects_unprotect },
    { "rcc_mode1_sender_rejects_unprotect()",
      rcc_mode1_sender_rejects_unprotect },
#ifdef GCM
    { "rcc_gcm_mode2_rejected_at_create()", rcc_gcm_mode2_rejected_at_create },
    { "rcc_gcm_mode3_basic_roundtrip()", rcc_gcm_mode3_basic_roundtrip },
    { "rcc_gcm_mode3_rate4()", rcc_gcm_mode3_rate4 },
    { "rcc_gcm_mode3_roc_after_tag_and_late_join()",
      rcc_gcm_mode3_roc_after_tag_and_late_join },
    { "rcc_gcm_mode3_roc_tamper_detected()",
      rcc_gcm_mode3_roc_tamper_detected },
    { "rcc_gcm_mode3_with_mki_field_order()",
      rcc_gcm_mode3_with_mki_field_order },
    { "rcc_gcm_mode3_wildcard_inbound_late_join()",
      rcc_gcm_mode3_wildcard_inbound_late_join },
    { "rcc_gcm_mode3_carry_replay_rejected()",
      rcc_gcm_mode3_carry_replay_rejected },
    { "rcc_gcm_mode3_sender_rejects_unprotect()",
      rcc_gcm_mode3_sender_rejects_unprotect },
#endif
    { 0 }
};
