#!/usr/bin/python

import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

tag_size = 16
key_size = 16
nonce_size = 12
min_ohb_size = 1

# key, nonce, pt, aad -> ct, tag
def single_encrypt(key, nonce, pt, aad):
    cipher = AESGCM(key)
    ct_and_tag = cipher.encrypt(nonce, pt, aad)
    return ct_and_tag[:-tag_size], ct_and_tag[-tag_size:]

# key, nonce, ct, aad, tag -> pt
def single_decrypt(key, nonce, ct, aad, tag):
    cipher = AESGCM(key)
    pt = cipher.decrypt(nonce, ct + tag, aad)
    return pt

# double-key = e2e-key || hbh-key
def hbh(key_or_nonce):
    n = len(key_or_nonce) / 2
    return key_or_nonce[n:]

def e2e(key_or_nonce):
    n = len(key_or_nonce) / 2
    return key_or_nonce[:n]

# Config byte:
#
# +-+-+-+-+-+-+-+-+
# |R R R R B M P Q|
# +-+-+-+-+-+-+-+-+
#
# Q: SEQ is present
# P: PT is present
# M: Marker bit is present
# B: Value of marker bit
#
# OHB = PT? SEQ? config
OHB_FLAG_SEQ = (1 << 0)
OHB_FLAG_PT  = (1 << 1)
OHB_FLAG_M   = (1 << 2)
OHB_SHIFT_B  = 3

def ohb_size_from_config(config):
    size = 1
    byte = ord(config)
    if byte & OHB_FLAG_PT != 0:
        size += 1
    if byte & OHB_FLAG_SEQ != 0:
        size += 2
    return size

def apply_ohb(ohb, header):
    config = ord(ohb[-1])
    ohb_bytes = [ord(x) for x in ohb]
    header_bytes = [ord(x) for x in header]
    end = -1

    # Always truncate to remove extension and unset the X bit
    cc = header_bytes[0] & 0x0f 
    header_len = 12 + (4 * cc)
    header_bytes = header_bytes[:header_len]
    header_bytes[0] &= 0xef

    # SEQ
    if config & OHB_FLAG_SEQ != 0:
        header_bytes[2:4] = ohb_bytes[end-2:end]
        end -= 2

    # PT
    if config & OHB_FLAG_PT != 0:
        pt = ohb_bytes[end-1] & 0x7f
        header_bytes[1] = (header_bytes[1] & 0x80) | pt
        end -= 1

    # M
    if config & OHB_FLAG_M != 0:
        M = (config >> OHB_SHIFT_B) & 0x01
        header_bytes[1] = (header_bytes[1] & 0x7f) | (M << 7)

    return bytes(bytearray(header_bytes))

# Enc Dec
#  |   ^  |<---- Payload ---->|
#  |   |  |<---- CT_inner --->|<-- ITag -->|
#  |   |  |<---- CT_inner --->|<-- ITag -->|<--- OHB -->|
#  |   |  |<------------------ CT_outer --------------->|<-- OTag -->|
#  V   |  |<------------------ Payload ---------------->|<--- Tag -->|

def double_encrypt(key, nonce, payload, header_wire):
    ohb = b'\x00'
    header_inner = apply_ohb(ohb, header_wire)
    ct_inner, tag_inner = single_encrypt(e2e(key), nonce, payload, header_inner)

    pt_outer = ct_inner + tag_inner + ohb
    ct_outer, tag_outer = single_encrypt(hbh(key), nonce, pt_outer, header_wire)
  
    print "inner key:", e2e(key).encode("hex")
    print "outer key:", hbh(key).encode("hex")
    print "inner aad:", header_inner.encode("hex")
    print "inner ciphertext:", ct_inner.encode("hex")
    print "inner tag:", tag_inner.encode("hex")
    print "outer plaintext:", pt_outer.encode("hex")
    print "outer ciphertext:", (ct_outer + tag_outer).encode("hex")
    return ct_outer, tag_outer 

def double_decrypt(key, nonce, payload, header_wire, tag):
    pt_outer = single_decrypt(hbh(key), hbh(nonce), payload, header_wire, tag)
    
    ohb_size = ohb_size_from_config(pt_outer[-1])
    ct_inner = pt_outer[:-(tag_size + ohb_size)]
    tag_inner = pt_outer[-(tag_size + ohb_size):-ohb_size]
    ohb = pt_outer[-ohb_size:]

    header_original = apply_ohb(ohb, header_wire)
    pt_inner = single_decrypt(e2e(key), e2e(nonce), ct_inner, header_original, tag_inner)
    return pt_inner

payload = b"a secret message"
header = '80abcdef0001020310111213'.decode('hex')

def test(label, proposition):
    try:
        assert(proposition)
    except Exception as e:
        print "[FAIL] {}".format(label)
        raise e
    print "[PASS] {}".format(label)

# Single encryption test
def single_encryption_test():
    key = os.urandom(key_size) 
    nonce = os.urandom(nonce_size)
    ct, tag = single_encrypt(key, nonce, payload, header)
    payload_out =  single_decrypt(key, nonce, ct, header, tag)
    test("single encryption", payload_out == payload)

# Full double encryption test
def double_encryption_test():
    key2 = os.urandom(2 * key_size)
    nonce2 = os.urandom(2 * nonce_size)
    ct, tag = double_encrypt(key2, nonce2, payload, header)
    payload_out = double_decrypt(key2, nonce2, ct, header, tag)
    test("double encryption", payload_out == payload)

# Header modification test
def header_modification_test():
    key_full = os.urandom(2 * key_size)
    nonce_full = os.urandom(2 * nonce_size)
    key_half = hbh(key_full)
    nonce_half = hbh(nonce_full)
    header_original = '90abcdef0001020310111213bede0000'.decode('hex')
    header_modified = '900000000001020310111213bede000120213031'.decode('hex')
    ohb = '2bcdef0f'.decode('hex')

    # Sender encrypt
    ct0, tag0 = double_encrypt(key_full, nonce_full, payload, header_original)

    # MD decrypt / modify / encrypt
    pt1 = single_decrypt(key_half, nonce_half, ct0, header_original, tag0)
    ohb_size = ohb_size_from_config(pt1[-1])
    pt1 = pt1[:-ohb_size] + ohb
    ct2, tag2 = single_encrypt(key_half, nonce_half, pt1, header_modified)

    # Receiver decrypt
    pt3 = double_decrypt(key_full, nonce_full, ct2, header_modified, tag2)
    test("header modification", pt3 == payload)


def marshal_buffer(name, buf):
    out = "static const uint8_t {}[{}] = {{".format(name, len(buf))
    for i in range(len(buf)):
        if i % 8 == 0:
            out += "\n   "
        out += " 0x{:02x},".format(ord(buf[i]))

    if len(buf) % 8 != 0:
        out += "\n"
    out += "};\n"
    return out

def make_test_cases():
    key = ("482383ca8e4eb2eb86e03ed14c65bb81" + \
           "1ef806b01c412b2f69b2ec8c8da6de22" + \
           "0102030405060708090a0b0c").decode("hex")

    iv = "1d2b9710540a78009c84d2d9".decode("hex")

    # Header with extension
    aad = "90010203deadbeeffeedfacebede0002107f23a0a1a2a300".decode("hex")

    plaintext = ("d9313225f88406e5a55909c5aff5269a" + \
               "86a7a9531534f7da2e4c303d8a318a72" + \
               "1c3c0c95956809532fcf0e2449a6b525" + \
               "b16aedf5aa0de657ba637b39").decode("hex")

    ct, tag = double_encrypt(key[:32], iv, plaintext, aad)
    ciphertext = ct + tag

    print marshal_buffer("srtp_aes_gcm_double_test_case_128_key", key)
    print marshal_buffer("srtp_aes_gcm_double_test_case_iv", iv)
    print marshal_buffer("srtp_aes_gcm_double_test_case_aad", aad)
    print marshal_buffer("srtp_aes_gcm_double_test_case_plaintext", plaintext)
    print marshal_buffer("srtp_aes_gcm_double_test_case_128_ciphertext", ciphertext)
    print """static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_128 = {{
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,            /* octets in key            */
    srtp_aes_gcm_double_test_case_128_key,            /* key                      */
    srtp_aes_gcm_double_test_case_iv,                 /* packet index             */
    {},                                               /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_plaintext,          /* plaintext                */
    {},                                               /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_128_ciphertext,     /* ciphertext  + tag        */
    {},                                               /* octets in AAD            */
    srtp_aes_gcm_double_test_case_aad,                /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    NULL,                                             /* pointer to next testcase */
}};\n""".format(len(plaintext), len(ciphertext), len(aad))

    key = ("914808dcf7de7475d56714deea6a67d1" + \
           "f8349a84b30ebe829bb5e06a42694353" + \
           "01edaea4a13801fa5e7d639cc16771a3" + \
           "c2da09d5c27af705e1a2d6adab2c7132" + \
           "0102030405060708090a0b0c").decode("hex")

    ct, tag = double_encrypt(key[:64], iv, plaintext, aad)
    ciphertext = ct + tag

    print marshal_buffer("srtp_aes_gcm_double_test_case_256_key", key)
    print marshal_buffer("srtp_aes_gcm_double_test_case_256_ciphertext", ciphertext)
    print """
static const srtp_cipher_test_case_t srtp_aes_gcm_double_test_case_256 = {{
    SRTP_AES_GCM_128_DOUBLE_KEY_LEN_WSALT,            /* octets in key            */
    srtp_aes_gcm_double_test_case_256_key,            /* key                      */
    srtp_aes_gcm_double_test_case_iv,                 /* packet index             */
    {},                                               /* octets in plaintext      */
    srtp_aes_gcm_double_test_case_plaintext,          /* plaintext                */
    {},                                               /* octets in ciphertext     */
    srtp_aes_gcm_double_test_case_256_ciphertext,     /* ciphertext  + tag        */
    {},                                               /* octets in AAD            */
    srtp_aes_gcm_double_test_case_aad,                /* AAD                      */
    GCM_DOUBLE_AUTH_TAG_LEN,
    NULL,                                             /* pointer to next testcase */
}};\n""".format(len(plaintext), len(ciphertext), len(aad))

#single_encryption_test()
#double_encryption_test()
#header_modification_test()
make_test_cases()


