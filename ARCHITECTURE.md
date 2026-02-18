# libsrtp Architecture Overview

libsrtp is a C library implementing the Secure Real-time Transport Protocol (SRTP) as defined in RFC 3711, with extensions for AES-GCM (RFC 7714), header extension encryption (RFC 6904), and CRYPTEX. It provides packet-level encryption and authentication for RTP and RTCP traffic used in real-time communications (VoIP, video conferencing, etc.).

**Version**: 3.0.0 (libsrtp3)
**License**: BSD 2-Clause
**Language**: C99

---

## Repository Structure

```
libsrtp/
├── srtp/                  # Core SRTP implementation (1 file)
│   └── srtp.c             # All protect/unprotect logic, key derivation, stream mgmt (~5300 lines)
├── crypto/                # Cryptographic subsystem
│   ├── cipher/            # Cipher implementations (AES-ICM, AES-GCM, null)
│   ├── hash/              # Authentication implementations (HMAC-SHA1, null)
│   ├── kernel/            # Crypto kernel: registration, alloc, error handling, key limits
│   ├── replay/            # Replay attack protection (rdb, rdbx)
│   ├── math/              # Bit/byte utility operations
│   ├── include/           # Internal crypto headers
│   └── test/              # Crypto-level test drivers
├── include/               # Public API headers
│   ├── srtp.h             # Public API: types, policies, protect/unprotect functions
│   ├── srtp_priv.h        # Private: stream/session structures, RTP/RTCP header layouts
│   └── stream_list_priv.h # Stream list management
├── test/                  # Integration tests and reference applications
├── fuzzer/                # Fuzz testing harness
├── doc/                   # Doxygen documentation sources
├── cmake/                 # CMake modules
├── CMakeLists.txt         # CMake build (primary)
├── meson.build            # Meson build (alternative)
├── configure.ac           # Autotools build (legacy)
└── Makefile.in            # Autotools Makefile template
```

---

## Layered Architecture

The library is organized into three layers:

```
┌─────────────────────────────────────────────────┐
│              Application (User Code)             │
├─────────────────────────────────────────────────┤
│           SRTP Session Layer (srtp/srtp.c)       │
│  Sessions, Streams, Policies, Protect/Unprotect  │
├─────────────────────────────────────────────────┤
│        Crypto Kernel (crypto/kernel/)            │
│  Algorithm registry, allocation, self-testing    │
├──────────┬──────────┬───────────┬───────────────┤
│ Ciphers  │  Auth    │  Replay   │  Key Limits   │
│ AES-ICM  │ HMAC-SHA1│  rdb/rdbx │  Usage track  │
│ AES-GCM  │ Null     │           │               │
│ Null     │          │           │               │
├──────────┴──────────┴───────────┴───────────────┤
│        Crypto Backend (compile-time selected)    │
│  OpenSSL │ WolfSSL │ mbedTLS │ NSS │ Built-in   │
└─────────────────────────────────────────────────┘
```

---

## Core Data Model

### Session (`srtp_ctx_t_`) — `include/srtp_priv.h`

A session is the top-level handle that manages multiple SRTP streams:

```c
typedef struct srtp_ctx_t_ {
    srtp_stream_list_t stream_list;        // All active streams, keyed by SSRC
    srtp_stream_ctx_t *stream_template;    // Template for auto-creating streams
    void *user_data;                       // Application-provided context
} srtp_ctx_t_;
```

### Stream (`srtp_stream_ctx_t_`) — `include/srtp_priv.h`

Each stream corresponds to a single RTP synchronization source (SSRC):

```c
typedef struct srtp_stream_ctx_t_ {
    uint32_t ssrc;                         // Synchronization Source identifier
    srtp_session_keys_t *session_keys;     // Array of derived key sets (for MKI)
    size_t num_master_keys;                // Number of master keys available
    bool use_mki;                          // Master Key Index enabled
    size_t mki_size;                       // MKI field size in bytes
    srtp_rdbx_t rtp_rdbx;                  // RTP replay database (extended)
    srtp_sec_serv_t rtp_services;          // Confidentiality, authentication, or both
    srtp_rdb_t rtcp_rdb;                   // RTCP replay database
    srtp_sec_serv_t rtcp_services;         // RTCP security services
    direction_t direction;                 // Sender, receiver, or unknown
    bool allow_repeat_tx;                  // Allow retransmission of same seq number
    uint8_t *enc_xtn_hdr;                 // Header extension IDs to encrypt (RFC 6904)
    size_t enc_xtn_hdr_count;
    uint32_t pending_roc;                  // Pending rollover counter
    bool use_cryptex;                      // CRYPTEX mode enabled
} srtp_stream_ctx_t_;
```

### Session Keys (`srtp_session_keys_t`) — `include/srtp_priv.h`

Derived cryptographic material for one master key:

```c
typedef struct srtp_session_keys_t {
    srtp_cipher_t *rtp_cipher;             // RTP payload cipher
    srtp_cipher_t *rtp_xtn_hdr_cipher;     // Header extension cipher
    srtp_auth_t *rtp_auth;                 // RTP authentication function
    srtp_cipher_t *rtcp_cipher;            // RTCP cipher
    srtp_auth_t *rtcp_auth;                // RTCP authentication function
    uint8_t salt[SRTP_AEAD_SALT_LEN];      // RTP AEAD salt (12 bytes)
    uint8_t c_salt[SRTP_AEAD_SALT_LEN];    // RTCP AEAD salt
    uint8_t *mki_id;                       // Master Key Identifier
    srtp_key_limit_ctx_t *limit;           // Key usage counter
} srtp_session_keys_t;
```

### Crypto Policy (`srtp_crypto_policy_t`) — `include/srtp.h`

Specifies which algorithms and parameters to use:

```c
typedef struct srtp_crypto_policy_t {
    srtp_cipher_type_id_t cipher_type;     // e.g., SRTP_AES_ICM_128, SRTP_AES_GCM_256
    size_t cipher_key_len;                 // Key length including salt
    srtp_auth_type_id_t auth_type;         // e.g., SRTP_HMAC_SHA1
    size_t auth_key_len;
    size_t auth_tag_len;                   // Truncated tag length (4 or 10 bytes typical)
    srtp_sec_serv_t sec_serv;              // Bitmask: confidentiality | authentication
} srtp_crypto_policy_t;
```

---

## Public API

### Lifecycle

| Function | Purpose |
|---|---|
| `srtp_init()` | Initialize the library and crypto kernel |
| `srtp_shutdown()` | Clean up global state |
| `srtp_create(session, policy)` | Create a session with one or more stream policies |
| `srtp_dealloc(session)` | Destroy a session and all its streams |
| `srtp_stream_add(session, policy)` | Add a stream to an existing session |
| `srtp_stream_remove(session, ssrc)` | Remove a stream by SSRC |

### Packet Protection

| Function | Purpose |
|---|---|
| `srtp_protect(ctx, rtp, rtp_len, srtp, srtp_len, mki_index)` | Encrypt and authenticate an RTP packet |
| `srtp_unprotect(ctx, srtp, srtp_len, rtp, rtp_len)` | Verify and decrypt an SRTP packet |
| `srtp_protect_rtcp(ctx, rtcp, rtcp_len, srtcp, srtcp_len, mki_index)` | Encrypt and authenticate an RTCP packet |
| `srtp_unprotect_rtcp(ctx, srtcp, srtcp_len, rtcp, rtcp_len)` | Verify and decrypt an SRTCP packet |

### Policy Presets

Convenience functions to configure `srtp_crypto_policy_t` with standard profiles:

- `srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80()` — AES-128-ICM + HMAC-SHA1-80 (default)
- `srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32()` — AES-128-ICM + HMAC-SHA1-32
- `srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80()` — AES-256-ICM + HMAC-SHA1-80
- `srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32()` — AES-256-ICM + HMAC-SHA1-32
- `srtp_crypto_policy_set_aes_gcm_128_16_auth()` — AES-128-GCM with 16-byte tag
- `srtp_crypto_policy_set_aes_gcm_128_8_auth()` — AES-128-GCM with 8-byte tag
- `srtp_crypto_policy_set_aes_gcm_256_16_auth()` — AES-256-GCM with 16-byte tag
- `srtp_crypto_policy_set_aes_gcm_256_8_auth()` — AES-256-GCM with 8-byte tag
- `srtp_crypto_policy_set_null_cipher_hmac_sha1_80()` — No encryption, HMAC-SHA1-80 only
- `srtp_crypto_policy_set_null_cipher_hmac_null()` — No security (testing)

---

## Packet Protection Flow

### SRTP Protect (Sender) — `srtp/srtp.c`

```
Input: plaintext RTP packet
  │
  ├─ Validate RTP header
  ├─ Look up stream by SSRC (or create from template)
  ├─ Verify sender direction
  ├─ Select session keys (by MKI index)
  ├─ Check key usage limits
  │
  ├─── [AES-ICM + HMAC path] ─────────────────────────────────┐
  │    ├─ Copy header to output                                │
  │    ├─ Set IV = (SSRC, extended sequence number)             │
  │    ├─ Encrypt payload with AES-ICM                         │
  │    ├─ Compute HMAC-SHA1 over header + encrypted payload    │
  │    ├─ Append authentication tag (+ MKI if enabled)         │
  │    └─ Update replay database                               │
  │                                                            │
  ├─── [AES-GCM (AEAD) path] ─────────────────────────────────┤
  │    ├─ Calculate 12-byte IV from salt ⊕ (SSRC || seq)       │
  │    ├─ Encrypt header extensions if configured (RFC 6904)   │
  │    ├─ Set AAD = RTP header                                 │
  │    ├─ GCM encrypt payload (produces ciphertext + auth tag) │
  │    └─ Update replay database                               │
  │                                                            │
Output: SRTP packet (header + encrypted payload + tag [+ MKI])
```

### SRTP Unprotect (Receiver) — `srtp/srtp.c`

```
Input: SRTP packet
  │
  ├─ Validate SRTP header
  ├─ Look up stream by SSRC (or create from template)
  ├─ Determine session keys (extract MKI if present)
  ├─ Estimate extended sequence number from local state
  ├─ Check replay database (reject duplicates)
  │
  ├─── [AES-ICM + HMAC path] ──────────────────────────────────┐
  │    ├─ Locate authentication tag in packet                   │
  │    ├─ Compute HMAC-SHA1, compare with tag → reject on fail  │
  │    ├─ Set IV and decrypt payload with AES-ICM               │
  │    └─ Update replay database                                │
  │                                                             │
  ├─── [AES-GCM (AEAD) path] ──────────────────────────────────┤
  │    ├─ Calculate IV from salt ⊕ (SSRC || seq)                │
  │    ├─ Set AAD = RTP header                                  │
  │    ├─ GCM decrypt (verifies auth tag implicitly)            │
  │    │  → reject if authentication fails                      │
  │    └─ Update replay database                                │
  │                                                             │
Output: plaintext RTP packet (or error)
```

### SRTCP Protect/Unprotect

SRTCP follows the same patterns with these differences:
- Uses a 31-bit SRTCP index instead of the RTP sequence number
- Includes an E-bit (encryption flag) in the SRTCP trailer
- Authentication is always required (not optional like SRTP)
- Separate key derivation labels for RTCP keys

---

## Cryptographic Subsystem

### Crypto Kernel — `crypto/kernel/crypto_kernel.c`

The kernel is a global singleton that manages all cryptographic algorithm registrations:

```c
typedef struct {
    srtp_crypto_kernel_state_t state;             // insecure | secure
    srtp_kernel_cipher_type_t *cipher_type_list;  // Registered cipher implementations
    srtp_kernel_auth_type_t *auth_type_list;      // Registered auth implementations
    srtp_kernel_debug_module_t *debug_module_list; // Debug modules
} srtp_crypto_kernel_t;
```

**Initialization** (`srtp_crypto_kernel_init()`):
1. Register all built-in cipher types (null, AES-ICM-128/192/256, AES-GCM-128/256)
2. Register all built-in auth types (null, HMAC-SHA1)
3. Run self-tests on every registered algorithm using known-answer test vectors
4. Transition to "secure" state only if all tests pass
5. Refuse to allocate any cipher/auth if not in "secure" state

### Cipher Abstraction — `crypto/include/cipher.h`

All ciphers implement a common interface via function pointers:

```c
typedef struct srtp_cipher_type_t {
    srtp_err_status_t (*alloc)(srtp_cipher_t **, size_t key_len, size_t tag_len);
    srtp_err_status_t (*dealloc)(srtp_cipher_t *);
    srtp_err_status_t (*init)(void *state, const uint8_t *key);
    srtp_err_status_t (*set_aad)(void *state, const uint8_t *aad, size_t aad_len);
    srtp_err_status_t (*encrypt)(void *state, const uint8_t *src, size_t src_len,
                                  uint8_t *dst, size_t *dst_len);
    srtp_err_status_t (*decrypt)(void *state, const uint8_t *src, size_t src_len,
                                  uint8_t *dst, size_t *dst_len);
    srtp_err_status_t (*set_iv)(void *state, uint8_t *iv, srtp_cipher_direction_t dir);
    const srtp_cipher_test_case_t *test_data;
    const char *description;
    srtp_cipher_type_id_t id;
} srtp_cipher_type_t;
```

### Authentication Abstraction — `crypto/include/auth.h`

All auth functions implement a parallel interface:

```c
typedef struct srtp_auth_type_t {
    srtp_err_status_t (*alloc)(srtp_auth_t **, size_t key_len, size_t tag_len);
    srtp_err_status_t (*dealloc)(srtp_auth_t *);
    srtp_err_status_t (*init)(void *state, const uint8_t *key, size_t key_len);
    srtp_err_status_t (*compute)(void *state, const uint8_t *buf, size_t len,
                                  size_t tag_len, uint8_t *tag);
    srtp_err_status_t (*update)(void *state, const uint8_t *buf, size_t len);
    srtp_err_status_t (*start)(void *state);
    const srtp_auth_test_case_t *test_data;
    const char *description;
    srtp_auth_type_id_t id;
} srtp_auth_type_t;
```

### Backend Implementations

Each cipher/auth has multiple backend implementations selected at compile time:

| Algorithm | OpenSSL | WolfSSL | mbedTLS | NSS | Built-in |
|---|---|---|---|---|---|
| AES-ICM | `aes_icm_ossl.c` | `aes_icm_wssl.c` | `aes_icm_mbedtls.c` | `aes_icm_nss.c` | `aes_icm.c` + `aes.c` |
| AES-GCM | `aes_gcm_ossl.c` | `aes_gcm_wssl.c` | `aes_gcm_mbedtls.c` | `aes_gcm_nss.c` | *(not available)* |
| HMAC-SHA1 | `hmac_ossl.c` | `hmac_wssl.c` | `hmac_mbedtls.c` | `hmac_nss.c` | `hmac.c` + `sha1.c` |

The built-in backend supports AES-128/256-ICM and HMAC-SHA1 only (no GCM, no AES-192).

---

## Key Derivation — `srtp/srtp.c` (`srtp_stream_init_keys`)

Master keys are never used directly. A Key Derivation Function (KDF) based on AES-CTR generates separate session keys for each purpose:

| Label | Derived Key |
|---|---|
| `label_rtp_encryption` | RTP payload cipher key |
| `label_rtp_msg_auth` | RTP authentication key |
| `label_rtp_salt` | RTP cipher salt (ICM mode) |
| `label_rtcp_encryption` | RTCP cipher key |
| `label_rtcp_msg_auth` | RTCP authentication key |
| `label_rtcp_salt` | RTCP cipher salt |
| `label_rtp_header_encryption` | Header extension cipher key |
| `label_rtp_header_salt` | Header extension salt |

The KDF uses the master key and master salt to produce cryptographically independent keys for each function, preventing key reuse across different contexts.

---

## Replay Protection — `crypto/replay/`

### RTP (`srtp_rdbx_t`)
- Tracks a 64-bit extended sequence number (32-bit seq + rollover counter)
- Maintains a sliding bitmask window (default 128 packets)
- Handles out-of-order arrival within the window
- Detects and rejects replayed packets

### RTCP (`srtp_rdb_t`)
- Tracks a 31-bit SRTCP index
- Simpler design since RTCP has its own explicit index field

---

## Key Usage Limits — `crypto/kernel/key.c`

Each session key set tracks how many packets have been processed:
- **Soft limit**: Triggers a `srtp_key_event_soft_limit` event (application should rekey)
- **Hard limit**: Triggers `srtp_key_event_hard_limit` (library refuses further operations)

---

## Build System

Three build systems are supported:

| System | Primary File | Status |
|---|---|---|
| **CMake** | `CMakeLists.txt` | Primary (requires 3.21+) |
| **Meson** | `meson.build` | Alternative (requires 0.52+) |
| **Autotools** | `configure.ac` / `Makefile.in` | Legacy |

### Key Build Options

- `CRYPTO_LIBRARY`: Select backend — `openssl` (default), `wolfssl`, `mbedtls`, `nss`, `internal`
- `BUILD_SHARED_LIBS`: Build as shared library
- `LIBSRTP_TEST_APPS`: Build test applications (default: ON)
- Sanitizer support: ASAN, UBSAN, LSAN, TSAN

---

## Test Infrastructure

| Test Program | Purpose |
|---|---|
| `test/srtp_driver` | In-memory SRTP protect/unprotect tests |
| `test/test_srtp` | Comprehensive SRTP API tests |
| `crypto/test/cipher_driver` | Cipher algorithm tests with known-answer vectors |
| `crypto/test/kernel_driver` | Crypto kernel self-test |
| `test/rdbx_driver` | Extended replay database tests |
| `test/replay_driver` | Replay protection tests |
| `test/roc_driver` | Rollover counter tests |
| `test/rtpw` | Reference RTP/SRTP application for live testing |
| `test/rtp_decoder` | SRTP packet decoder (requires libpcap) |
| `fuzzer/` | Fuzz testing harness |

---

## Important Constants

```c
#define SRTP_MASTER_KEY_LEN     30   // Default master key + salt (AES-128-ICM)
#define SRTP_MAX_KEY_LEN        64   // Maximum key material size
#define SRTP_MAX_TAG_LEN        16   // Maximum authentication tag size
#define SRTP_MAX_MKI_LEN       128   // Maximum Master Key Index size
#define SRTP_SALT_LEN           14   // ICM/CTR mode salt length
#define SRTP_AEAD_SALT_LEN      12   // GCM AEAD salt length
#define SRTP_MAX_TRAILER_LEN   144   // Maximum bytes appended to a packet
```

---

## Supported Platforms

Linux, macOS, Windows (MSVC), Cygwin, Solaris, OpenBSD — with position-independent code (`-fPIC`) for shared library builds.
