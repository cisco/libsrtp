[![CMake Build](https://github.com/cisco/libsrtp/actions/workflows/cmake.yml/badge.svg)](https://github.com/cisco/libsrtp/actions/workflows/cmake.yml)
[![CMake Release](https://github.com/cisco/libsrtp/actions/workflows/cmake_release.yml/badge.svg)](https://github.com/cisco/libsrtp/actions/workflows/cmake_release.yml)
[![Autotools Build](https://github.com/cisco/libsrtp/actions/workflows/autotools.yml/badge.svg)](https://github.com/cisco/libsrtp/actions/workflows/autotools.yml)
[![Autotools Build](https://github.com/cisco/libsrtp/actions/workflows/meson.yml/badge.svg)](https://github.com/cisco/libsrtp/actions/workflows/meson.yml)
[![Coverity Scan Build Status](https://scan.coverity.com/projects/14274/badge.svg)](https://scan.coverity.com/projects/cisco-libsrtp)
[![OSS-Fuzz Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/systemd.svg)](https://oss-fuzz-build-logs.storage.googleapis.com/index.html#libsrtp)

<a name="introduction-to-libsrtp"></a>
# Introduction to libSRTP

This package provides an implementation of the Secure Real-time
Transport Protocol (SRTP), the Universal Security Transform (UST), and
a supporting cryptographic kernel. The SRTP API is documented in include/srtp.h,
and the library is in libsrtp2.a (after compilation).

This document describes libSRTP, the Open Source Secure RTP library
from Cisco Systems, Inc. RTP is the Real-time Transport Protocol, an
IETF standard for the transport of real-time data such as telephony,
audio, and video, defined by [RFC 3550](https://tools.ietf.org/html/rfc3550).
Secure RTP (SRTP) is an RTP profile for providing confidentiality to RTP data
and authentication to the RTP header and payload. SRTP is an IETF Standard,
defined in [RFC 3711](https://tools.ietf.org/html/rfc3711), and was developed
in the IETF Audio/Video Transport (AVT) Working Group. This library supports
all of the mandatory features of SRTP, but not all of the optional features. See
the [Supported Features](#supported-features) section for more detailed information.

This document is also used to generate the documentation files in the /doc/
folder where a more detailed reference to the libSRTP API and related functions
can be created (requires installing doxygen.). The reference material is created
automatically from comments embedded in some of the C header files. The
documentation is organized into modules in order to improve its clarity. These
modules do not directly correspond to files. An underlying cryptographic kernel
provides much of the basic functionality of libSRTP but is mostly undocumented
because it does its work behind the scenes.

--------------------------------------------------------------------------------



# Contact Us

- [libsrtp@lists.packetizer.com](mailto:libsrtp@lists.packetizer.com) general mailing list for news / announcements / discussions. This is an open list, see
[https://lists.packetizer.com/mailman/listinfo/libsrtp](https://lists.packetizer.com/mailman/listinfo/libsrtp) for singing up.
- [libsrtp-security@lists.packetizer.com](mailto:libsrtp-security@lists.packetizer.com) for disclosing security issues to the libsrtp maintenance team. This is a closed list but anyone can send to it.

--------------------------------------------------------------------------------



## Contents

- [Introduction to libSRTP](#introduction-to-libsrtp)
- [Contact Us](#contact-us)
  - [Contents](#contents)
- [License and Disclaimer](#license-and-disclaimer)
- [libSRTP Overview](#libsrtp-overview)
  - [Secure RTP Background](#secure-rtp-background)
  - [Supported Features](#supported-features)
  - [Implementation Notes](#implementation-notes)
- [Installing and Building libSRTP](#installing-and-building-libsrtp)
  - [Using CMake](#using-cmake)
    - [Using Visual Studio](#using-visual-studio)
  - [Using Meson](#using-meson)
  - [Using Autotools](#using-autotools)
    - [Changing Build Configuration](#changing-build-configuration)
  - [Build Options](#build-options)
- [Applications](#applications)
  - [Example Code](#example-code)
- [Credits](#credits)
- [References](#references)

--------------------------------------------------------------------------------



# License and Disclaimer

libSRTP is distributed under the following license, which is included
in the source code distribution. It is reproduced in the manual in
case you got the library from another source.

> Copyright (c) 2001-2017 Cisco Systems, Inc.  All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions
> are met:
>
> - Redistributions of source code must retain the above copyright
> notice, this list of conditions and the following disclaimer.
> - Redistributions in binary form must reproduce the above copyright
> notice, this list of conditions and the following disclaimer in
> the documentation and/or other materials provided with the distribution.
> - Neither the name of the Cisco Systems, Inc. nor the names of its
> contributors may be used to endorse or promote products derived
> from this software without specific prior written permission.
>
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
> "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
> LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
> FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
> COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
> INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
> (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
> SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
> HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
> STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
> ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
> OF THE POSSIBILITY OF SUCH DAMAGE.

--------------------------------------------------------------------------------



# libSRTP Overview

libSRTP provides functions for protecting RTP and RTCP.  RTP packets
can be encrypted and authenticated (using the `srtp_protect()`
function), turning them into SRTP packets. Similarly, SRTP packets
can be decrypted and have their authentication verified (using the
`srtp_unprotect()` function), turning them into RTP packets. Similar
functions apply security to RTCP packets.

The typedef `srtp_stream_t` points to a structure holding all of the
state associated with an SRTP stream, including the keys and
parameters for cipher and message authentication functions and the
anti-replay data. A particular `srtp_stream_t` holds the information
needed to protect a particular RTP and RTCP stream. This datatype
is intentionally opaque in order to better seperate the libSRTP
API from its implementation.

Within an SRTP session, there can be multiple streams, each
originating from a particular sender. Each source uses a distinct
stream context to protect the RTP and RTCP stream that it is
originating. The typedef `srtp_t` points to a structure holding all of
the state associated with an SRTP session. There can be multiple
stream contexts associated with a single `srtp_t`. A stream context
cannot exist indepent from an `srtp_t`, though of course an `srtp_t` can
be created that contains only a single stream context. A device
participating in an SRTP session must have a stream context for each
source in that session, so that it can process the data that it
receives from each sender.

In libSRTP, a session is created using the function `srtp_create()`.
The policy to be implemented in the session is passed into this
function as an opaque `srtp_policy_t` handle. A single policy handle
describes one stream policy. To configure multiple streams, create a
session and add additional policies with `srtp_stream_add()`.

A policy handle is configured with `srtp_policy_set_*` functions. At a
minimum, this includes SSRC selection, profile selection, and key/salt
material. The profile configures RTP/RTCP crypto policy settings, while the
SSRC selector identifies how and where that policy is applied.

--------------------------------------------------------------------------------



## Secure RTP Background

In this section we review SRTP and introduce some terms that are used
in libSRTP. An RTP session is defined by a pair of destination
transport addresses, that is, a network address plus a pair of UDP
ports for RTP and RTCP. RTCP, the RTP control protocol, is used to
coordinate between the participants in an RTP session, e.g. to provide
feedback from receivers to senders. An *SRTP session* is
similarly defined; it is just an RTP session for which the SRTP
profile is being used. An SRTP session consists of the traffic sent
to the SRTP or SRTCP destination transport addresses. Each
participant in a session is identified by a synchronization source
(SSRC) identifier. Some participants may not send any SRTP traffic;
they are called receivers, even though they send out SRTCP traffic,
such as receiver reports.

RTP allows multiple sources to send RTP and RTCP traffic during the
same session. The synchronization source identifier (SSRC) is used to
distinguish these sources. In libSRTP, we call the SRTP and SRTCP
traffic from a particular source a *stream*. Each stream has its own
SSRC, sequence number, rollover counter, and other data. A particular
choice of options, cryptographic mechanisms, and keys is called a
*policy*. Each stream within a session can have a distinct policy
applied to it.

A single policy can be used for all of the streams in a given session,
though the case in which a single *key* is shared across multiple
streams requires care. When key sharing is used, the SSRC values that
identify the streams **must** be distinct. This requirement can be
enforced by using the convention that each SRTP and SRTCP key is used
for encryption by only a single sender. In other words, the key is
shared only across streams that originate from a particular device (of
course, other SRTP participants will need to use the key for
decryption). libSRTP supports this enforcement by detecting the case
in which a key is used for both inbound and outbound data.

--------------------------------------------------------------------------------



## Supported Features

This library supports all of the mandatory-to-implement features of
SRTP (as defined in [RFC 3711](https://tools.ietf.org/html/rfc3711)). Some of these
features can be selected (or de-selected) at run time by setting an
appropriate policy using an `srtp_policy_t` handle.
Some other behaviors of the protocol can be adapted by defining an
approriate event handler for the exceptional events; see the SRTPevents
section in the generated documentation.

Some options that are described in the SRTP specification are not
supported. This includes

- key derivation rates other than zero,
- the cipher F8,
- the use of the packet index to select between master keys.

The user should be aware that it is possible to misuse this library,
and that the result may be that the security level it provides is
inadequate. If you are implementing a feature using this library, you
will want to read the Security Considerations section of [RFC 3711](https://tools.ietf.org/html/rfc3711#section-9).
In addition, it is important that you read and understand the
terms outlined in the [License and Disclaimer](#license-and-disclaimer) section.

This library also supports the AES-GCM Authenticated Encryption methods
described in [RFC 7714](https://tools.ietf.org/html/rfc7714)

--------------------------------------------------------------------------------



## Implementation Notes

* It is possible to configure which 3rd party crypto backend (OpenSSL, wolfSSL,
NSS or mbedTLS) libSRTP will be built with, see [Build Options](#build-options).
If the `internal` crypto library is selected then libSRTP provides
an internal implementation of AES and SHA1. The internal implementation only
supports AES-128 & AES-256, so to use AES-192 or the AES-GCM group of ciphers a
3rd party crypto backend must be configured. After `srtp_init()`,
`srtp_profile_supported()` reports whether AES-192 or AES-GCM is loaded.
For this and performance reasons it
is highly recommended to use a 3rd party crypto backend.
* The `srtp_protect()` function assumes that the buffer holding the
rtp packet has enough storage allocated that the authentication
tag can be written to the end of that packet. If this assumption
is not valid, memory corruption will ensue.
* Automated tests for the crypto functions are provided through
the `cipher_type_self_test()` and `auth_type_self_test()` functions.
These functions should be used to test each port of this code
to a new platform.
* Replay protection is contained in the crypto engine, and
tests for it are provided.
* This implementation provides calls to initialize, protect, and
unprotect RTP packets, and makes as few as possible assumptions
about how these functions will be called. For example, the
caller is not expected to provide packets in order (though if
they're called more than 65k out of sequence, synchronization
will be lost).
* The sequence number in the rtp packet is used as the low 16 bits
of the sender's local packet index. Note that RTP will start its
sequence number in a random place, and the SRTP layer just jumps
forward to that number at its first invocation. An earlier
version of this library used initial sequence numbers that are
less than 32,768; this trick is no longer required as the
`rdbx_estimate_index(...)` function has been made smarter as of
version 1.0.1.
* The replay window for (S)RTCP is hardcoded to 128 bits in length.

--------------------------------------------------------------------------------



# Installing and Building libSRTP

To install libSRTP, download the latest release of the distribution
from [https://github.com/cisco/libsrtp/releases](https://github.com/cisco/libsrtp/releases).
You probably want to get the most recent release. Unpack the distribution and
extract the source files; the directory into which the source files
will go is named `libsrtp-A-B-C` where `A` is the version number, `B` is the
major release number and `C` is the minor release number.

libSRTP can be built with [CMake](#using-cmake), [Meson](#using-meson) or
[Autotools](#using-autotools). CMake is the primary build system. The options
that select what is built are listed for all three tools in
[Build Options](#build-options).

--------------------------------------------------------------------------------



## Using CMake

CMake can be downloaded here: https://cmake.org/ . Configure, build, test and
install from the `libsrtp` directory:

```
# Configure, the build files are put in the build subdirectory
cmake -S . -B build

# Build the project
cmake --build build

# Run tests
ctest --test-dir build

# Optionally, install
cmake --install build
```

Options are set at configure time with `-DNAME=value`, see
[Build Options](#build-options).

The `dev` preset selects a debug build with the address and undefined behavior
sanitizers enabled:

```
cmake --preset dev
cmake --build --preset dev
ctest --preset dev
```



### Using Visual Studio

On Windows, Visual Studio can be used through CMake. Select the generator that
matches the installed Visual Studio version, for example:

```
# Create the project files
cmake -S . -B build -G "Visual Studio 17 2022"

# Build and test, Visual Studio is a multi-configuration generator
cmake --build build --config Release
ctest --test-dir build -C Release
```

`cmake --help` lists the available generators.

--------------------------------------------------------------------------------



## Using Meson

On all platforms including Windows, one can build using [Meson](https://mesonbuild.com).
Steps to download Meson are here: https://mesonbuild.com/Getting-meson.html

To build with Meson:

```
# Setup the build subdirectory
meson setup --prefix=/path/to/prefix builddir

# Build the project
meson compile -C builddir

# Run tests
meson test -C builddir

# Optionally, install
meson install -C builddir
```

Options are set at setup with `-Dname=value`, and can be changed later with
`meson configure builddir`, see [Build Options](#build-options).

To build with Visual Studio, run the above commands from inside a Visual Studio
command prompt, or run `vcvarsall.bat` with the appropriate arguments inside
a Command Prompt.

The commands can also be replaced with the equivalent `ninja` targets:
`ninja -C builddir`, `ninja -C builddir test`, `ninja -C builddir install`.

--------------------------------------------------------------------------------



## Using Autotools

The Autotools build requires GNU `make` (BSD make will not work; GNU make may
be installed as `gmake`). In the `libsrtp` directory, run the configure script
and then make:

`make` builds the static library and the test applications, `make runtest`
runs the tests and `make shared_library` builds the shared library.
`./configure --help` lists all options, including the standard autoconf options
such as `--prefix`. The libSRTP options are listed in
[Build Options](#build-options).

This package has been tested on the following platforms: Mac OS X
(powerpc-apple-darwin1.4), Cygwin (i686-pc-cygwin), Solaris
(sparc-sun-solaris2.6), RedHat Linux 7.1 and 9 (i686-pc-linux), and
OpenBSD (sparc-unknown-openbsd2.7).



### Changing Build Configuration

To build the `./configure` script mentioned above, libSRTP relies on the
[autoconf](https://www.gnu.org/software/autoconf/) toolchain.  Since
`./configure` is built from `configure.ac`, if you make changes in
how `./configure` works (e.g., to add a new library dependency), you will need
to rebuild `./configure` and commit the updated version.  In addition to
autoconf itself, you will need to have the `pkgconfig` tools installed as well.

For example, on macOS:

```
brew install autoconf pkgconfig
# Edit configure.ac
autoreconf -ivf
```

--------------------------------------------------------------------------------



## Build Options

The options that select what libSRTP is built with. A `-` marks an option that
the build tool does not provide. The first value listed is the default unless
noted.

Description | CMake | Meson | Autotools
------------|-------|-------|----------
Crypto library, `openssl` by default (`internal` supports only AES-128 and AES-256) | `-DCRYPTO_LIBRARY=<openssl\|wolfssl\|mbedtls\|nss\|internal>` | `-Dcrypto-library=<openssl\|wolfssl\|mbedtls\|nss\|internal>` | `--with-crypto-library=<openssl\|wolfssl\|nss\|internal>`
Use the crypto library's key derivation function (KDF) | - | `-Dcrypto-library-kdf=<auto\|enabled\|disabled>` | `--enable-openssl-kdf` (OpenSSL only, off by default)
Library type | `-DBUILD_SHARED_LIBS=<OFF\|ON>` (static by default) | `-Ddefault_library=<shared\|static\|both>` (shared by default) | `make` builds static, `make shared_library` builds shared
Debug logging in all modules | `-DENABLE_DEBUG_LOGGING=<OFF\|ON>` | `-Ddebug-logging=<false\|true>` | `--enable-debug-logging`
Log to stdout | `-DERR_REPORTING_STDOUT=<OFF\|ON>` | `-Dlog-stdout=<false\|true>` | `--enable-log-stdout`
Log to a file | `-DERR_REPORTING_FILE=<path>` | `-Dlog-file=<path>` | `--with-log-file=<path>`
Test applications | `-DLIBSRTP_TEST_APPS=<ON\|OFF>` | `-Dtests=<auto\|enabled\|disabled>` | always built
Test application requiring libpcap (`rtp_decoder`) | built if libpcap is found | `-Dpcap-tests=<auto\|enabled\|disabled>` | `--disable-pcap`
Fuzzer (requires clang) | - | `-Dfuzzer=<disabled\|enabled\|auto>` | -
API documentation (doxygen) | - | `-Ddoc=<auto\|enabled\|disabled>` | -

AES-192 and the AES-GCM ciphers require an external crypto library. There is no
log output by default. Autotools does not support mbedTLS.

CMake provides additional development options: `ENABLE_WARNINGS` and
`ENABLE_WARNINGS_AS_ERRORS` (both `ON` by default), `ENABLE_SANITIZE_ADDR`,
`ENABLE_SANITIZE_UNDEF`, `ENABLE_SANITIZE_LEAK`, `ENABLE_SANITIZE_THREAD` and
`ENABLE_LTO` (all `OFF` by default).

### Crypto Library Location

The crypto library is detected automatically. A library that is not in a
default search location can be specified as follows. `<dir>` is the installation
prefix, which contains the `include` and `lib` directories.

Build tool | Setting
-----------|--------
CMake | `-DCMAKE_PREFIX_PATH=<dir>` for all libraries, or `-DOPENSSL_ROOT_DIR=<dir>`, `-DWOLFSSL_ROOT_DIR=<dir>` or `-DMBEDTLS_ROOT_DIR=<dir>` for the respective library
Meson | `PKG_CONFIG_PATH=<dirs>` in the environment or `-Dpkg_config_path=<dirs>`, where `<dirs>` contains the library's `.pc` file, for example `/opt/openssl/lib/pkgconfig`
Autotools | `PKG_CONFIG_PATH=<dirs>` in the environment, or `--with-openssl-dir=<dir>`, `--with-wolfssl-dir=<dir>` or `--with-nss-dir=<dir>`

--------------------------------------------------------------------------------



# Applications

Several test drivers and a simple and portable srtp application are
included in the `test/` subdirectory.

Test driver     | Function tested
---------       | -------
kernel_driver   | crypto kernel (ciphers, auth funcs, rng)
srtp_driver	    | srtp in-memory tests (does not use the network)
rdbx_driver	    | rdbx (extended replay database)
roc_driver	    | extended sequence number functions
replay_driver	  | replay database
cipher_driver	  | ciphers
auth_driver	    | hash functions


--------------------------------------------------------------------------------



## Example Code

This section provides a simple example of how to use libSRTP. Here we assume
that the functions `get_rtp_packet()` and `send_srtp_packet()` are available
to us. The former puts an RTP packet
into the buffer and returns the number of octets written to that
buffer. The latter sends the RTP packet in the buffer, given the
length as its second argument.

~~~.c
srtp_t session;
srtp_policy_t policy;

// Set key/salt to predetermined values.
uint8_t master_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                          0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
uint8_t master_salt[14] = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
                           0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D};

// Initialize libSRTP.
srtp_init();

// Create and configure an opaque policy handle.
srtp_policy_create(&policy);
srtp_policy_set_ssrc(policy, (srtp_ssrc_t){ssrc_any_outbound, 0});
srtp_policy_set_profile(policy, srtp_profile_aes128_cm_sha1_80);
srtp_policy_add_key(policy, master_key, sizeof(master_key),
                    master_salt, sizeof(master_salt), NULL, 0);

// Allocate and initialize the SRTP session.
srtp_create(&session, policy);

srtp_policy_destroy(policy);

// Main loop: get RTP packets, send SRTP packets.
while (1) {
  char rtp_buffer[2048];
  size_t rtp_len;
  char srtp_buffer[2048];
  size_t srtp_len = sizeof(srtp_buffer);

  rtp_len = get_rtp_packet(rtp_buffer);
  srtp_protect(session, rtp_buffer, rtp_len, srtp_buffer, &srtp_len);
  send_srtp_packet(srtp_buffer, srtp_len);
}

srtp_dealloc(session);
srtp_shutdown();
~~~

--------------------------------------------------------------------------------



# Credits

The original implementation and documentation of libSRTP was written
by David McGrew of Cisco Systems, Inc. in order to promote the use,
understanding, and interoperability of Secure RTP. Michael Jerris
contributed support for building under MSVC. Andris Pavenis
contributed many important fixes. Brian West contributed changes to
enable dynamic linking. Yves Shumann reported documentation bugs.
Randell Jesup contributed a working SRTCP implementation and other
fixes. Steve Underwood contributed x86_64 portability changes. We also give
thanks to Fredrik Thulin, Brian Weis, Mark Baugher, Jeff Chan, Bill
Simon, Douglas Smith, Bill May, Richard Preistley, Joe Tardo and
others for contributions, comments, and corrections.

This reference material, when applicable, in this documenation was generated
using the doxygen utility for automatic documentation of source code.

Copyright 2001-2005 by David A. McGrew, Cisco Systems, Inc.

--------------------------------------------------------------------------------



# References

SRTP and ICM References
September, 2005

Secure RTP is defined in [RFC 3711](https://tools.ietf.org/html/rfc3711).
The counter mode definition is in [Section 4.1.1](https://tools.ietf.org/html/rfc3711#section-4.1.1).

SHA-1 is defined in [FIPS PUB 180-4](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).

HMAC is defined in [RFC 2104](https://tools.ietf.org/html/rfc2104)
and HMAC-SHA1 test vectors are available
in [RFC 2202](https://tools.ietf.org/html/rfc2202#section-3).

AES-GCM usage in SRTP is defined in [RFC 7714](https://tools.ietf.org/html/rfc7714)
