<a name="introduction-to-libsrtp"></a>
# Introduction to libSRTP

This package provides an implementation of the Secure Real-time
Transport Protocol (SRTP), the Universal Security Transform (UST), and
a supporting cryptographic kernel. The SRTP API is documented in include/srtp.h,
and the library is in libsrtp2.a (after compilation).

This document describes libSRTP, the Open Source Secure RTP library
from Cisco Systems, Inc. RTP is the Real-time Transport Protocol, an
IETF standard for the transport of real-time data such as telephony,
audio, and video, defined by [RFC 3550](https://www.ietf.org/rfc/rfc3550.txt).
Secure RTP (SRTP) is an RTP profile for providing confidentiality to RTP data
and authentication to the RTP header and payload. SRTP is an IETF Standard,
defined in [RFC 3711](https://www.ietf.org/rfc/rfc3711.txt), and was developed
in the IETF Audio/Video Transport (AVT) Working Group. This library supports
all of the mandatory features of SRTP, but not all of the optional features. See
the [Supported Features](#license) section for more detailed information.

This document is also used to generate the documentation files in the /doc/
folder where a more detailed reference to the libSRTP API and related functions
can be created (requires installing doxygen.). The reference material is created
automatically from comments embedded in some of the C header files. The
documentation is organized into modules in order to improve its clarity. These
modules do not directly correspond to files. An underlying cryptographic kernel
provides much of the basic functionality of libSRTP but is mostly undocumented
because it does its work behind the scenes.

--------------------------------------------------------------------------------

<a name="contents"></a>
## Contents

- [Introduction to libSRTP](#introduction-to-libsrtp)
   - [Contents](#contents)
- [License and Disclaimer](#license-and-disclaimer)
- [libSRTP Overview](#libsrtp-overview)
  - [Secure RTP Background](#secure-rtp-background)
  - [Supported Features](#supported-features)
  - [Implementation Notes](#implementation-notes)
- [Installing and Building libSRTP](#installing-and-building-libsrtp)
- [Applications](#applications)
  - [Example Code](#example-code)
- [ISMA Encryption Support](#isma-encryption-support)
- [Credits](#credits)
- [References](#references)

--------------------------------------------------------------------------------

<a name="license-and-disclaimer"></a>
# License and Disclaimer

libSRTP is distributed under the following license, which is included
in the source code distribution. It is reproduced in the manual in
case you got the library from another source.

> Copyright (c) 2001-2005 Cisco Systems, Inc.  All rights reserved.
>
> Redistribution and use in source and binary forms, with or without
> modification, are permitted provided that the following conditions
> are met:
>
> - Redistributions of source code must retain the above copyright
>   notice, this list of conditions and the following disclaimer.
> - Redistributions in binary form must reproduce the above copyright
>   notice, this list of conditions and the following disclaimer in
>   the documentation and/or other materials provided with the distribution.
> - Neither the name of the Cisco Systems, Inc. nor the names of its
>   contributors may be used to endorse or promote products derived
>   from this software without specific prior written permission.
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

<a name="libsrtp-overview"></a>
# libSRTP Overview

libSRTP provides functions for protecting RTP and RTCP.  RTP packets
can be encrypted and authenticated (`using the srtp_protect()`
function), turning them into SRTP packets. Similarly, SRTP packets
can be decrypted and have their authentication verified (using the
srtp_unprotect() function), turning them into RTP packets. Similar
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
function as an `srtp_policy_t` structure. A single one of these
structures describes the policy of a single stream. These structures
can also be linked together to form an entire session policy. A linked
list of `srtp_policy_t` structures is equivalent to a session policy.
In such a policy, we refer to a single srtp_policy_t as an *element*.

An `srtp_policy_t` strucutre contains two `crypto_policy_t` structures
that describe the cryptograhic policies for RTP and RTCP, as well as
the SRTP master key and the SSRC value. The SSRC describes what to
protect (e.g. which stream), and the `crypto_policy_t` structures
describe how to protect it. The key is contained in a policy element
because it simplifies the interface to the library. In many cases, it
is desirable to use the same cryptographic policies across all of the
streams in a session, but to use a distinct key for each stream. A
`crypto_policy_t` structure can be initialized by using either the
`crypto_policy_set_rtp_default()` or `crypto_policy_set_rtcp_default()`
functions, which set a crypto policy structure to the default policies
for RTP and RTCP protection, respectively.

--------------------------------------------------------------------------------

<a name="secure-rtp-background"></a>
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
applied to it. A session policy is a collection of stream policies.

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

<a name="supported-features"></a>
## Supported Features

This library supports all of the mandatory-to-implement features of
SRTP (as defined by the most recent Internet Draft). Some of these
features can be selected (or de-selected) at run time by setting an
appropriate policy; this is done using the structure `srtp_policy_t`.
Some other behaviors of the protocol can be adapted by defining an
approriate event handler for the exceptional events; see the SRTPevents
section in the generated documentation.

Some options that are not included in the specification are supported.
Most notably, the TMMH authentication function is included, though it
was removed from the SRTP Internet Draft during the summer of 2002.

Some options that are described in the SRTP specification are not
supported. This includes

- the Master Key Index (MKI),
- key derivation rates other than zero,
- the cipher F8,
- anti-replay lists with sizes other than 128,
- the use of the packet index to select between master keys.

The user should be aware that it is possible to misuse this libary,
and that the result may be that the security level it provides is
inadequate. If you are implementing a feature using this library, you
will want to read the Security Considerations section of the Internet
Draft. In addition, it is important that you read and understand the
terms outlined in the [License and Disclaimer](#license-and-disclaimer) section.

--------------------------------------------------------------------------------

<a name="implementation-notes"></a>
## Implementation Notes

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
    `rdbx_estimate_index(...)` function has been made smarter.

  * The replay window is 128 bits in length, and is hard-coded to this
    value for now.

--------------------------------------------------------------------------------

<a name="installing-and-building-libsrtp"></a>
# Installing and Building libSRTP

To install libSRTP, download the latest release of the distribution
from [github](https://github.com/cisco/libsrtp/releases). You probably
want to get the most recent release. Unpack the distribution and
extract the source files; the directory into which the source files
will go is named `libsrtp-A-B-C` where `A` is the version number, `B` is the
major release number and `C` is the minor release number.

libSRTP uses the GNU `autoconf` and `make` utilities (BSD make will not work; if
both versions of make are on your platform, you can invoke GNU make as
`gmake`.). In the `libsrtp` directory, run the configure script and then
make:

~~~.txt
./configure [ options ]
make
~~~

The configure script accepts the following options:

Option                    | Description
---------                 | -------
\-\-help                  | provides a usage summary
\-\-disable-debug         | compiles libSRTP without the runtime dynamic debugging system
\-\-enable-generic-aesicm | in changes for ismacryp
\-\-enable-syslog         | use syslog for error reporting.
\-\-disable-stdout        | diables stdout for error reporting.
\-\-enable-console        | use `/dev/console` for error reporting
\-\-enable-openssl        | use OpenSSL crypto primitives
\-\-with-openssl-dir      | Specify location of OpenSSL installation
\-\-enable-openssl-kdf use| OpenSSL SRTP KDF algorithm
\-\-gdoi                  | use GDOI key management (disabled at present)

By default, dynamic debugging is enabled and stdout is used for
debugging. You can use the configure options to have the debugging
output sent to syslog or the system console. Alternatively, you can
define `ERR_REPORTING_FILE` in `include/conf.h` to be any other
file that can be opened by libSRTP, and debug messages will be sent to
it.

This package has been tested on the following platforms: Mac OS X
(powerpc-apple-darwin1.4), Cygwin (i686-pc-cygwin), Solaris
(sparc-sun-solaris2.6), RedHat Linux 7.1 and 9 (i686-pc-linux), and
OpenBSD (sparc-unknown-openbsd2.7).

--------------------------------------------------------------------------------

<a name="applications"></a>
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

The app `rtpw` is a simple rtp application which reads words from
`/usr/dict/words` and then sends them out one at a time using [s]rtp.
Manual srtp keying uses the -k option; automated key management
using gdoi will be added later.

usage:
~~~.txt
rtpw [[-d <debug>]* [-k|b <key> [-a][-e <key size>][-g]] [-s | -r] dest_ip dest_port] | [-l]
~~~

Either the -s (sender) or -r (receiver) option must be chosen.  The
values `dest_ip`, `dest_port` are the IP address and UDP port to which
the dictionary will be sent, respectively.

The options are:

Option         | Description
---------      | -------
  -s           | (S)RTP sender - causes app to send words
  -r           | (S)RTP receive - causes app to receive words
  -k <key>     | use SRTP master key <key>, where the key is a hexadecimal (without the leading "0x")
  -b <key>     | same as -k but with base64 encoded key
  -e <keysize> | encrypt/decrypt (for data confidentiality) (requires use of -k option as well) (use 128, 192, or 256 for keysize)
  -g           | use AES-GCM mode (must be used with -e)
  -a           | message authentication (requires use of -k option as well)
  -l           | list the available debug modules
  -d <debug>   | turn on debugging for module <debug>

In order to get random 30-byte values for use as key/salt pairs , you
can use the following bash function to format the output of
`/dev/random` (where that device is available).

~~~.txt
function randhex() {
   cat /dev/random | od --read-bytes=32 --width=32 -x | awk '{ print $2 $3 $4 $5 $6 $7 $8 $9 $10 $11 $12 $13 $14 $15 $16 }'
}
~~~

An example of an SRTP session using two rtpw programs follows:

~~~.txt
set k=c1eec3717da76195bb878578790af71c4ee9f859e197a414a78d5abc7451

[sh1]$ test/rtpw -s -k $k -e 128 -a 0.0.0.0 9999
Security services: confidentiality message authentication
set master key/salt to C1EEC3717DA76195BB878578790AF71C/4EE9F859E197A414A78D5ABC7451
setting SSRC to 2078917053
sending word: A
sending word: a
sending word: aa
sending word: aal
...

[sh2]$ test/rtpw -r -k $k -e 128 -a 0.0.0.0 9999
security services: confidentiality message authentication
set master key/salt to C1EEC3717DA76195BB878578790AF71C/4EE9F859E197A414A78D5ABC7451
19 octets received from SSRC 2078917053 word: A
19 octets received from SSRC 2078917053 word: a
20 octets received from SSRC 2078917053 word: aa
21 octets received from SSRC 2078917053 word: aal
...
~~~

--------------------------------------------------------------------------------

<a name="example-code"></a>
## Example Code

This section provides a simple example of how to use libSRTP. The
example code lacks error checking, but is functional. Here we assume
that the value ssrc is already set to describe the SSRC of the stream
that we are sending, and that the functions `get_rtp_packet()` and
`send_srtp_packet()` are available to us. The former puts an RTP packet
into the buffer and returns the number of octets written to that
buffer. The latter sends the RTP packet in the buffer, given the
length as its second argument.

~~~.c
srtp_t session;
srtp_policy_t policy;
uint8_t key[30];

// initialize libSRTP
srtp_init();

// set policy to describe a policy for an SRTP stream
crypto_policy_set_rtp_default(&policy.rtp);
crypto_policy_set_rtcp_default(&policy.rtcp);
policy.ssrc = ssrc;
policy.key  = key;
policy.next = NULL;

// set key to random value
crypto_get_random(key, 30);

// allocate and initialize the SRTP session
srtp_create(&session, &policy);

// main loop: get rtp packets, send srtp packets
while (1) {
  char rtp_buffer[2048];
  unsigned len;

  len = get_rtp_packet(rtp_buffer);
  srtp_protect(session, rtp_buffer, &len);
  send_srtp_packet(rtp_buffer, len);
}
~~~

--------------------------------------------------------------------------------

<a name="isma-encryption-support"></a>
# ISMA Encryption Support

The Internet Streaming Media Alliance (ISMA) specifies a way
to pre-encrypt a media file prior to streaming.  This method
is an alternative to SRTP encryption, which is potentially
useful when a particular media file will be streamed
multiple times.  The specification is available online
at http://www.isma.tv/specreq.nsf/SpecRequest.

libSRTP provides the encryption and decryption functions needed for ISMAcryp
in the library `libaesicm.a`, which is included in the default
Makefile target.  This library is used by the MPEG4IP project; see
http://mpeg4ip.sourceforge.net/.

Note that ISMAcryp does not provide authentication for
RTP nor RTCP, nor confidentiality for RTCP.
ISMAcryp RECOMMENDS the use of SRTP message authentication for ISMAcryp
streams while using ISMAcryp encryption to protect the media itself.

--------------------------------------------------------------------------------

<a name="credits"></a>
# Credits

The original implementation and documentation of libSRTP was written
by David McGrew of Cisco Systems, Inc. in order to promote the use,
understanding, and interoperability of Secure RTP. Michael Jerris
contributed support for building under MSVC. Andris Pavenis
contributed many important fixes. Brian West contributed changes to
enable dynamic linking. Yves Shumann reported documentation bugs.
Randell Jesup contributed a working SRTCP implementation and other
fixes. Alex Vanzella and Will Clark contributed changes so that the
AES ICM implementation can be used for ISMA media encryption. Steve
Underwood contributed x86_64 portability changes. We also give
thanks to Fredrik Thulin, Brian Weis, Mark Baugher, Jeff Chan, Bill
Simon, Douglas Smith, Bill May, Richard Preistley, Joe Tardo and
others for contributions, comments, and corrections.

This reference material, when applicable, in this documenation was generated
using the doxygen utility for automatic documentation of source code.

Copyright 2001-2005 by David A. McGrew, Cisco Systems, Inc.

--------------------------------------------------------------------------------

<a name="references"></a>
# References

SRTP and ICM References
September, 2005

Secure RTP is defined in [RFC 3711](https://www.ietf.org/rfc/rfc3711.txt).
The counter mode definition is in Section 4.1.1.

SHA-1 is defined in FIPS-180-1, available online at the NIST website.

HMAC is defined in [RFC2104](https://www.ietf.org/rfc/rfc2104.txt)
and HMAC-SHA1 test vectors are available
in [RFC2202](https://www.ietf.org/rfc/rfc2202.txt).

ICM is defined by draft-irtf-cfrg-icm-00.txt, and its application in
ISMAcryp (the Internet Streaming Media Alliance 1.0 Encryption and
Authentication) is defined in that specification.  It is available
from http://www.isma.tv/.
