---
title: ShangMi (SM) Cipher Suites for Transport Layer Security (TLS) Protocol Version 1.3
abbrev: TLSv1.3 SM Cipher Suites
docname: draft-yang-tls-tls13-sm-suites-06
date: 2020-09-27
# date: 2019-08
# date: 2019

stand_alone: no

ipr: trust200902
area: Security
wg: TLS
kw: Internet-Draft
cat: info

coding: us-ascii
pi:    # can use array (if all yes) or hash here
  toc: yes
  sortrefs:
  symrefs: yes

author:
      -
        ins: P. Yang
        name: Paul Yang
        org: Ant Group
        # abbrev: AntFin
        street: No. 77 Xueyuan Road
        city: Hangzhou
        code: 310000
        country: China
        phone: +86-571-2688-8888
        facsimile: +86-571-8643-2811
        email: kaishen.yy@antfin.com

normative:
  RFC2119:
  RFC8174:
  RFC8446:
  RFC5116:
  ISO-SM2:
    title: >
      IT Security techniques -- Digital signatures with appendix -- Part 3:
      Discrete logarithm based mechanisms
    target: https://www.iso.org/standard/76382.html
    author:
      org: International Organization for Standardization
    date: 2018-11
    seriesinfo:
      ISO: ISO/IEC 14888-3:2018
  ISO-SM3:
    title: >
      IT Security techniques -- Hash-functions -- Part 3:
      Dedicated hash-functions
    target: https://www.iso.org/standard/67116.html
    author:
      org: International Organization for Standardization
    date: 2018-10
    seriesinfo:
      ISO: ISO/IEC 10118-3:2018
  ISO-SM4:
    title: >
      IT Security techniques -- Encryption algorithms
      -- Part 3: Block ciphers
    target: https://www.iso.org/standard/54531.html
    author:
      org: International Organization for Standardization
    date: 2010-12
    seriesinfo:
      ISO: ISO/IEC 18033-3:2010
  GCM:
    title: >
      NIST Special Publication 800-38D:
      Recommendation for Block Cipher Modes of Operation:
      Galois/Counter Mode (GCM) and GMAC.
    target: http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
    author:
      ins: Dworkin, M.
      org: U.S. National Institute of Standards and Technology
    date: 2007-11
  CCM:
    title: >
      NIST Special Publication 800-38C: The CCM
      Mode for Authentication and Confidentiality
    target: http://csrc.nist.gov/publications/nistpubs/800-38C/SP800-38C.pdf
    author:
      ins: Dworkin, M.
      org: U.S. National Institute of Standards and Technology
    date: 2004-05

informative:
  GBT.32907-2016:
    title: Information security technology — SM4 block cipher algorithm
    target: http://www.gmbz.org.cn/upload/2018-04-04/1522788048733065051.pdf
    author:
      org: Standardization Administration of China
    date: 2017-03-01
    seriesinfo:
      GB/T: 32907-2016
  GBT.32905-2016:
    title: Information security technology — SM3 cryptographic hash algorithm
    target: http://www.gmbz.org.cn/upload/2018-07-24/1532401392982079739.pdf
    author:
      org: Standardization Administration of China
    date: 2017-03-01
    seriesinfo:
      GB/T: 32905-2016
  GBT.32918.2-2016:
    title: >
      Information security technology — Public key cryptographic algorithm SM2
      based on elliptic curves — Part 2: Digital signature algorithm
    target: http://www.gmbz.org.cn/upload/2018-07-24/1532401673138056311.pdf
    author:
      org: Standardization Administration of China
    date: 2017-03-01
    seriesinfo:
      GB/T: 32918.2-2016
  GBT.32918.5-2016:
    title: >
      Information security technology — Public key cryptographic algorithm SM2
      based on elliptic curves — Part 5: Parameter definition
    target: http://www.gmbz.org.cn/upload/2018-07-24/1532401863206085511.pdf
    author:
      org: Standardization Administration of China
    date: 2017-03-01
    seriesinfo:
      GB/T: 32918.5-2016
  GMT.0009-2012:
    title: SM2 cryptography algorithm application specification
    target: http://www.gmbz.org.cn/main/viewfile/2018011001400692565.html
    author:
      org: State Cryptography Administration of China
    date: 2012-11-22
    seriesinfo:
      GM/T: 0009-2016
  J02:
    title: On the Security of CTR + CBC-MAC
    target: http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/ccm/ccm-ad1.pdf
    author:
      ins: Jonsson, J.
    date: 2002
  MV04:
    title: >
      The Security and Performance of
      the Galois/Counter Mode (GCM)
    target: http://eprint.iacr.org/2004/193
    author:
      ins: McGrew, D. and J. Viega
    date: 2004-12


# --- note_IESG_Note
#
# bla bla bla

--- abstract

This document specifies how to use the ShangMi (SM) cryptographic
algorithms with Transport Layer Security (TLS) protocol version 1.3.

The use of these algorithms with TLSv1.3 is not endorsed by the
IETF.  The SM algorithms are becoming mandatory in China, and so
this document provides a description of how to use the SM algorithms
with TLSv1.3 and specifies a profile of TLSv1.3 so that
implementers can produce interworking
implementations.


--- middle

Introduction        {#intro}
============

This document describes two new cipher suites, a signature algorithm, and a
key-exchange mechanism for the Transport Layer
Security (TLS) protocol version 1.3 (TLSv1.3, [RFC8446]).
These all utilize several ShangMi (SM) cryptographic algorithms
to fulfil the authentication and confidentiality requirements of TLS 1.3.
The new cipher suites are (see also {{proposed}}):

~~~~~~~~
   CipherSuite TLS_SM4_GCM_SM3 = { 0x00, 0xC6 };
   CipherSuite TLS_SM4_CCM_SM3 = { 0x00, 0xC7 };
~~~~~~~~

For a more detailed
introduction to SM cryptographic algorithms, please read {{sm-algos}}.
These cipher suites follow the TLSv1.3 requirements. Specifically,
all the cipher suites use SM4 in either GCM (Galois/Counter Mode) mode
or CCM (Counter with CBC-MAC) mode to meet the needs of TLSv1.3 to have an AEAD
(Authenticated Encryption with Associated Data) capable encryption algorithm.
The key exchange mechanism utilizes ECDHE (Elliptic Curve Diffie-Hellman
Ephemeral) over the SM2 elliptic curve, and the signature algorithm combines
the SM3 hash function and the SM2 elliptic curve signature scheme.

For the details about how these mechanisms negotiate shared encryption
keys, authenticate the peer(s), and protect the record structure, please read
{{definitions}}.

The cipher suites, signature algorithm, and key exchange mechanism
defined in this document are not recommended by the IETF. The SM
algorithms are becoming mandatory in China, and so this document
provides a description of how to use them with TLSv1.3 and specifies
a profile of TLS 1.3 so that implementers can produce interworking
implementations.


The SM Algorithms    {#sm-algos}
-------------------

Several different SM
cryptographic algorithms are used to integrate with TLS 1.3,
including SM2 for authentication, SM4 for
encryption and SM3 as the hash function.

SM2 is a set of elliptic curve based cryptographic algorithms including digital
signature, public key encryption and key exchange scheme. In this document, only
the SM2 digital signature algorithm and basic key exchange scheme are involved, which have already been added
to ISO/IEC 14888-3:2018 {{ISO-SM2}} (as well as in {{GBT.32918.2-2016}}).
SM4 is a block cipher defined in {{GBT.32907-2016}} and now is being standardized
by ISO to ISO/IEC 18033-3:2010 {{ISO-SM4}}. SM3 is a hash function which produces
an output of 256 bits. SM3 has already been accepted by ISO in
ISO/IEC 10118-3:2018 {{ISO-SM3}}, and also been described by {{GBT.32905-2016}}.


Terminology     {#term}
-----------

Although this document is not an IETF Standards Track publication it
adopts the conventions for normative language to provide clarity of
instructions to the implementer, and to indicate requirement levels
for compliant TLSv1.3 implementations.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in BCP 14
{{RFC2119}} {{RFC8174}} when, and only when, they appear in all capitals,
as shown here.

Algorithm Identifiers {#proposed}
=====================

The cipher suites defined here have the following identifiers:

~~~~~~~~
   CipherSuite TLS_SM4_GCM_SM3 = { 0x00, 0xC6 };
   CipherSuite TLS_SM4_CCM_SM3 = { 0x00, 0xC7 };
~~~~~~~~

To accomplish a TLSv1.3 handshake, additional objects have been introduced along with
the cipher suites as follows:

* The combination of SM2 signature algorithm and SM3 hash function used in the Signature Algorithm
extension defined in Section 4.2.3 of {{RFC8446}}:

~~~~~~~~
      SignatureScheme sm2sig_sm3 = { 0x0708 };
~~~~~~~~

* The SM2 elliptic curve ID used in the Supported Groups extension defined in
Section 4.2.7 of {{RFC8446}}:

~~~~~~~~
      NamedGroup curveSM2 = { 41 };
~~~~~~~~


Algorithm Definitions  {#definitions}
=========================

TLS Versions
------------

The new cipher suites along with any related signature algorithm or key exchange
scheme defined in this document are only applicable to TLSv1.3.
Implementations of this document MUST NOT apply these cipher suites, signature
algorithms or key exchange scheme to any older versions of TLS.

Authentication
--------------

### SM2 Signature Scheme

The Chinese government requires the use of the SM2 signature algorithm.
This section specifies the use of the SM2 signature algorithm
as the authentication method for a TLSv1.3 handshake.

The SM2 signature is defined in {{ISO-SM2}}. The SM2 signature algorithm is
based on elliptic curves. The SM2 signature algorithm uses a fixed elliptic curve
parameter set defined in {{GBT.32918.5-2016}}. This curve has the name curveSM2
and has been assigned the value 41 as shown in {{proposed}}. That is to say, SM2
MUST select the specific elliptic curve. But it is acceptable to write test cases
that use other elliptic curve parameter sets for SM2, take Annex F.14 of {{ISO-SM2}}
as a reference.

Implementations of the signature scheme and key exchange mechanism defined in this document MUST conform to
what {{GBT.32918.5-2016}} requires, that is to say, the only valid elliptic curve
parameter set for SM2 signature algorithm (a.k.a curveSM2) is defined as follows:

~~~~~~~~
   curveSM2: a prime field of 256 bits

   y^2 = x^3 + ax + b

   p  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF
        FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
   a  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF
        FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
   b  = 28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7
        F39789F5 15AB8F92 DDBCBD41 4D940E93
   n  = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF
        7203DF6B 21C6052B 53BBF409 39D54123
   Gx = 32C4AE2C 1F198119 5F990446 6A39C994
        8FE30BBF F2660BE1 715A4589 334C74C7
   Gy = BC3736A2 F4F6779C 59BDCEE3 6B692153
        D0A9877C C62A4740 02DF32E5 2139F0A0
~~~~~~~~

The SM2 signature algorithm requests an identifier value when generating or verifying
a signature. In all uses except when a client or server needs to verify a peer's
SM2 certificate in the Certificate message, an implementation of this document
MUST use the following ASCII string value as the SM2 identifier when doing a
TLSv1.3 key exchange:

~~~~~~~~
   TLSv1.3+GM+Cipher+Suite
~~~~~~~~

If either a client or a server needs to verify the peer's SM2 certificate
contained in the Certificate message, then the following ASCII string value MUST be
used as the SM2 identifier according to {{GMT.0009-2012}}:

~~~~~~~~
   1234567812345678
~~~~~~~~

Expressed as octets, this is:

~~~~~~~~
   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
   0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
~~~~~~~~

In practice, the SM2 identifier used in a certificate signature depends on the
CA who signs that certificate. CAs may choose values other than the ones mentioned
above. Implementations of this document SHOULD confirm this information by themselves.

Key Exchange  {#kx}
------------

### Hello Messages

The use of the algorithms defined by this document is negotiated during
the TLS handshake with information exchanged in the Hello messages.

#### ClientHello

To use the cipher suites defined by this document, a TLSv1.3 client includes
the new cipher suites in the 'cipher_suites'
array of the ClientHello structure defined in Section 4.1.2 of {{RFC8446}}.

Other requirements of this TLSv1.3 profile on the extensions of
ClientHello message are:

* For the supported_groups extension, 'curveSM2' MUST be included;
* For the signature_algorithms extension, 'sm2sig_sm3' MUST be included;
* For the signature_algorithms_cert extension (if present), 'sm2sig_sm3' MUST be included;
* For the key_share extension, a KeyShareEntry for the 'curveSM2' group MUST be included

#### ServerHello

If a TLSv1.3 server receives a ClientHello message containing the algorithms
defined in this document, it MAY choose to use them. If
so, then the server MUST put one of the new cipher suites defined in this
document into its ServerHello's 'cipher_suites' array and eventually send it
to the client side.

A TLSv1.3 server's choice of what cipher suite to use depends on the configuration
of the server. For instance, a TLSv1.3 server may be configured to include the
new cipher suites defined in this document, or it may not be. Typical TLSv1.3
server applications also provide a mechanism that configures the cipher suite
preference at server side. If a server is not configured to use the cipher suites
defined in this document, it SHOULD choose another cipher suite in the list that
the TLSv1.3 client provides; otherwise the server aborts the handshake with
an "illegal_parameter" alert.

The following extensions MUST conform to the new requirements:

* For the key_share extension, a KeyShareEntry with SM2 related values MUST be added
if the server wants to conform to this profile.

### CertificateRequest

If a CertificateRequest message is sent by the server to request the client
to send its certificate for authentication purposes, for conformance to this
profile, it is REQUIRED that:

* The only valid signature algorithm present in "signature_algorithms" extension
MUST be "sm2sig_sm3" and "signature_algorithms_cert" MUST NOT be present.
That is to say, if the server chooses to conform to this profile,
the signature algorithm for client's certificate MUST use the SM2/SM3 procedure
specified by this document.

### Certificate

When a server sends the Certificate message containing the server certificate
to the client side, several new rules are added that will affect the certificate
selection:

* The public key in the certificate MUST be a valid SM2 public key.
* The signature algorithm used by the CA to sign current certificate MUST be
'sm2sig_sm3'.
* The certificate MUST be capable of signing, e.g., the digitalSignature bit
of X.509's Key Usage extension is set.

### CertificateVerify

In the CertificateVerify message, the signature algorithm MUST be 'sm2sig_sm3',
indicating that the hash function is SM3 and the signature algorithm is SM2.

Key Scheduling
-------------

As described in {{sm-algos}}, SM2 is actually a set of cryptographic
algorithms including one key exchange protocol which defines methods such as
key derivation function, etc. This document does not define an SM2 key exchange
protocol, and an SM2 key exchange protocol SHALL NOT be used in the basic key exchange
scheme defined in {{kx}}. Implementations of this document MUST always conform to
what TLSv1.3 {{RFC8446}} and its successors require about the key derivation and
related methods.

Cipher
------

The new cipher suites introduced in this document add two new AEAD encryption
algorithms, AEAD_SM4_GCM and AEAD_SM4_CCM, which stand for SM4 cipher in Galois/Counter
mode and SM4 cipher [GBT.32907-2016] in Counter with CBC-MAC mode, respectively.
The Hash function for both cipher suites is SM3 ({{ISO-SM3}}).

This section defines the AEAD_SM4_GCM and AEAD_SM4_CCM AEAD algorithms in a
style similar to what {{RFC5116}} used to define AEAD ciphers based on AES cipher.

### AEAD_SM4_GCM

The AEAD_SM4_GCM authenticated encryption algorithm works as specified in [GCM],
using SM4 as the block cipher, by providing the key, nonce, plaintext, and
associated data to that mode of operation. An authentication tag conforming to
the requirements of Section 5.2 of TLSv1.3 {{RFC8446}} MUST be constructed using
the details in the TLS record header. The additional data input that forms the
authentication tag MUST be the TLS record header. The AEAD_SM4_GCM ciphertext is formed by
appending the authentication tag provided as an output to the GCM encryption
operation to the ciphertext that is output by that operation. AEAD_SM4_GCM has 
four inputs: an SM4 key, an initialization vector (IV), a plaintext content, and optional 
additional authenticated data (AAD). AEAD_SM4_GCM generates two outputs: a ciphertext 
and message authentication code (also called an authentication tag). To have a common 
set of terms for AEAD_SM4_GCM and AEAD_SM4_CCM, the AEAD_SM4_GCM IV is referred to as a 
nonce in the remainder of this document. A simple test vector of AEAD_SM4_GCM and 
AEAD_SM4_CCM is given in Appendix A of this document.

The nonce is generated by the party performing the authenticated encryption operation.
Within the scope of any authenticated-encryption key, the nonce value MUST be unique.
That is, the set of nonce values used with any given key MUST NOT contain any duplicates.
Using the same nonce for two different messages encrypted with the same key
destroys the security properties of GCM mode. To generate the nonce, implementations of this document
MUST conform to TLSv1.3 (see {{RFC8446}}, Section 5.3).

The input and output lengths are as follows:

~~~~~~~~
   the SM4 key length is 16 octets,

   the max plaintext length is 2^36 - 31 octets,

   the max AAD length is 2^61 - 1 octets,

   the nonce length is 12 octets,

   the authentication tag length is 16 octets, and

   the max ciphertext length is 2^36 - 15 octets.
~~~~~~~~

A security analysis of GCM is available in [MV04].

### AEAD_SM4_CCM

The AEAD_SM4_CCM authenticated encryption algorithm works as specified in [CCM],
using SM4 as the block cipher. AEAD_SM4_CCM has four inputs: an SM4 key, a nonce,
a plaintext, and optional additional authenticated data (AAD). AEAD_SM4_CCM
generates two outputs: a ciphertext and a message authentication code (also called
an authentication tag). The formatting and counter generation functions are as
specified in Appendix A of [CCM], and the values of the parameters
identified in that appendix are as follows:

~~~~~~~~
   the nonce length n is 12,

   the tag length t is 16, and

   the value of q is 3.
~~~~~~~~

An authentication tag is also used in AEAD_SM4_CCM. The generation of the authentication
tag MUST conform to TLSv1.3 (See {{RFC8446}}, Section 5.2).
The AEAD_SM4_CCM ciphertext is formed by appending the authentication tag provided
as an output to the CCM encryption operation to the ciphertext that is output
by that operation. The input and output lengths are as follows:

~~~~~~~~
   the SM4 key length is 16 octets,

   the max plaintext length is 2^24 - 1 octets,

   the max AAD length is 2^64 - 1 octets, and

   the max ciphertext length is 2^24 + 15 octets.
~~~~~~~~

To generate the nonce, implementations of this document MUST conform to
TLSv1.3 (see {{RFC8446}}, Section 5.3).

A security analysis of CCM is available in [J02].


IANA Considerations
===================

IANA has assigned the values {0x00, 0xC6} and {0x00, 0xC7} with the names
TLS_SM4_GCM_SM3, TLS_SM4_CCM_SM3,
to the "TLS Cipher Suite" registry with this document as reference:

|   Value    | Description | DTLS-OK | Recommended | Reference |
|-----------:+-----------------+-----+-------------+-----------|
| 0x00,0xC6  | TLS_SM4_GCM_SM3 | No  |      No     | this RFC  |
| 0x00,0xC7  | TLS_SM4_CCM_SM3 | No  |      No     | this RFC  |

IANA has assigned the value 0x0708 with the name 'sm2sig_sm3', to the
"TLS SignatureScheme" registry:

|  Value | Description | Recommended | Reference |
|-------:+-------------+-------------+-----------|
| 0x0708 | sm2sig_sm3  |     No      | this RFC  |

IANA has assigned the value 41 with the name 'curveSM2', to the
"TLS Supported Groups" registry:

| Value | Description | DTLS-OK | Recommended | Reference |
|------:+-------------+---------+-------------+-----------|
|  41   |  curveSM2   |   No    |     No      | this RFC  |


Security Considerations
=======================

At the time of writing, there are no known weak keys for SM
cryptographic algorithms: SM2, SM3 and SM4, and no security issues
have been found for these algorithms.

A security analysis of GCM is available in [MV04].

A security analysis of CCM is available in [J02].

--- back

Test Vectors
============

All values are in hexadecimal and are in network byte order (big endian).

SM4-GCM Test Vectors
--------------------

~~~~~~~~
Initialization Vector:   00001234567800000000ABCD
Key:                     0123456789ABCDEFFEDCBA9876543210
Plaintext:               AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB
                         CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD
                         EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF
                         EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA
Associated Data:         FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2
CipherText:              17F399F08C67D5EE19D0DC9969C4BB7D
                         5FD46FD3756489069157B282BB200735
                         D82710CA5C22F0CCFA7CBF93D496AC15
                         A56834CBCF98C397B4024A2691233B8D
Authentication Tag:      83DE3541E4C2B58177E065A9BF7B62EC
~~~~~~~~

SM4-CCM Test Vectors
--------------------

~~~~~~~~
Initialization Vector:   00001234567800000000ABCD
Key:                     0123456789ABCDEFFEDCBA9876543210
Plaintext:               AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB
                         CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD
                         EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF
                         EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA
Associated Data:         FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2
CipherText:              48AF93501FA62ADBCD414CCE6034D895
                         DDA1BF8F132F042098661572E7483094
                         FD12E518CE062C98ACEE28D95DF4416B
                         ED31A2F04476C18BB40C84A74B97DC5B
Authentication Tag:      16842D4FA186F56AB33256971FA110F4
~~~~~~~~


Contributors
===============

Qin Long  
Ant Group  
zhuolong.lq@antfin.com  

Kepeng Li  
Ant Group  
kepeng.lkp@antfin.com  

Ke Zeng  
Ant Group  
william.zk@antfin.com  

Han Xiao  
Ant Group  
han.xiao@antfin.com  

Zhi Guan  
Peking University  
guan@pku.edu.cn  
