/*

libsslhaf: For passive SSL fingerprinting

 | THIS PRODUCT IS NOT READY FOR PRODUCTION USE. DEPLOY AT YOUR OWN RISK.

Copyright (c) 2009-2012, Qualys, Inc.
Copyright (c) 2012-2013, Network Box Corporation, Ltd.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

* Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

* Neither the name of the Qualys, Inc. nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

/*
 * This parser will extract the list of SSL cipher suites and extensions
 * offered by SSL clients during the negotiation phase.
 *
 * The goal is to extract and catalogue important information from both client
 * and server sides of the handshake procedure.  Another goal is client
 * fingerprinting.  Different clients use different SSL implementations and
 * configure them in different ways. By looking at the differences in the
 * cipher suites we hope to be able to identify clients, irrespective of what
 * data they are communicating (eg HTTP request headers).
 *
 * For HTTP, this way of fingerprinting is much more reliable than other
 * approaches (e.g. TCP/IP fingerprinting), for the following reasons:
 *
 * - HTTP proxies do not terminate SSL, which means that every client
 *   creates a unique data stream that is sent directly to servers.
 *
 * - NAT will modify TCP/IP packets, but leave SSL data streams
 *   untouched.
 *
 */

#ifndef SSLHAF_H
#define SSLHAF_H

#include <stdint.h>
#include <stddef.h>



/**
 * The sslhaf work stucture
 */
struct sslhaf_cfg_t {
    /* Inspection state; see above for the constants. */
    int state;

    /* The buffer we use to store the first SSL packet.
     * Allocated from the connection pool.
     */
    uint8_t record_type;

    unsigned char *inputbuf;
    size_t inputbuflen;
    size_t inputbufoff;
    size_t inputtogo;

    /* The client hello version used; 2 or 3. */
    unsigned int hello_version;

    /* SSL version indicated in the handshake. */
    unsigned int protocol_high;
    unsigned int protocol_low;

    /* How many suites are there? */
    unsigned int slen;

    /* Pointer to the first suite. Do note that a v3 suites consumes
     * 2 bytes whereas a v2 suite consumes 3 bytes. You need to check
     * hello_version before you access the suites.
     */
    const char *suites;

    /* Handkshake version as string. */
    const char *thandshake;

    /* Protocol version number as string. */
    const char *tprotocol;

    /* Suites as text. */
    const char *tsuites;

    /* How many requests were there on this connection? */
    unsigned int request_counter;

    /* SHA1 hash of the remote address. */
    const char *ipaddress_hash;

    /* How many output buckets seen on a connection */
    int out_bucket_count;

    /* How many input data fragments seen before first output data fragment. */
    int in_data_fragments;

    /* How many output buckets sent before first input data fragment. */
    int in_data_fragment_out_buckets;

    /* Indicates the connection has switched to encrypted handshake messages. */
    int seen_cipher_change;

    /* How many compression methods are there. */
    int compression_len;

    /* List of all compression methods as a comma-separated string. */
    const char *compression_methods;

    /* How many extensions were there in the handshake? */
    int extensions_len;

    /* A string that contains the list of all extensions seen in the handshake. */
    const char *extensions;

    /* User data */
    void *user_data;

    /* A pointer to the controlled memory alloc function */
    void* (*alloc_fn)(struct sslhaf_cfg_t *cfg, size_t size);
    /* A pointer to the controlled memory free function */
    void (*free_fn)(struct sslhaf_cfg_t *cfg, void* obj);
    /* A pointer to a limited stream printf style function.
     * If buf is NULL, size is ignored and the buffer will be dynamically allocated */
    char* (*snprintf_fn)(struct sslhaf_cfg_t *cfg,
            char *inputbuf, size_t len, const char *format, ...);
    /* A pointer to an error logging printf style function */
    void (*log_fn)(struct sslhaf_cfg_t *cfg, const char *format, ...);
};

typedef struct sslhaf_cfg_t sslhaf_cfg_t;



/**
 * Parsing states and limits
 */
#define SSLHAF_STATE_START                                  0
#define SSLHAF_STATE_BUFFER                                 1
#define SSLHAF_STATE_READING                                2
#define SSLHAF_STATE_GOAWAY                                 3

#define SSLHAF_BUF_LIMIT                                    16384



/**
 * SSLv3+ definitions
 */
#define SSLHAF_PROTOCOL_RECORD_TYPE_CHANGE_CIPHER_SPEC      20
#define SSLHAF_PROTOCOL_RECORD_TYPE_ALERT                   21
#define SSLHAF_PROTOCOL_RECORD_TYPE_HANDSHAKE               22
#define SSLHAF_PROTOCOL_RECORD_TYPE_APPLICATION             23

#define SSLHAF_PROTOCOL_MESSAGE_TYPE_HELLO_REQUEST          0
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_CLIENT_HELLO           1
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_SERVER_HELLO           2
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_CERTIFICATE            11
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_SERVER_KEY_EXCHANGE    12
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_CERTIFICATE_REQUEST    13
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_SERVER_HELLO_DONE      14
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_CERTIFICATE_VERIFY     15
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_CLIENT_KEY_EXCHANGE    16
#define SSLHAF_PROTOCOL_MESSAGE_TYPE_FINISHED               12



/**
 * SSLv2 definitions
 */
#define SSLHAF_PROTOCOL_RECORD_TYPE_2_0_HANDSHAKE           128

#define SSLHAF_PROTOCOL_MESSAGE_TYPE_2_0_CLIENT_HELLO       1



/**
 * Cipher description
 */
enum haf_cipher_group {
    haf_cg_UNKNOWN =                                        0,
    haf_cg_SSL_2_0,
    haf_cg_SSL_3_0,
    haf_cg_TLS_1_0,
    haf_cg_TLSKRB,
    haf_cg_TLSAES,
    haf_cg_TLSMISTY1,
    haf_cg_TLSCAM,
    haf_cg_TLSPSK,
    haf_cg_SEED,
    haf_cg_TLS_1_1,
    haf_cg_TLSECC,
    haf_cg_TLSSRP,
    haf_cg_TLSPSK_NULL,
    haf_cg_TLS_1_2,
    haf_cg_56bit,
    haf_cg_TLSAES_GCM,
    haf_cg_NSS,
    haf_cg_RI,
    haf_cg_END,
};

struct haf_cipher_description {
    const char* name;
    uint16_t id;
    uint16_t key_size;
    enum haf_cipher_group group;
};



/**
 * Get a description of a cipher given its id code
 */
struct haf_cipher_description *get_cipher_description(uint32_t id);

/**
 * Create and initialise a sslhaf_cfg object
 */
sslhaf_cfg_t *sslhaf_cfg_create(
    void *user_data,
    void* (*alloc_fn)(struct sslhaf_cfg_t *cfg, size_t size),
    void (*free_fn)(struct sslhaf_cfg_t *cfg, void* obj),
    char* (*snprintf_fn)(struct sslhaf_cfg_t *cfg,
            char *msgbuf, size_t len, const char *format, ...),
    void (*log_fn)(struct sslhaf_cfg_t *cfg, const char *format, ...));

/**
 * Cleanup and free a sslhaf_cfg object
 */
void sslhaf_cfg_destroy(sslhaf_cfg_t *cfg);

/**
 * Deal with a single buffer. We look for a handshake SSL packet, buffer
 * it (possibly across several invocations), then invoke a function to analyse it.
 */
int sslhaf_decode_buffer(sslhaf_cfg_t *cfg,
    const unsigned char *inputbuf, size_t inputlen);

#endif /* SSLHAF_H */
