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


#ifdef __cplusplus
extern "C" {
#endif


#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


#define SSLHAF_STATE_START 0
#define SSLHAF_STATE_BUFFER 1
#define SSLHAF_STATE_READING 2
#define SSLHAF_STATE_GOAWAY 3

#define SSLHAF_BUF_LIMIT 16384

#define SSLHAF_SESSION_ID_LENGTH_LIMIT 32

#define SSLHAF_PROTOCOL_CHANGE_CIPHER_SPEC 20
#define SSLHAF_PROTOCOL_HANDSHAKE 22
#define SSLHAF_PROTOCOL_APPLICATION 23

/**
 * The ids of TLS compression methods.
 */
#define SSLHAF_COMPRESSION_METHOD_NULL 0
#define SSLHAF_COMPRESSION_METHOD_DEFLATE 1
#define SSLHAF_COMPRESSION_METHOD_LZS 64

/**
 * The types and names used for TLS extensions.
 */
#define SSLHAF_EXTENSION_SNI_TYPE 0x0000
#define SSLHAF_EXTENSION_SNI_NAME "server_name"

#define SSLHAF_EXTENSION_UNSUPPORTED_NAME "sslhaf unsupported"

/**
 * Return codes used by sslhaf functions.
 */
#define SSLHAF_OK 1
#define SSLHAF_AGAIN -11
#define SSLHAF_NOMEM -12
#define SSLHAF_INVAL -22

/**
 * Helper function to set and return an error code.
 */
#define SSLHAF_RETURN_ERROR(cfg, err) \
    (cfg)->last_error_code = (err); \
    (cfg)->last_error_line = __LINE__; \
    return (err);



/**
 * Holds information about a TLS cipher suite.
 */
struct sslhaf_suite_t {
    const char *label;
    uint32_t id;
    uint16_t key_len;
};

typedef struct sslhaf_suite_t sslhaf_suite_t;



/**
 * Holds information about TLS compression methods.
 */
struct sslhaf_compression_method_t {
    uint8_t method;
};

typedef struct sslhaf_compression_method_t sslhaf_compression_method_t;



/**
 * Holds information about various supported TLS extensions.
 */
struct sslhaf_extension_sni_t {
    uint8_t type;

    /* Number of server names listed. */
    uint16_t server_names_len;

    /* Server names listed */
    char **server_names;
};

typedef struct sslhaf_extension_sni_t sslhaf_extension_sni_t;


struct sslhaf_extension_t {
    const char *name;
    uint16_t type;

    union {
        struct sslhaf_extension_sni_t sni;
    } detail;
};

typedef struct sslhaf_extension_t sslhaf_extension_t;



/**
 * The structure that maintains user preferences, parsing state and parsed data
 */
struct sslhaf_cfg_t {
    /* Inspection state; see above for the constants. */
    int state;

    /* The TLS protocol of the transaction under scrutiny. */
    int buf_protocol;

    /* The buffer we use to store the first SSL packet. */
    unsigned char *buf;
    size_t buf_off;
    size_t buf_len;
    size_t buf_to_go;

    /* The amount of input data used during one call to decode_buffer. */
    size_t input_used_session;

    /* The amount of data used in total. */
    size_t input_used_total;

    /* The client hello version used; 2 or 3. */
    uint8_t hello_version;

    /* SSL version indicated in the handshake. */
    uint8_t protocol_high;
    uint8_t protocol_low;

    /* How many bytes are there for session id in the handshake? */
    uint16_t session_id_len;

    /* A session id might be seen in the handshake for session reuse.
     * If session_id_len is 0, always NULL*/
    unsigned char* session_id;

    /* How many suites are there? */
    uint16_t suites_len;

    /* A list of details of all suites seen in the handshake. */
    const sslhaf_suite_t **suites;

    /* How many compression methods are there. */
    uint8_t compression_len;

    /* A list of details of all compression methods seen in the handshake. */
    sslhaf_compression_method_t **compression_methods;

    /* How many extensions were there in the handshake? */
    uint16_t extensions_len;

    /* A list of details of all extensions seen in the handshake. */
    sslhaf_extension_t **extensions;

    /* The entire raw handshake packet, consisting of a record layer packet
     * with a Client Hello inside it.
     * Encoded as a string of hexadecimal characters. */
    char *tclient_hello;

    /* Handshake version as string. */
    char *thandshake;

    /* Protocol version number as string. */
    char *tprotocol;

    /* A string of a comma separated list of cipher suites seen in the handshake. */
    char *tsuites;

    /* A string of a comma separated list of compression methods seen in the handshake. */
    char *tcompmethods;

    /* A string of a comma separated list of all extensions seen in the handshake. */
    char *textensions;

    /* How many requests were there on this connection? */
    size_t request_counter;

    /* How many output buckets seen on a connection */
    size_t out_bucket_count;

    /* How many output buckets sent before first input data fragment. */
    size_t in_data_fragment_out_buckets;

    /* How many input data fragments seen before first output data fragment. */
    size_t in_data_fragments;

    /* Indicates the connection has switched to encrypted handshake messages. */
    bool seen_cipher_change;

    /* Last error information. Useful for debugging. */
    int last_error_code;
    size_t last_error_line;

    /* User data */
    void *user_data;

    /* A pointer to the controlled memory alloc function. */
    void* (*alloc_fn)(struct sslhaf_cfg_t *cfg, size_t size);
    /* A pointer to the controlled memory free function. */
    void (*free_fn)(struct sslhaf_cfg_t *cfg, void *obj);
    /* A pointer to a limited stream printf style function.
     * If buf is NULL, len is to be ignored and the return buffer should be
     * dynamically allocated. */
    char* (*snprintf_fn)(struct sslhaf_cfg_t *cfg,
                         char *buf, size_t len, const char *format, ...);
    /* A pointer to a memory free function for snprintf allocated buffers.
     * Author may simply use free_fn here as well. */
    void (*free_snprintf_fn)(struct sslhaf_cfg_t *cfg, void *buf);
    /* A pointer to an error logging printf style function. */
    void (*log_fn)(struct sslhaf_cfg_t *cfg, const char *format, ...);

    /* User configuration flag indicating whether printable text copies of
     * handshake information should be made. OFF by default. */
    bool do_create_strings;
};

typedef struct sslhaf_cfg_t sslhaf_cfg_t;



/**
 * Create and initialise a sslhaf_cfg object using a default function set:
 *   alloc/free_fn: uses malloc(3) and free(3)
 *   snprintf_fn: uses vsnprintf(3) or vasprintf(3)
 *   free_snprintf_fn: uses free(3)
 *   log_fn: is NULL
 * User data will be NULL.
 */
sslhaf_cfg_t *sslhaf_cfg_create_default(void);

/**
 * Create and initialise a sslhaf_cfg object using a default function set:
 *   alloc/free_fn: uses malloc(3) and free(3)
 *   snprintf_fn: uses vsnprintf(3) or vasprintf(3)
 *   free_snprintf_fn: uses free(3)
 *   log_fn: uses vprintf(3)
 * User data will be NULL.
 */
sslhaf_cfg_t *sslhaf_cfg_create_verbose(void);

/**
 * Create and initialise a sslhaf_cfg object
 */
sslhaf_cfg_t *sslhaf_cfg_create(
    void *user_data,
    void* (*alloc_fn)(struct sslhaf_cfg_t *cfg, size_t size),
    void (*free_fn)(struct sslhaf_cfg_t *cfg, void *obj),
    char* (*snprintf_fn)(struct sslhaf_cfg_t *cfg,
            char *msgbuf, size_t len, const char *format, ...),
    void (*free_snprintf_fn)(struct sslhaf_cfg_t *cfg, void *buf),
    void (*log_fn)(struct sslhaf_cfg_t *cfg, const char *format, ...));

/**
 * Retrieve configuration flag indicating whether printable text copies of
 * handshake information should be made. */
bool sslhaf_cfg_get_create_strings(const sslhaf_cfg_t *cfg);

/**
 * Set the configuration flag indicating whether printable text copies of
 * handshake information should be made. */
void sslhaf_cfg_set_create_strings(sslhaf_cfg_t *cfg, bool create_strings);

/**
 * Cleanup and free a sslhaf_cfg object
 */
void sslhaf_cfg_destroy(sslhaf_cfg_t *cfg);

/**
 * Deal with a single buffer. We look for a handshake SSL packet, buffer it
 * (possibly across several invocations), then invoke a functions to analyse it.
 */
int sslhaf_decode_buffer(sslhaf_cfg_t *cfg,
    const unsigned char *inputbuf, size_t inputlen);

/**
 * Resolve a cipher id into an SSLv2 or TLS cipher suite description.
 */
const sslhaf_suite_t *sslhaf_get_suite(uint32_t id);

/**
 * Resolve a TLS extension id into a sslhaf extension type.
 */
const char *sslhaf_get_extension_name(uint16_t type);

#ifdef __cplusplus
}; // extern "C"
#endif

#endif /* SSLHAF_H */
