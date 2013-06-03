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

#include "sslhaf.h"

#include <string.h>
#include <errno.h>



#if defined(__x86_64__)
# define SSLHAF_SIZE_T_FMT                                     "lu"
#else
# define SSLHAF_SIZE_T_FMT                                     "u"
#endif



#if 0
/**
 * Convert the bytes given on input into their hexadecimal representation.
 */
static char *mod_sslhaf_bytes2hex(apr_pool_t *pool, unsigned char *data, int len) {
    static unsigned char b2hex[] = "0123456789abcdef";
    char *hex = NULL;
    int i, j;

    hex = apr_palloc(pool, (len * 2) + 1);
    if (hex == NULL) return NULL;

    j = 0;
    for(i = 0; i < len; i++) {
        hex[j++] = b2hex[data[i] >> 4];
        hex[j++] = b2hex[data[i] & 0x0f];
    }

    hex[j] = '\0';

    return hex;
}

/**
 * Generate a SHA1 hash of the supplied data.
 */
static char *mod_sslhaf_generate_sha1(apr_pool_t *pool, char *data, int len) {
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t context;

    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)data, len);
    apr_sha1_final(digest, &context);

    return mod_sslhaf_bytes2hex(pool, digest, APR_SHA1_DIGESTSIZE);
}
#endif




sslhaf_cfg_t *sslhaf_cfg_create(
        void *user_data,
        void* (*alloc_fn)(struct sslhaf_cfg_t *cfg, size_t size),
        void (*free_fn)(struct sslhaf_cfg_t *cfg, void* obj),
        char* (*snprintf_fn)(struct sslhaf_cfg_t *cfg,
                char *inputbuf, size_t len, const char *format, ...),
        void (*log_fn)(struct sslhaf_cfg_t *cfg, const char *format, ...)) {
    sslhaf_cfg_t *cfg;
    sslhaf_cfg_t temp_cfg;
    memset(&temp_cfg, 0, sizeof(temp_cfg));
    temp_cfg.user_data = user_data;

    cfg = (*alloc_fn)(&temp_cfg, sizeof(*cfg));
    if (cfg == NULL)
        return NULL;

    memset(cfg, 0, sizeof(*cfg));

    cfg->user_data = user_data;
    cfg->alloc_fn = alloc_fn;
    cfg->free_fn = free_fn;
    cfg->snprintf_fn = snprintf_fn;
    cfg->log_fn = log_fn;

    return cfg;
}

void sslhaf_cfg_destroy(sslhaf_cfg_t *cfg) {
    sslhaf_cfg_t temp_cfg;
    memset(&temp_cfg, 0, sizeof(temp_cfg));
    temp_cfg.user_data = cfg->user_data;

    if (cfg->buf != NULL) {
        cfg->free_fn(cfg, cfg->buf);
        cfg->buf = NULL;
    }

    cfg->suites = NULL;

    if (cfg->thandshake != NULL) {
        cfg->free_fn(cfg, cfg->thandshake);
        cfg->thandshake = NULL;
    }

    if (cfg->tprotocol != NULL) {
        cfg->free_fn(cfg, cfg->tprotocol);
        cfg->tprotocol = NULL;
    }

    if (cfg->tsuites != NULL) {
        cfg->free_fn(cfg, cfg->tsuites);
        cfg->tsuites = NULL;
    }

    if (cfg->compression_methods != NULL) {
        cfg->free_fn(cfg, cfg->compression_methods);
        cfg->compression_methods = NULL;
    }

    if (cfg->extensions != NULL) {
        cfg->free_fn(cfg, cfg->extensions);
        cfg->extensions = NULL;
    }

    cfg->user_data = NULL;

    void (*free_fn)(struct sslhaf_cfg_t *cfg, void* obj) = cfg->free_fn;
    (*free_fn)(&temp_cfg, cfg);
}



/**
 * Convert one byte into its hexadecimal representation.
 */
static char *sslhaf_c2x(unsigned char what, char *where) {
    static const char c2x_table[] = "0123456789abcdef";

    what = what & 0xff;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0x0f];

    return where;
}



/**
 * Decode SSLv2 packet.
 */
static int sslhaf_decode_packet_v2(sslhaf_cfg_t *cfg) {
    unsigned char *buf = cfg->buf;
    size_t len = cfg->buf_len;
    int cslen;
    char *q;

    // There are 6 bytes before the list of cipher suites:
    // cipher suite length (2 bytes), session ID length (2 bytes)
    // and challenge length (2 bytes).
    if (len < 6) {
        return -1;
    }

    // How many bytes do the cipher suites consume?
    cslen = (buf[0] * 256) + buf[1];

    // Skip over to the list.
    buf += 6;
    len -= 6;

    // Check that we have the suites in the buffer.
    if (len < (size_t)cslen) {
        return -2;
    }

    // In SSLv2 each suite consumes 3 bytes.
    cslen = cslen / 3;

    // Keep the pointer to where the suites begin. The memory
    // was allocated by the caller, so it should be around for as
    // long as we need it.
    cfg->slen = cslen;
    cfg->suites = (const char *)buf;

    cfg->thandshake = cfg->snprintf_fn(cfg,
        NULL, 0, "%i", cfg->hello_version);
    cfg->tprotocol = cfg->snprintf_fn(cfg,
        NULL, 0, "%i.%i", cfg->protocol_high, cfg->protocol_low);

    // Create a list of suites as text, for logging. Each 3-byte
    // suite can consume up to 6 bytes (in hexadecimal form) with
    // an additional byte for a comma. We need 9 bytes at the
    // beginning (handshake and version), as well as a byte for
    // the terminating NUL byte.
    cfg->tsuites = cfg->alloc_fn(cfg, (cslen * 7) + 1);
    if (cfg->tsuites == NULL) {
        return -3;
    }

    q = cfg->tsuites;

    // Extract cipher suites; each suite consists of 3 bytes.
    while(cslen--) {
        if (q != cfg->tsuites) {
            *q++ = ',';
        }

        if (*buf != 0) {
            sslhaf_c2x(*buf, q);
            q += 2;

            sslhaf_c2x(*(buf + 1), q);
            q += 2;
        } else {
            if (*(buf + 1) != 0) {
                sslhaf_c2x(*(buf + 1), q);
                q += 2;
            }
        }

        sslhaf_c2x(*(buf + 2), q);
        q += 2;

        buf += 3;
    }

    *q = '\0';

    return 1;
}

/**
 * Decode SSLv3+ packet containing handshake data.
 */
static int sslhaf_decode_packet_v3_handshake(sslhaf_cfg_t *cfg) {
    unsigned char *buf = cfg->buf;
    size_t len = cfg->buf_len;

    #ifdef SSLHAF_ENABLE_DEBUG
    if (cfg->log_fn != NULL)
        cfg->log_fn(cfg,
            "sslhaf_decode_packet_v3_handshake (len %" SSLHAF_SIZE_T_FMT ")",
                len);
    #endif

    // Loop while there's data in buffer
    while(len > 0) {
        size_t ml;
        int mt;

        #ifdef SSLHAF_ENABLE_DEBUG
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "sslhaf_decode_packet_v3_handshake loop (len %" SSLHAF_SIZE_T_FMT,
                    len);
        #endif

        // Check for size first
        if (len < 4) {
            if (cfg->log_fn != NULL)
                cfg->log_fn(cfg,
                    "Decoding packet v3 HANDSHAKE: Packet too small %" SSLHAF_SIZE_T_FMT,
                        len);

            return -1;
        }

        // Message type
        mt = buf[0];

        // Message length
        ml = (buf[1] * 65536) + (buf[2] * 256) + buf[3];

        #ifdef SSLHAF_ENABLE_DEBUG
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "sslhaf_decode_packet_v3_handshake mt %d %" SSLHAF_SIZE_T_FMT,
                    mt, ml);
        #endif

        if (mt != 1) {
            return 1;
        }

        // Does the message length correspond
        // to the size of our buffer?
        if (ml > len - 4) {
            if (cfg->log_fn != NULL)
                cfg->log_fn(cfg,
                    "Decoding packet v3 HANDSHAKE: Length mismatch. Expecting %"
                    SSLHAF_SIZE_T_FMT " got %" SSLHAF_SIZE_T_FMT,
                        ml, len - 4);

            return -2;
        }

        // Is this a Client Hello message?
        if (mt == 1) {
            unsigned char *p = buf + 4; // skip over the message type and length
            char *q;
            size_t mylen = ml;
            int idlen;
            int cslen;

            if (mylen < 34) { // for the version number and random value
                return -3;
            }

            p += 2; // version number
            p += 32; // random value
            mylen -= 34;

            if (mylen < 1) { // for the ID length byte
                return -4;
            }

            idlen = *p;
            p += 1; // ID len
            mylen -= 1;

            if (mylen < (size_t)idlen) { // for the ID
                return -5;
            }

            p += idlen; // ID
            mylen -= idlen;

            if (mylen < 2) { // for the CS length bytes
                return -6;
            }

            cslen = (*p * 256) + *(p + 1);
            cslen = cslen / 2; // each suite consumes 2 bytes

            p += 2; // Cipher Suites len
            mylen -= 2;

            if (mylen < (size_t)cslen * 2) { // for the suites
                return -7;
            }

            // Keep the pointer to where the suites begin. The memory
            // was allocated from the connection pool, so it should
            // be around for as long as we need it.
            cfg->slen = cslen;
            cfg->suites = (const char *)p;

            cfg->thandshake = cfg->snprintf_fn(cfg,
                NULL, 0, "%d", cfg->hello_version);
            cfg->tprotocol = cfg->snprintf_fn(cfg,
                NULL, 0, "%d.%d", cfg->protocol_high, cfg->protocol_low);

            // Create a list of suites as text, for logging
            cfg->tsuites = cfg->alloc_fn(cfg, (cslen * 7) + 1);
            if (cfg->tsuites == NULL) {
                return -8;
            }

            q = cfg->tsuites;

            // Extract cipher suites; each suite consists of 2 bytes
            while(cslen--) {
                if (q != cfg->tsuites) {
                    *q++ = ',';
                }

                if (*p != 0) {
                    sslhaf_c2x(*p, q);
                    q += 2;
                }

                sslhaf_c2x(*(p + 1), q);
                q += 2;

                p += 2;
            }

            *q = '\0';
            mylen -= cfg->slen * 2;

            // Compression
            if (mylen < 1) { // compression data length
                return -9;
            }

            int clen = *p++;
            mylen--;

            if (mylen < (size_t)clen) { // compression data
                return -10;
            }

            cfg->compression_len = clen;

            cfg->compression_methods = cfg->alloc_fn(cfg, (clen * 3) + 1);
            if (cfg->compression_methods == NULL) {
                return -11;
            }

            q = cfg->compression_methods;

            while(clen--) {
                if (q != cfg->compression_methods) {
                    *q++ = ',';
                }

                sslhaf_c2x(*p, q);
                p++;
                q += 2;
            }

            *q = '\0';
            mylen -= cfg->compression_len;

            if (mylen == 0) {
                // It's OK if there is no more data; that means
                // we're seeing a handshake without any extensions
                return 1;
            }

            // Extensions
            if (mylen < 2) { // extensions length
                return -12;
            }

            int elen = (*p * 256) + *(p + 1);

            mylen -= 2;
            p += 2;

            if (mylen < (size_t)elen) { // extension data
                return -13;
            }

            cfg->extensions_len = 0;
            cfg->extensions = cfg->alloc_fn(cfg, (elen * 5) + 1);
            if (cfg->extensions == NULL) {
                return -14;
            }

            q = cfg->extensions;

            while(elen > 0) {
                cfg->extensions_len++;

                if (q != cfg->extensions) {
                    *q++ = ',';
                }

                // extension type, byte 1
                sslhaf_c2x(*p, q);
                p++;
                elen--;
                q += 2;

                // extension type, byte 2
                sslhaf_c2x(*p, q);
                p++;
                elen--;
                q += 2;

                // extension length
                int ext1len = (*p * 256) + *(p + 1);
                p += 2;
                elen -= 2;

                // skip over extension data
                p += ext1len;
                elen -= ext1len;
            }

            *q = '\0';
        }

        // Skip over the message
        len -= 4;
        len -= ml;
        buf += 4;
        buf += ml;
    }

    return 1;
}

/**
 * Decode SSLv3+ packet data.
 */
static int sslhaf_decode_packet_v3(sslhaf_cfg_t *cfg) {
    /* Handshake */
    if (cfg->buf_protocol == SSLHAF_PROTOCOL_HANDSHAKE) {
        if (cfg->seen_cipher_change == 0) {
            return sslhaf_decode_packet_v3_handshake(cfg);
        } else {
            // Ignore encrypted handshake messages
            return 1;
        }
    } else
    /* Application data */
    if (cfg->buf_protocol == SSLHAF_PROTOCOL_APPLICATION) {
        // On first data fragment, remember how many
        // output buckets we have seen so far
        if (cfg->in_data_fragments == 0) {
            cfg->in_data_fragment_out_buckets = cfg->out_bucket_count;
            cfg->in_data_fragments++;
        } else {
            // Increment data fragement counter for as
            // long as the output bucket counter remains
            // the same
            if (cfg->out_bucket_count == cfg->in_data_fragment_out_buckets) {
                cfg->in_data_fragments++;
            }
        }

        return 1;
    } else
    /* Change cipher spec */
    if (cfg->buf_protocol == SSLHAF_PROTOCOL_CHANGE_CIPHER_SPEC) {
        cfg->seen_cipher_change = 1;
        return 1;
    } else {
        // Ignore unknown protocols
        return 1;
    }
}

/**
 * Deal with a single buffer. We look for a handshake SSL packet, buffer
 * it (possibly across several invocations), then invoke a function to analyse it.
 */
int sslhaf_decode_buffer(sslhaf_cfg_t *cfg,
    const unsigned char *inputbuf, size_t inputlen)
{
    if (cfg->state == SSLHAF_STATE_GOAWAY) {
        return -1;
    }

    #ifdef SSLHAF_ENABLE_DEBUG
    if (cfg->log_fn != NULL)
        cfg->log_fn(cfg,
            "decode_bucket (inputlen %" SSLHAF_SIZE_T_FMT ")",
                inputbuflen);
    #endif

    // Loop while there's input to process
    while(inputlen > 0) {
        #ifdef SSLHAF_ENABLE_DEBUG
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "decode_bucket (inputlen %" SSLHAF_SIZE_T_FMT ", state %d)",
                    inputbuflen, cfg->state);
        #endif

        // Are we looking for the next packet of data?
        if ((cfg->state == SSLHAF_STATE_START)||(cfg->state == SSLHAF_STATE_READING)) {
            size_t len;

            // Are we expecting a handshake packet?
            if (cfg->state == SSLHAF_STATE_START) {
                if ((inputbuf[0] != SSLHAF_PROTOCOL_HANDSHAKE)&&(inputbuf[0] != 128)) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "First byte (%d) of this connection does not indicate SSL; skipping",
                                inputbuf[0]);
                    return -1;
                }
            }

            // Check for SSLv3+
            if (  (inputbuf[0] == SSLHAF_PROTOCOL_HANDSHAKE)
                ||(inputbuf[0] == SSLHAF_PROTOCOL_APPLICATION)
                ||(inputbuf[0] == SSLHAF_PROTOCOL_CHANGE_CIPHER_SPEC))
            {
                // Remember protocol
                cfg->buf_protocol = inputbuf[0];

                // Go over the protocol byte
                inputbuf++;
                inputlen--;

                // Are there enough bytes to begin analysis?
                if (inputlen < 4) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Less than 4 bytes from the packet available in this buffer");
                    return -1;
                }

                cfg->hello_version = 3;
                cfg->protocol_high = inputbuf[0];
                cfg->protocol_low = inputbuf[1];

                // Go over the version bytes
                inputbuf += 2;
                inputlen -= 2;

                // Calculate packet length
                len = (inputbuf[0] * 256) + inputbuf[1];

                // Limit what we are willing to accept
                if ((len <= 0)||(len > SSLHAF_BUF_LIMIT)) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "TLS record too long: %" SSLHAF_SIZE_T_FMT "; limit %d",
                                len, SSLHAF_BUF_LIMIT);
                    return -1;
                }

                // Go over the packet length bytes
                inputbuf += 2;
                inputlen -= 2;

                // Allocate a buffer to hold the entire packet
                cfg->buf = cfg->alloc_fn(cfg, len);
                if (cfg->buf == NULL) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Failed to allocate %" SSLHAF_SIZE_T_FMT " bytes",
                                len);
                    return -1;
                }

                // Go into buffering mode
                cfg->state = SSLHAF_STATE_BUFFER;
                cfg->buf_len = 0;
                cfg->buf_to_go = len;

                #ifdef SSLHAF_ENABLE_DEBUG
                if (cfg->log_fn != NULL)
                    cfg->log_fn(cfg,
                        "decode_bucket; buffering protocol %d high %d low %d len %" SSLHAF_SIZE_T_FMT,
                            cfg->buf_protocol,
                            cfg->protocol_high, cfg->protocol_low, len);
                #endif
            }
            else
            // Is it a SSLv2 ClientHello?
            if (inputbuf[0] == 128) {
                // Go over packet type
                inputbuf++;
                inputlen--;

                // Are there enough bytes to begin analysis?
                if (inputlen < 4) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Less than 5 bytes from the packet available in this bucket");
                    return -1;
                }

                // Check that it is indeed ClientHello
                if (inputbuf[1] != 1) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Not SSLv2 ClientHello (%d)",
                                inputbuf[1]);
                    return -1;
                }

                cfg->hello_version = 2;

                if ((inputbuf[2] == 0x00)&&(inputbuf[3] == 0x02)) {
                    // SSL v2 uses 0x0002 for the version number
                    cfg->protocol_high = inputbuf[3];
                    cfg->protocol_low = inputbuf[2];
                } else {
                    // SSL v3 will use 0x0300, 0x0301, etc.
                    cfg->protocol_high = inputbuf[2];
                    cfg->protocol_low = inputbuf[3];
                }

                // We've already consumed 3 bytes from the packet
                len = inputbuf[0] - 3;

                // Limit what we are willing to accept
                if ((len <= 0)||(len > SSLHAF_BUF_LIMIT)) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "TLS record too long: %" SSLHAF_SIZE_T_FMT "; limit %d",
                              len, SSLHAF_BUF_LIMIT);
                    return -1;
                }

                // Go over the packet length (1 byte), message
                // type (1 byte) and version (2 bytes)
                inputbuf += 4;
                inputlen -= 4;

                // Allocate a buffer to hold the entire packet
                cfg->buf = cfg->alloc_fn(cfg, len);
                if (cfg->buf == NULL) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Failed to allocate %" SSLHAF_SIZE_T_FMT " bytes",
                                len);
                    return -1;
                }

                // Go into buffering mode
                cfg->state = SSLHAF_STATE_BUFFER;
                cfg->buf_len = 0;
                cfg->buf_to_go = len;
            }
            else {
                // Unknown protocol
                return -1;
            }
        }

        // Are we buffering?
        if (cfg->state == SSLHAF_STATE_BUFFER) {
            // How much data is available?
            if (cfg->buf_to_go <= inputlen) {
                int rc;

                // We have enough data to complete this packet
                memcpy(cfg->buf + cfg->buf_len, inputbuf, cfg->buf_to_go);
                cfg->buf_len += cfg->buf_to_go;
                inputbuf += cfg->buf_to_go;
                inputlen -= cfg->buf_to_go;
                cfg->buf_to_go = 0;

                // Decode the packet now
                if (cfg->hello_version == 3) {
                    rc = sslhaf_decode_packet_v3(cfg);
                } else {
                    rc = sslhaf_decode_packet_v2(cfg);
                }

                // Free the packet buffer, which we no longer need
                cfg->free_fn(cfg, cfg->buf);
                cfg->buf = NULL;

                if (rc < 0) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Packet decoding error rc %d (hello %d)",
                                rc, cfg->hello_version);
                    return -1;
                }

                // Go back to looking at the next packet
                cfg->state = SSLHAF_STATE_READING;

                return rc;
            } else {
                // There's not enough data; copy what we can and
                // we'll get the rest later
                memcpy(cfg->buf + cfg->buf_len, inputbuf, inputlen);
                cfg->buf_len += inputlen;
                cfg->buf_to_go -= inputlen;
                inputbuf += inputlen;
                inputlen = 0;
            }
        }
    }

    return 1;
}
