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
# define SSLHAF_SIZE_T_FMT                                     "d"
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
    temp_cfg.user_data = user_data;

    cfg = (*alloc_fn)(&temp_cfg, sizeof(*cfg));
    if (cfg == NULL)
        return NULL;

    cfg->user_data = user_data;
    cfg->alloc_fn = alloc_fn;
    cfg->free_fn = free_fn;
    cfg->snprintf_fn = snprintf_fn;
    cfg->log_fn = log_fn;

    return cfg;
}

void sslhaf_cfg_destroy(sslhaf_cfg_t *cfg) {
    cfg->inputbuf = NULL;
    cfg->suites = NULL;
    cfg->thandshake = NULL;
    cfg->tprotocol = NULL;
    cfg->tsuites = NULL;
    cfg->ipaddress_hash = NULL;
    cfg->compression_methods = NULL;
    cfg->extensions = NULL;
    cfg->user_data = NULL;
}



/**
 * Convert one byte into its hexadecimal representation.
 */
static unsigned char *c2x(unsigned what, unsigned char *where) {
    static const char c2x_table[] = "0123456789abcdef";

    what = what & 0xff;
    *where++ = c2x_table[what >> 4];
    *where++ = c2x_table[what & 0x0f];

    return where;
}



/**
 * Decode SSLv2 packet.
 */
int decode_packet_v2(sslhaf_cfg_t *cfg) {
    unsigned char *q;
    unsigned char *inputbuf = cfg->inputbuf + cfg->inputbufoff;
    size_t inputlen = cfg->inputbuflen - cfg->inputbufoff;
    int cslen;
    int sidlen;
    int chlen;

    // There are 6 bytes before the list of cipher suites:
    // cipher suite length (2 bytes), session ID length (2 bytes)
    // and challenge length (2 bytes).
    if (inputlen < 6)
        return -EAGAIN;

    // How many bytes do the cipher suites consume?
    cslen = (inputbuf[0] << 8) + inputbuf[1];
    // How many bytes does the sessionid consume?
    sidlen = (inputbuf[2] << 8) + inputbuf[3];
    // How many bytes does the challenge consume?
    chlen = (inputbuf[4] << 8) + inputbuf[5];

    // validate lengths
    if ((cslen + sidlen + chlen) != cfg->inputtogo) {
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "TLS handshake sections length doesn't match packet size: "
                "%" SSLHAF_SIZE_T_FMT " != " SSLHAF_SIZE_T_FMT,
                    (cslen + sidlen + chlen), cfg->inputtogo);
        return -EINVAL;
    }

    // Skip over to the list.
    cfg->inputbufoff += 6;
    cfg->inputtogo -= 6;
    inputbuf += 6;
    inputlen -= 6;

    // Check that we have the suites in the buffer.
    if (inputlen < (size_t)cslen) {
        return -EAGAIN;
    }

    // In SSLv2 each suite consumes 3 bytes.
    cslen = cslen / 3;

    // Keep the pointer to where the suites begin.
    cfg->slen = cslen;
    cfg->suites = (const char *)inputbuf;

    cfg->thandshake = cfg->snprintf_fn(cfg, NULL, 0, "%i", cfg->hello_version);
    cfg->tprotocol = cfg->snprintf_fn(cfg, NULL, 0, "%i.%i", cfg->protocol_high, cfg->protocol_low);

    // Create a list of suites as text, for logging. Each 3-byte
    // suite can consume up to 6 bytes (in hexadecimal form) with
    // an additional byte for a comma. We need 9 bytes at the
    // beginning (handshake and version), as well as a byte for
    // the terminating NUL byte.
    q = cfg->alloc_fn(cfg, (cslen * 7) + 1);
    if (q == NULL) {
        return -3;
    }

    cfg->tsuites = (const char *)q;

    // Extract cipher suites; each suite consists of 3 bytes.
    while(cslen--) {
        if ((const char *)q != cfg->tsuites) {
            *q++ = ',';
        }

        if (*inputbuf != 0) {
            sslhaf_c2x(*inputbuf, q);
            q += 2;

            sslhaf_c2x(*(inputbuf + 1), q);
            q += 2;
        } else {
            if (*(inputbuf + 1) != 0) {
                sslhaf_c2x(*(inputbuf + 1), q);
                q += 2;
            }
        }

        sslhaf_c2x(*(inputbuf + 2), q);
        q += 2;

        inputbuf += 3;
    }

    *q = '\0';

    return 1;
}

/**
 * Decode SSLv3+ packet containing handshake data.
 */
static int decode_packet_v3_handshake(sslhaf_cfg_t *cfg) {
    unsigned char *buf = cfg->inputbuf;
    size_t len = cfg->inputbuflen;

    #ifdef ENABLE_DEBUG
    if (cfg->log_fn != NULL)
        cfg->log_fn(cfg,
            "decode_packet_v3_handshake (len %" SSLHAF_SIZE_T_FMT ")",
                len);
    #endif

    // Loop while there's data in buffer
    while (len > 0) {
        size_t ml;
        int mt;

        #ifdef ENABLE_DEBUG
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "decode_packet_v3_handshake loop (len %" SSLHAF_SIZE_T_FMT,
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

        #ifdef ENABLE_DEBUG
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "decode_packet_v3_handshake mt %d %" SSLHAF_SIZE_T_FMT,
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
            unsigned char *q;
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

            cfg->thandshake = cfg->snprintf_fn(cfg, NULL, 0, "%d", cfg->hello_version);
            cfg->tprotocol = cfg->snprintf_fn(cfg, NULL, 0, "%d.%d", cfg->protocol_high, cfg->protocol_low);

            // Create a list of suites as text, for logging
            q = cfg->alloc_fn(cfg, (cslen * 7) + 1);
            cfg->tsuites = (const char *)q;

            // Extract cipher suites; each suite consists of 2 bytes
            while(cslen--) {
                if ((const char *)q != cfg->tsuites) {
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
                return -8;
            }

            int clen = *p++;
            mylen--;

            if (mylen < clen) { // compression data
                return -9;
            }

            cfg->compression_len = clen;
            q = cfg->alloc_fn(cfg, (clen * 3) + 1);
            cfg->compression_methods = (const char *)q;

            while(clen--) {
                if ((const char *)q != cfg->compression_methods) {
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
                return -10;
            }

            int elen = (*p * 256) + *(p + 1);

            mylen -= 2;
            p += 2;

            if (mylen < elen) { // extension data
                return -11;
            }

            cfg->extensions_len = 0;
            q = cfg->alloc_fn(cfg, (elen * 5) + 1);
            cfg->extensions = (const char *)q;

            while(elen > 0) {
                cfg->extensions_len++;

                if ((const char *)q != cfg->extensions) {
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
static int decode_packet_v3(sslhaf_cfg_t *cfg) {
    /* Handshake */
    if (cfg->record_type == SSLHAF_PROTOCOL_RECORD_TYPE_HANDSHAKE) {
        if (cfg->seen_cipher_change == 0) {
            return decode_packet_v3_handshake(cfg);
        } else {
            // Ignore encrypted handshake messages
            return 0;
        }
    } else
    /* Application data */
    if (cfg->record_type == SSLHAF_PROTOCOL_RECORD_TYPE_APPLICATION) {
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

        return 0;
    } else
    /* Change cipher spec */
    if (cfg->record_type == SSLHAF_PROTOCOL_RECORD_TYPE_CHANGE_CIPHER_SPEC) {
        cfg->seen_cipher_change = 1;
        return 0;
    }

    // Ignore unknown protocols
    return 0;
}

int sslhaf_decode_buffer(sslhaf_cfg_t *cfg,
        const unsigned char *inputbuf, size_t inputlen) {
    #ifdef ENABLE_DEBUG
    if (cfg->log_fn != NULL)
        cfg->log_fn(cfg,
            "decode_bucket (inputlen %" SSLHAF_SIZE_T_FMT ")",
                inputbuflen);
    #endif

    // Loop while there's input to process
    while (inputlen > 0) {
        #ifdef ENABLE_DEBUG
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "decode_bucket (inputlen %" SSLHAF_SIZE_T_FMT ", state %d)",
                    inputbuflen, cfg->state);
        #endif

        // Are we looking for the next packet of data?
        if ((cfg->state == SSLHAF_STATE_START) ||
                (cfg->state == SSLHAF_STATE_READING)) {
            size_t inputtogo;

            // Are we expecting a handshake packet?
            if (cfg->state == SSLHAF_STATE_START) {
                if ((inputbuf[0] != SSLHAF_PROTOCOL_RECORD_TYPE_HANDSHAKE) &&
                        !(inputbuf[0] & SSLHAF_PROTOCOL_RECORD_TYPE_2_0_HANDSHAKE)) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "First byte (%d) of this connection does not indicate SSL; skipping",
                                inputbuf[0]);
                    return -ENOTSUP;
                }
            }

            // Check for SSLv3+
            if ((inputbuf[0] == SSLHAF_PROTOCOL_RECORD_TYPE_HANDSHAKE) ||
                    (inputbuf[0] == SSLHAF_PROTOCOL_RECORD_TYPE_APPLICATION) ||
                    (inputbuf[0] == SSLHAF_PROTOCOL_RECORD_TYPE_CHANGE_CIPHER_SPEC)) {
                // Are there enough bytes to begin analysis?
                if (inputlen < 11) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Less than 11 bytes from the packet available in this buffer");
                    return -EAGAIN;
                }

                // Check that it is indeed ClientHello
                if ((inputbuf[0] != SSLHAF_PROTOCOL_RECORD_TYPE_HANDSHAKE) ||
                        (inputbuf[5] != SSLHAF_PROTOCOL_MESSAGE_TYPE_CLIENT_HELLO)) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Not SSLv3+ ClientHello (%d, %d)",
                                inputbuf[0], inputbuf[5]);
                    return -EINVAL;
                }

                cfg->record_type = inputbuf[0];
                cfg->hello_version = 3;

                // Check message version against record version
                if ((inputbuf[6] < inputbuf[1]) ||
                        (inputbuf[7] < inputbuf[2])) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "TLS message version is lower than record version: %d.%d < %d.%d",
                                inputbuf[6], inputbuf[7], inputbuf[1], inputbuf[2]);
                    return -EINVAL;
                }

                cfg->protocol_high = inputbuf[6];
                cfg->protocol_low = inputbuf[7];

                // Calculate message length (subtract two for message version)
                inputtogo = ((inputbuf[8] << 16) | (inputbuf[9] << 8) | inputbuf[10]) - 2;

                // Check message length against record length
                if (inputtogo != (((inputbuf[3] << 8) | inputbuf[4]) - 2)) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "TLS message length field mismatch: %d != %d - 4",
                                ((inputbuf[8] << 16) | (inputbuf[9] << 8) | inputbuf[10]),
                                ((inputbuf[3] << 8) | inputbuf[4]));
                    return -EINVAL;
                }

                // Zero record size?
                if (inputtogo == 0) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "TLS record too short: %" SSLHAF_SIZE_T_FMT,
                                inputtogo);
                    return -EINVAL;
                }

                // Limit what we are willing to accept
                if (inputtogo > SSLHAF_BUF_LIMIT) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "TLS record too long: %" SSLHAF_SIZE_T_FMT "; limit: %d",
                                inputtogo, SSLHAF_BUF_LIMIT);
                    return -EINVAL;
                }

                // Go over the record type (1 byte), record version (2 bytes),
                // record length (2 bytes), message type (1 byte),
                // message length (3 bytes), message version (2 bytes)
                inputbuf += 11;
                inputlen -= 11;

                // Allocate a buffer to hold the entire message
                cfg->inputbuf = cfg->alloc_fn(cfg, inputtogo);
                if (cfg->inputbuf == NULL) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Failed to allocate %" SSLHAF_SIZE_T_FMT " bytes",
                                inputtogo);
                    return -ENOMEM;
                }

                cfg->inputbuflen = 0;
                cfg->inputbufoff = 0;
                cfg->inputtogo = inputtogo;

                // Go into buffering mode
                cfg->state = SSLHAF_STATE_BUFFER;

                #ifdef ENABLE_DEBUG
                if (cfg->log_fn != NULL)
                    cfg->log_fn(cfg,
                        "decode_bucket; buffering protocol %d high %d low %d len %" SSLHAF_SIZE_T_FMT,
                            cfg->record_type, cfg->protocol_high, cfg->protocol_low, inputtogo);
                #endif
            }
            else
            // Is it a SSLv2 ClientHello?
            if (inputbuf[0] & SSLHAF_PROTOCOL_RECORD_TYPE_2_0_HANDSHAKE) {
                // Are there enough bytes to begin analysis?
                if (inputlen < 5) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Less than 5 bytes from the packet available in this buffer");
                    return -EAGAIN;
                }

                // Check that it is indeed ClientHello
                if (inputbuf[2] != SSLHAF_PROTOCOL_MESSAGE_TYPE_2_0_CLIENT_HELLO) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Not SSLv2 ClientHello (%d)",
                                inputbuf[2]);
                    return -EINVAL;
                }

                cfg->record_type = SSLHAF_PROTOCOL_RECORD_TYPE_2_0_HANDSHAKE;
                cfg->hello_version = 2;

                if ((inputbuf[3] == 0x00) && (inputbuf[4] == 0x02)) {
                    // SSL v2 uses 0x0002 for the version number
                    cfg->protocol_high = inputbuf[4];
                    cfg->protocol_low = inputbuf[3];
                } else {
                    // SSL v3 will use 0x0300, 0x0301, etc.
                    cfg->protocol_high = inputbuf[3];
                    cfg->protocol_low = inputbuf[4];
                }

                // Calculate message length
                inputtogo = (((inputbuf[0] & 0x7f) << 8) | inputbuf[1]);

                // Zero record size?
                if (inputtogo == 0) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "TLS record too short: %" SSLHAF_SIZE_T_FMT,
                                inputtogo);
                    return -EINVAL;
                }

                // Limit what we are willing to accept
                if (inputtogo > SSLHAF_BUF_LIMIT) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "TLS record too long: %" SSLHAF_SIZE_T_FMT "; limit %d",
                                inputtogo, SSLHAF_BUF_LIMIT);
                    return -EINVAL;
                }

                // Go over the packet length (2 bytes), message
                // type (1 byte) and version (2 bytes)
                inputbuf += 5;
                inputlen -= 5;

                // Allocate a buffer to hold the entire message
                cfg->inputbuf = cfg->alloc_fn(cfg, inputtogo);
                if (cfg->inputbuf == NULL) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Failed to allocate %" SSLHAF_SIZE_T_FMT " bytes",
                                inputtogo);
                    return -ENOMEM;
                }

                cfg->inputbuflen = 0;
                cfg->inputbufoff = 0;
                cfg->inputtogo = inputtogo;

                // Go into buffering mode
                cfg->state = SSLHAF_STATE_BUFFER;

                #ifdef ENABLE_DEBUG
                if (cfg->log_fn != NULL)
                    cfg->log_fn(cfg,
                        "decode_buffer; buffering protocol %d high %d low %d len %" SSLHAF_SIZE_T_FMT,
                            cfg->record_type, cfg->protocol_high, cfg->protocol_low, inputtogo);
                #endif
            }
            else {
                // Unknown protocol
                return -EINVAL;
            }
        }

        // Are we buffering?
        if (cfg->state == SSLHAF_STATE_BUFFER) {
            size_t tobufferlen =
                (inputlen < (SSLHAF_BUF_LIMIT - cfg->inputbuflen)) ?
                    inputlen :
                    (SSLHAF_BUF_LIMIT - cfg->inputbuflen);
            int rc;

            memcpy(cfg->inputbuf + cfg->inputbuflen, inputbuf, tobufferlen);

            cfg->inputbuflen += tobufferlen;
            inputbuf += tobufferlen;
            inputlen -= tobufferlen;

            // How much data is available?
            if (cfg->inputtogo <= (cfg->inputbuflen - cfg->inputbufoff)) {
                // Decode the packet now
                if (cfg->hello_version == 3) {
                    rc = decode_packet_v3(cfg);
                } else {
                    rc = decode_packet_v2(cfg);
                }

                cfg->inputbuflen = 0;
                cfg->inputbufoff = 0;
                cfg->inputtogo = 0;

                if (rc < 0) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Packet decoding error rc %d (hello %d)",
                                rc, cfg->hello_version);
                    return rc;
                }

                // Go back to looking at the next packet
                cfg->state = SSLHAF_STATE_READING;
            } else {
                // Decode part of the packet now
                if (cfg->hello_version == 3) {
                    rc = decode_packet_v3(cfg);
                } else {
                    rc = decode_packet_v2(cfg);
                }

                return rc;
            }
        }
    }

    return 0;
}
