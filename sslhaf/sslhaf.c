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

#include <apr_strings.h>
#include <http_log.h>

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
static int decode_packet_v2(ap_filter_t *f, sslhaf_cfg_t *cfg) {
    unsigned char *buf = cfg->buf;
    apr_size_t len = cfg->buf_len;
    int cslen;
    unsigned char *q;

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
    if (len < (apr_size_t)cslen) {
        return -2;
    }

    // In SSLv2 each suite consumes 3 bytes.
    cslen = cslen / 3;

    // Keep the pointer to where the suites begin. The memory
    // was allocated from the connection pool, so it should
    // be around for as long as we need it.
    cfg->slen = cslen;
    cfg->suites = (const char *)buf;

    cfg->thandshake = apr_psprintf(f->c->pool, "%i", cfg->hello_version);
    cfg->tprotocol = apr_psprintf(f->c->pool, "%i.%i", cfg->protocol_high, cfg->protocol_low);

    // Create a list of suites as text, for logging. Each 3-byte
    // suite can consume up to 6 bytes (in hexadecimal form) with
    // an additional byte for a comma. We need 9 bytes at the
    // beginning (handshake and version), as well as a byte for
    // the terminating NUL byte.
    q = apr_pcalloc(f->c->pool, (cslen * 7) + 1);
    if (q == NULL) {
        return -3;
    }

    cfg->tsuites = (const char *)q;

    // Extract cipher suites; each suite consists of 3 bytes.
    while(cslen--) {
        if ((const char *)q != cfg->tsuites) {
            *q++ = ',';
        }

        if (*buf != 0) {
            c2x(*buf, q);
            q += 2;

            c2x(*(buf + 1), q);
            q += 2;
        } else {
            if (*(buf + 1) != 0) {
                c2x(*(buf + 1), q);
                q += 2;
            }
        }

        c2x(*(buf + 2), q);
        q += 2;

        buf += 3;
    }

    *q = '\0';

    return 1;
}

/**
 * Decode SSLv3+ packet containing handshake data.
 */
static int decode_packet_v3_handshake(ap_filter_t *f, sslhaf_cfg_t *cfg) {
    unsigned char *buf = cfg->buf;
    apr_size_t len = cfg->buf_len;

    #ifdef ENABLE_DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
        "mod_sslhaf [%s]: decode_packet_v3_handshake (len %" APR_SIZE_T_FMT ")",
        f->c->remote_ip, len);
    #endif

    // Loop while there's data in buffer
    while(len > 0) {
        apr_size_t ml;
        int mt;

        #ifdef ENABLE_DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
            "mod_sslhaf [%s]: decode_packet_v3_handshake loop (len %" APR_SIZE_T_FMT,
            f->c->remote_ip, len);
        #endif

        // Check for size first
        if (len < 4) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                "mod_sslhaf [%s]: Decoding packet v3 HANDSHAKE: Packet too small %" APR_SIZE_T_FMT,
                f->c->remote_ip, len);

            return -1;
        }

        // Message type
        mt = buf[0];

        // Message length
        ml = (buf[1] * 65536) + (buf[2] * 256) + buf[3];

        #ifdef ENABLE_DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
            "mod_sslhaf [%s]: decode_packet_v3_handshake mt %d %" APR_SIZE_T_FMT,
            f->c->remote_ip, mt, ml);
        #endif

        if (mt != 1) {
            return 1;
        }

        // Does the message length correspond
        // to the size of our buffer?
        if (ml > len - 4) {
            ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                "mod_sslhaf [%s]: Decoding packet v3 HANDSHAKE: Length mismatch. Expecting %"
                APR_SIZE_T_FMT " got %" APR_SIZE_T_FMT, f->c->remote_ip, ml, len - 4);

            return -2;
        }

        // Is this a Client Hello message?
        if (mt == 1) {
            unsigned char *p = buf + 4; // skip over the message type and length
            unsigned char *q;
            apr_size_t mylen = ml;
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

            if (mylen < (apr_size_t)idlen) { // for the ID
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

            if (mylen < (apr_size_t)cslen * 2) { // for the suites
                return -7;
            }

            // Keep the pointer to where the suites begin. The memory
            // was allocated from the connection pool, so it should
            // be around for as long as we need it.
            cfg->slen = cslen;
            cfg->suites = (const char *)p;

            cfg->thandshake = apr_psprintf(f->c->pool, "%d", cfg->hello_version);
            cfg->tprotocol = apr_psprintf(f->c->pool, "%d.%d", cfg->protocol_high, cfg->protocol_low);

            // Create a list of suites as text, for logging
            q = apr_pcalloc(f->c->pool, (cslen * 7) + 1);
            cfg->tsuites = (const char *)q;

            // Extract cipher suites; each suite consists of 2 bytes
            while(cslen--) {
                if ((const char *)q != cfg->tsuites) {
                    *q++ = ',';
                }

                if (*p != 0) {
                    c2x(*p, q);
                    q += 2;
                }

                c2x(*(p + 1), q);
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
            q = apr_pcalloc(f->c->pool, (clen * 3) + 1);
            cfg->compression_methods = (const char *)q;

            while(clen--) {
                if ((const char *)q != cfg->compression_methods) {
                    *q++ = ',';
                }

                c2x(*p, q);
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
            q = apr_pcalloc(f->c->pool, (elen * 5) + 1);
            cfg->extensions = (const char *)q;

            while(elen > 0) {
                cfg->extensions_len++;

                if ((const char *)q != cfg->extensions) {
                    *q++ = ',';
                }

                // extension type, byte 1
                c2x(*p, q);
                p++;
                elen--;
                q += 2;

                // extension type, byte 2
                c2x(*p, q);
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
static int decode_packet_v3(ap_filter_t *f, sslhaf_cfg_t *cfg) {
    /* Handshake */
    if (cfg->buf_protocol == PROTOCOL_HANDSHAKE) {
        if (cfg->seen_cipher_change == 0) {
            return decode_packet_v3_handshake(f, cfg);
        } else {
            // Ignore encrypted handshake messages
            return 1;
        }
    } else
    /* Application data */
    if (cfg->buf_protocol == PROTOCOL_APPLICATION) {
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
    if (cfg->buf_protocol == PROTOCOL_CHANGE_CIPHER_SPEC) {
        cfg->seen_cipher_change = 1;
        return 1;
    } else {
        // Ignore unknown protocols
        return 1;
    }
}

/**
 * Deal with a single bucket. We look for a handshake SSL packet, buffer
 * it (possibly across several invocations), then invoke a function to analyse it.
 */
int sslhaf_decode_bucket(ap_filter_t *f, sslhaf_cfg_t *cfg,
    const unsigned char *inputbuf, apr_size_t inputlen)
{
    #ifdef ENABLE_DEBUG
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
        "mod_sslhaf [%s]: decode_bucket (inputlen %" APR_SIZE_T_FMT ")", f->c->remote_ip, inputlen);
    #endif

    // Loop while there's input to process
    while(inputlen > 0) {
        #ifdef ENABLE_DEBUG
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
        "mod_sslhaf [%s]: decode_bucket (inputlen %" APR_SIZE_T_FMT ", state %d)", f->c->remote_ip, inputlen, cfg->state);
        #endif

        // Are we looking for the next packet of data?
        if ((cfg->state == STATE_START)||(cfg->state == STATE_READING)) {
            apr_size_t len;

            // Are we expecting a handshake packet?
            if (cfg->state == STATE_START) {
                if ((inputbuf[0] != PROTOCOL_HANDSHAKE)&&(inputbuf[0] != 128)) {
                    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
                        "mod_sslhaf: First byte (%d) of this connection does not indicate SSL; skipping", inputbuf[0]);
                        return -1;
                }
            }

            // Check for SSLv3+
            if (  (inputbuf[0] == PROTOCOL_HANDSHAKE)
                ||(inputbuf[0] == PROTOCOL_APPLICATION)
                ||(inputbuf[0] == PROTOCOL_CHANGE_CIPHER_SPEC))
            {
                // Remember protocol
                cfg->buf_protocol = inputbuf[0];

                // Go over the protocol byte
                inputbuf++;
                inputlen--;

                // Are there enough bytes to begin analysis?
                if (inputlen < 4) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                        "mod_sslhaf [%s]: Less than 5 bytes from the packet available in this bucket",
                        f->c->remote_ip);
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
                if ((len <= 0)||(len > BUF_LIMIT)) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                        "mod_sslhaf [%s]: TLS record too long: %" APR_SIZE_T_FMT "; limit %d",
                        f->c->remote_ip, len, BUF_LIMIT);
                    return -1;
                }

                // Go over the packet length bytes
                inputbuf += 2;
                inputlen -= 2;

                // Allocate a buffer to hold the entire packet
                cfg->buf = malloc(len);
                if (cfg->buf == NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                        "mod_sslhaf [%s]: Failed to allocate %" APR_SIZE_T_FMT " bytes",
                        f->c->remote_ip, len);
                    return -1;
                }

                // Go into buffering mode
                cfg->state = STATE_BUFFER;
                cfg->buf_len = 0;
                cfg->buf_to_go = len;

                #ifdef ENABLE_DEBUG
                ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, f->c->base_server,
                    "mod_sslhaf [%s]: decode_bucket; buffering protocol %d high %d low %d len %" APR_SIZE_T_FMT,
                    f->c->remote_ip, cfg->buf_protocol, cfg->protocol_high, cfg->protocol_low, len);
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
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                        "mod_sslhaf [%s]: Less than 5 bytes from the packet available in this bucket",
                        f->c->remote_ip);
                    return -1;
                }

                // Check that it is indeed ClientHello
                if (inputbuf[1] != 1) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                        "mod_sslhaf [%s]: Not SSLv2 ClientHello (%d)",
                        f->c->remote_ip, inputbuf[1]);
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
                if ((len <= 0)||(len > BUF_LIMIT)) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                        "mod_sslhaf [%s]: TLS record too long: %" APR_SIZE_T_FMT "; limit %d",
                        f->c->remote_ip, len, BUF_LIMIT);
                    return -1;
                }

                // Go over the packet length (1 byte), message
                // type (1 byte) and version (2 bytes)
                inputbuf += 4;
                inputlen -= 4;

                // Allocate a buffer to hold the entire packet
                cfg->buf = malloc(len);
                if (cfg->buf == NULL) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                        "mod_sslhaf [%s]: Failed to allocate %" APR_SIZE_T_FMT " bytes",
                        f->c->remote_ip, len);
                    return -1;
                }

                // Go into buffering mode
                cfg->state = STATE_BUFFER;
                cfg->buf_len = 0;
                cfg->buf_to_go = len;
            }
            else {
                // Unknown protocol
                return -1;
            }
        }

        // Are we buffering?
        if (cfg->state == STATE_BUFFER) {
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
                    rc = decode_packet_v3(f, cfg);
                } else {
                    rc = decode_packet_v2(f, cfg);
                }

                // Free the packet buffer, which we no longer need
                free(cfg->buf);
                cfg->buf = NULL;

                if (rc < 0) {
                    ap_log_error(APLOG_MARK, APLOG_ERR, 0, f->c->base_server,
                        "mod_sslhaf [%s]: Packet decoding error rc %d (hello %d)",
                        f->c->remote_ip, rc, cfg->hello_version);
                    return -1;
                }

                // Go back to looking at the next packet
                cfg->state = STATE_READING;

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
