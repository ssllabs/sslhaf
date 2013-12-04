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

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>



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



/*
 * Default pluggable functions.
 */
static void* sslhaf_default_alloc_fn(sslhaf_cfg_t *cfg, size_t size) {
  return malloc(size);
  }

static void sslhaf_default_free_fn(sslhaf_cfg_t *cfg, void* obj) {
  free(obj);
  }

static char* sslhaf_default_snprintf_fn(sslhaf_cfg_t *cfg,
    char *buf, size_t len, const char *format, ...) {
  va_list ap;
  va_start(ap, format);

  if (buf != NULL)
    {
    vsnprintf(buf, len, format, ap);
    }
  else
    {
    int ret = vasprintf(&buf, format, ap);
    (void)ret;
    }

  va_end(ap);

  return buf;
  }

static void sslhaf_default_log_fn(sslhaf_cfg_t *cfg, const char *format, ...) {
  va_list ap;
  va_start(ap, format);

  vprintf(format, ap);

  va_end(ap);
  }



sslhaf_cfg_t *sslhaf_cfg_create_default(void) {
    return sslhaf_cfg_create(NULL,
        &sslhaf_default_alloc_fn,
        &sslhaf_default_free_fn,
        &sslhaf_default_snprintf_fn,
        &sslhaf_default_free_fn,
        NULL);
}

sslhaf_cfg_t *sslhaf_cfg_create_verbose(void) {
    return sslhaf_cfg_create(NULL,
        &sslhaf_default_alloc_fn,
        &sslhaf_default_free_fn,
        &sslhaf_default_snprintf_fn,
        &sslhaf_default_free_fn,
        &sslhaf_default_log_fn);
}

sslhaf_cfg_t *sslhaf_cfg_create(
        void *user_data,
        void* (*alloc_fn)(struct sslhaf_cfg_t *cfg, size_t size),
        void (*free_fn)(struct sslhaf_cfg_t *cfg, void *obj),
        char* (*snprintf_fn)(struct sslhaf_cfg_t *cfg,
                char *inputbuf, size_t len, const char *format, ...),
        void (*free_snprintf_fn)(struct sslhaf_cfg_t *cfg, void *buf),
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
    cfg->free_snprintf_fn = free_snprintf_fn;
    cfg->log_fn = log_fn;

    cfg->do_create_strings = false;

    return cfg;
}

bool sslhaf_cfg_get_create_strings(const sslhaf_cfg_t *cfg) {
    return cfg->do_create_strings;
}

void sslhaf_cfg_set_create_strings(sslhaf_cfg_t *cfg, bool create_strings) {
    cfg->do_create_strings = create_strings;
}

void sslhaf_cfg_destroy(sslhaf_cfg_t *cfg) {
    sslhaf_cfg_t temp_cfg;
    memset(&temp_cfg, 0, sizeof(temp_cfg));
    temp_cfg.user_data = cfg->user_data;
    temp_cfg.free_fn = cfg->free_fn;
    temp_cfg.free_snprintf_fn = cfg->free_snprintf_fn;

    if (cfg->buf != NULL) {
        cfg->free_fn(cfg, cfg->buf);
        cfg->buf = NULL;
    }

    if (cfg->suites != NULL) {
        for (unsigned int suite_count = 0;
                suite_count < cfg->suites_len; suite_count++) {
                cfg->suites[suite_count] = NULL;
        }

        cfg->free_fn(cfg, cfg->suites);
        cfg->suites = NULL;
    }

    if (cfg->compression_methods != NULL) {
        for (unsigned int comp_count = 0;
                comp_count < cfg->compression_len; comp_count++) {
            if (cfg->compression_methods[comp_count] == NULL) {
                continue;
            }

            cfg->free_fn(cfg, cfg->compression_methods[comp_count]);
            cfg->compression_methods[comp_count] = NULL;
        }

        cfg->free_fn(cfg, cfg->compression_methods);
        cfg->compression_methods = NULL;
    }

    if (cfg->extensions != NULL) {
        for (unsigned int ext_count = 0;
                ext_count < cfg->extensions_len; ext_count++) {
            if (cfg->extensions[ext_count] == NULL) {
                continue;
            }

            if (cfg->extensions[ext_count]->type == SSLHAF_EXTENSION_SNI_TYPE){
                sslhaf_extension_sni_t *sni =
                    &cfg->extensions[ext_count]->detail.sni;

                for (unsigned int names_count = 0;
                        names_count < sni->server_names_len; names_count++) {
                    cfg->free_fn(cfg, sni->server_names[names_count]);
                    sni->server_names[names_count] = NULL;
                }

                cfg->free_fn(cfg, sni->server_names);
                sni->server_names = NULL;
            }

            cfg->free_fn(cfg, cfg->extensions[ext_count]);
            cfg->extensions[ext_count] = NULL;
        }

        cfg->free_fn(cfg, cfg->extensions);
        cfg->extensions = NULL;
    }

    if (cfg->tclient_hello != NULL) {
        cfg->free_fn(cfg, cfg->tclient_hello);
        cfg->tclient_hello = NULL;
    }

    if (cfg->thandshake != NULL) {
        temp_cfg.free_snprintf_fn(cfg, cfg->thandshake);
        cfg->thandshake = NULL;
    }

    if (cfg->tprotocol != NULL) {
        temp_cfg.free_snprintf_fn(cfg, cfg->tprotocol);
        cfg->tprotocol = NULL;
    }

    if (cfg->tsuites != NULL) {
        cfg->free_fn(cfg, cfg->tsuites);
        cfg->tsuites = NULL;
    }

    if (cfg->tcompmethods != NULL) {
        cfg->free_fn(cfg, cfg->tcompmethods);
        cfg->tcompmethods = NULL;
    }

    if (cfg->textensions != NULL) {
        cfg->free_fn(cfg, cfg->textensions);
        cfg->textensions = NULL;
    }

    memset(cfg, 0, sizeof(sslhaf_cfg_t));

    temp_cfg.free_fn(&temp_cfg, cfg);
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
 * Resolve a TLS extension id into a sslhaf extension type.
 */
const char *sslhaf_get_extension_name(uint16_t type) {
    switch (type) {
        case SSLHAF_EXTENSION_SNI_TYPE:
            return SSLHAF_EXTENSION_SNI_NAME;
    };

    return SSLHAF_EXTENSION_UNSUPPORTED_NAME;
}



/**
 * Decode SSLv2 packet.
 */
static int sslhaf_decode_packet_v2(sslhaf_cfg_t *cfg) {
    char *q;
    uint16_t section_to_go;
    uint16_t obj_count;

    // There are 6 bytes before the list of cipher suites:
    // cipher suite length (2 bytes), session ID length (2 bytes)
    // and challenge length (2 bytes).
    if (cfg->buf_len < 6) {
        SSLHAF_RETURN_ERROR(cfg, SSLHAF_AGAIN);
    }

    if (cfg->do_create_strings) {
        // record packet information as strings
        cfg->thandshake = cfg->snprintf_fn(cfg,
            NULL, 0, "%i", cfg->hello_version);
        if (cfg->thandshake == NULL) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
        }
        cfg->tprotocol = cfg->snprintf_fn(cfg,
            NULL, 0, "%i.%i", cfg->protocol_high, cfg->protocol_low);
        if (cfg->tprotocol == NULL) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
        }
    }

    // How many bytes do the cipher suites consume?
    section_to_go =
        (cfg->buf[cfg->buf_off] * 256) +
        cfg->buf[cfg->buf_off + 1];

    // Skip over to the list.
    cfg->buf_off += 6;
    cfg->buf_len -= 6;
    cfg->buf_to_go -= 6;

    cfg->input_used_session += 6;
    cfg->input_used_total += 6;

    // Check that we have the suites in the buffer.
    if (cfg->buf_len < section_to_go) {
        SSLHAF_RETURN_ERROR(cfg, SSLHAF_AGAIN);
    }

    cfg->suites_len = section_to_go / 3; // In SSLv2 each suite consumes 3 bytes.
    cfg->suites = cfg->alloc_fn(cfg,
        sizeof(sslhaf_suite_t*) * cfg->suites_len);
    if (cfg->suites == NULL) {
        SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
    }
    memset(cfg->suites, 0,
        sizeof(sslhaf_suite_t*) * cfg->suites_len);

    // Extract cipher suites; each suite consists of 3 bytes.
    for (obj_count = 0; obj_count < cfg->suites_len; ++obj_count) {
        if (cfg->do_create_strings) {
            // Create a list of suites as text, for logging. Each 3-byte
            // suite can consume up to 6 bytes (in hexadecimal form) with
            // an additional byte for a comma.  The last entry has no comma,
            // instead it has a NUL byte.
            if (cfg->tsuites == NULL) {
                cfg->tsuites = cfg->alloc_fn(cfg, (cfg->suites_len * 7));
                if (cfg->tsuites == NULL) {
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
                }

                q = cfg->tsuites;
            } else {
                *q++ = ',';
            }

            if (cfg->buf[cfg->buf_off] != 0) {
                sslhaf_c2x(cfg->buf[cfg->buf_off], q);
                q += 2;

                sslhaf_c2x(cfg->buf[cfg->buf_off + 1], q);
                q += 2;
            } else if (cfg->buf[cfg->buf_off + 1] != 0) {
                sslhaf_c2x(cfg->buf[cfg->buf_off + 1], q);
                q += 2;
            }

            sslhaf_c2x(cfg->buf[cfg->buf_off + 2], q);
            q += 2;

            q[0] = '\0';
        }

        cfg->suites[obj_count] = sslhaf_get_suite(
            (cfg->buf[cfg->buf_off] * 65536) +
            (cfg->buf[cfg->buf_off + 1] * 256) +
             cfg->buf[cfg->buf_off + 2]);

        cfg->buf_off += 3;
        cfg->buf_len -= 3;
        cfg->buf_to_go -= 3;

        cfg->input_used_session += 3;
        cfg->input_used_total += 3;

        section_to_go -= 3;
    }

    if (section_to_go > 0) {
        SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
    }

    return SSLHAF_OK;
}

/**
 * Decode SSLv3+ packet containing handshake data.
 */
static int sslhaf_decode_packet_v3_handshake(sslhaf_cfg_t *cfg) {
    unsigned char *p, *t;
    char *q;
    size_t msg_len;
    size_t msg_to_go, section_to_go, sub_section_to_go, object_to_go;
    size_t temp_to_go;
    uint8_t msg_type;

    // Check for size first
    if (cfg->buf_len == 0) {
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "Decoding packet v3 HANDSHAKE: Packet too small %" SSLHAF_SIZE_T_FMT,
                    cfg->buf_len);

        SSLHAF_RETURN_ERROR(cfg, SSLHAF_AGAIN);
    }

    #ifdef SSLHAF_ENABLE_DEBUG
    if (cfg->log_fn != NULL)
        cfg->log_fn(cfg,
            "sslhaf_decode_packet_v3_handshake (len %" SSLHAF_SIZE_T_FMT ")",
                cfg->buf_len);
    #endif

    if (cfg->do_create_strings) {
        // make a copy of the entire Client Hello and convert it to hex
        cfg->tclient_hello = cfg->alloc_fn(cfg,
            (cfg->buf_to_go * 2) + 1);
        if (cfg->tclient_hello == NULL) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
        }

        temp_to_go = cfg->buf_to_go;

        t = cfg->buf;
        q = cfg->tclient_hello;

        // now encode the client hello
        while (temp_to_go--) {
            sslhaf_c2x(*t, q);
            q += 2;
            t += 1;
        }
        q[0] = '\0';

        // record packet information as strings
        cfg->thandshake = cfg->snprintf_fn(cfg,
            NULL, 0, "%i", cfg->hello_version);
        if (cfg->thandshake == NULL) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
        }
        cfg->tprotocol = cfg->snprintf_fn(cfg,
            NULL, 0, "%i.%i", cfg->protocol_high, cfg->protocol_low);
        if (cfg->tprotocol == NULL) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
        }
    }

    // Loop while there's data in buffer
    while (cfg->buf_len > 0) {
        #ifdef SSLHAF_ENABLE_DEBUG
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "sslhaf_decode_packet_v3_handshake loop (len %" SSLHAF_SIZE_T_FMT,
                    cfg->buf_len);
        #endif

        // Check for size first
        if (cfg->buf_len < 4) {
            if (cfg->log_fn != NULL)
                cfg->log_fn(cfg,
                    "Decoding packet v3 HANDSHAKE: Packet too small %" SSLHAF_SIZE_T_FMT,
                        cfg->buf_len);

            SSLHAF_RETURN_ERROR(cfg, SSLHAF_AGAIN);
        }

        // Message type
        msg_type = cfg->buf[cfg->buf_off + 0];

        // Is this a Client Hello message?
        if (msg_type != 1) {
            return SSLHAF_OK;
        }

        // Message length
        msg_len =
            (cfg->buf[cfg->buf_off + 1] * 65536) +
            (cfg->buf[cfg->buf_off + 2] * 256) +
             cfg->buf[cfg->buf_off + 3];

        p = cfg->buf + cfg->buf_off + 4; // skip over the message type and length
        msg_to_go = msg_len;

        // Does the message length correspond
        // to the size of our buffer?
        if (cfg->buf_len != (msg_len + 4)) {
            if (cfg->log_fn != NULL)
                cfg->log_fn(cfg,
                    "Decoding packet v3 HANDSHAKE: Length mismatch. Expecting %"
                    SSLHAF_SIZE_T_FMT " got %" SSLHAF_SIZE_T_FMT,
                        cfg->buf_len - 4, msg_len);
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        #ifdef SSLHAF_ENABLE_DEBUG
        if (cfg->log_fn != NULL)
            cfg->log_fn(cfg,
                "sslhaf_decode_packet_v3_handshake mt %d %" SSLHAF_SIZE_T_FMT,
                    msg_type, msg_len);
        #endif

        if (msg_to_go < 34) { // for the version number and random value
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        // Use the version number from Client Hello, overriding the
        // value we got earlier. Some clients will always set the
        // version number in the Record Layer to TLS 1.0, even if they
        // support better protocols.            
        cfg->protocol_high = p[0];
        cfg->protocol_low = p[1];

        p += 2; // version number
        p += 32; // random value
        msg_to_go -= 34;

        if (msg_to_go < 1) { // for the ID length byte
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        section_to_go = p[0]; // length of ID section

        p += 1; // ID len
        msg_to_go -= 1;

        if (msg_to_go < section_to_go) { // for the ID
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        p += section_to_go; // seek past the ID
        msg_to_go -= section_to_go;

        if (msg_to_go < 2) { // for the CS length bytes
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        section_to_go = (p[0] * 256) + p[1];

        p += 2; // Cipher Suites len
        msg_to_go -= 2;

        if (msg_to_go < section_to_go) { // for the suites
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        cfg->suites_len = section_to_go / 2; // 2 bytes per suite id
        cfg->suites = cfg->alloc_fn(cfg,
            sizeof(sslhaf_suite_t*) * cfg->suites_len);
        if (cfg->suites == NULL) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
        }
        memset(cfg->suites, 0,
            sizeof(sslhaf_suite_t*) * cfg->suites_len);

        // Extract cipher suites; each suite consists of 2 bytes
        for (uint16_t suite_count = 0; suite_count < cfg->suites_len;
                suite_count++) {
            if (cfg->do_create_strings) {
                if (cfg->tsuites == NULL) {
                    // Create a list of suites as text, for logging. Each 2-byte
                    // suite can consume up to 4 bytes (in hexadecimal form) with
                    // an additional byte for a comma.  The last entry has no comma,
                    // instead it has a NUL byte.
                    cfg->tsuites = cfg->alloc_fn(cfg, (cfg->suites_len * 5));
                    if (cfg->tsuites == NULL) {
                        SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
                    }

                    q = cfg->tsuites;
                } else {
                    *q++ = ',';
                }

                if (p[0] != 0) {
                    sslhaf_c2x(p[0], q);
                    q += 2;
                }

                sslhaf_c2x(p[1], q);
                q += 2;

                q[0] = '\0';
            }

            cfg->suites[suite_count] = sslhaf_get_suite((p[0] * 256) + p[1]);

            p += 2;
            msg_to_go -= 2;
            section_to_go -= 2;
        }

        // Compression
        if (msg_to_go < 1) { // compression data length
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        section_to_go = p[0]; // length of compression method section

        p++;
        msg_to_go--;

        if (msg_to_go < section_to_go) { // compression data
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        cfg->compression_len = section_to_go / 1; // 1 byte per compression method
        cfg->compression_methods = cfg->alloc_fn(cfg,
            sizeof(sslhaf_compression_method_t*) * cfg->compression_len);
        if (cfg->compression_methods == NULL) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
        }
        memset(cfg->compression_methods, 0,
            sizeof(sslhaf_compression_method_t*) * cfg->compression_len);

        for (uint16_t comp_count = 0; comp_count < cfg->compression_len;
                comp_count++) {
            if (cfg->do_create_strings) {
                if (cfg->tcompmethods == NULL) {
                    // Create a list of compression methods as text, for logging. Each 1-byte
                    // method can consume up to 2 bytes (in hexadecimal form) with
                    // an additional byte for a comma.  The last entry has no comma,
                    // instead it has a NUL byte.
                    cfg->tcompmethods = cfg->alloc_fn(cfg, (cfg->compression_len * 3));
                    if (cfg->tcompmethods == NULL) {
                        SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
                    }

                    q = cfg->tcompmethods;
                } else {
                    *q++ = ',';
                }

                sslhaf_c2x(p[0], q);
                q += 2;

                q[0] = '\0';
            }

            cfg->compression_methods[comp_count] = cfg->alloc_fn(cfg,
                sizeof(sslhaf_compression_method_t));
            if (cfg->compression_methods[comp_count] == NULL) {
                SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
            }

            cfg->compression_methods[comp_count]->method = p[0];

            p++;
            msg_to_go--;
            section_to_go--;
        }

        if (msg_to_go == 0) {
            // It's OK if there is no more data; that means
            // we're seeing a handshake without any extensions
            return SSLHAF_OK;
        }

        // Extensions
        if (msg_to_go < 2) { // extensions length
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        section_to_go = (p[0] * 256) + p[1]; // length of extensions section

        p += 2;
        msg_to_go -= 2;

        if (msg_to_go < section_to_go) { // extension data
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        temp_to_go = section_to_go;
        t = p;

        cfg->extensions_len = 0;

        while (temp_to_go > 0) {
            if (temp_to_go < 4) {
                SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
            }

            // skip extension type
            t += 2;
            temp_to_go -= 2;

            // quick validation of extension length
            sub_section_to_go = (t[0] * 256) + t[1];

            t += 2;
            temp_to_go -= 2;

            if (temp_to_go < sub_section_to_go) {
                SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
            }

            t += sub_section_to_go;
            temp_to_go -= sub_section_to_go;

            cfg->extensions_len++;
        }

        cfg->extensions = cfg->alloc_fn(cfg,
            sizeof(sslhaf_extension_t*) * cfg->extensions_len);
        if (cfg->extensions == NULL) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
        }
        memset(cfg->extensions, 0,
            sizeof(sslhaf_extension_t*) * cfg->extensions_len);

        for (uint16_t ext_count = 0; ext_count < cfg->extensions_len;
                ext_count++) {
            uint16_t extension_type;

            if (cfg->do_create_strings) {
                // Create a list of compression methods as text, for logging. Each 3-byte
                // method can consume up to 4 bytes (in hexadecimal form) with
                // an additional byte for a comma.  The last entry has no comma,
                // instead it has a NUL byte.
                if (cfg->textensions == NULL) {
                    cfg->textensions = cfg->alloc_fn(cfg, (cfg->extensions_len * 5));
                    if (cfg->textensions == NULL) {
                        SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
                    }

                    q = cfg->textensions;
                } else {
                    *q++ = ',';
                }

                // extension type, byte 1
                sslhaf_c2x(p[0], q);
                q += 2;

                // extension type, byte 2
                sslhaf_c2x(p[1], q);
                q += 2;

                q[0] = '\0';
            }

            // extension type
            extension_type = (p[0] * 256) + p[1];

            // extension length, validation performed in previous iteration
            sub_section_to_go = (p[2] * 256) + p[3];

            p += 4;
            msg_to_go -= 4;
            section_to_go -= 4;

            cfg->extensions[ext_count] = cfg->alloc_fn(cfg,
                sizeof(sslhaf_extension_t));
            if (cfg->extensions[ext_count] == NULL) {
                SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
            }
            memset(cfg->extensions[ext_count], 0, sizeof(sslhaf_extension_t));

            cfg->extensions[ext_count]->type = extension_type;
            cfg->extensions[ext_count]->name = sslhaf_get_extension_name(
                extension_type);

            if (cfg->extensions[ext_count]->type == SSLHAF_EXTENSION_SNI_TYPE) {
                sslhaf_extension_sni_t *sni =
                    &cfg->extensions[ext_count]->detail.sni;

                if (sub_section_to_go < 5) {
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
                }

                object_to_go = (p[0] * 256) + p[1];

                p += 2;
                msg_to_go -= 2;
                section_to_go -= 2;
                sub_section_to_go -= 2;

                if (object_to_go != sub_section_to_go) {
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
                }

                temp_to_go = object_to_go;
                t = p;

                while (temp_to_go > 0) {
                    // ignore host name type

                    // calculate server name len and validate
                    uint16_t name_len = (t[1] * 256) + t[2];

                    t += 3;
                    temp_to_go -= 3;

                    if (temp_to_go < name_len) {
                        SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
                    }

                    t += name_len;
                    temp_to_go -= name_len;

                    sni->server_names_len++;
                }

                sni->server_names = cfg->alloc_fn(cfg,
                    sizeof(char*) * sni->server_names_len);
                if (sni->server_names == NULL) {
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
                }

                for (uint16_t name_count = 0;
                        name_count < sni->server_names_len; name_count++) {
                    // ignore host name type

                    // don't need to validate again
                    uint16_t name_len = (p[1] * 256) + p[2];

                    p += 3;
                    msg_to_go -= 3;
                    section_to_go -= 3;
                    sub_section_to_go -= 3;

                    sni->server_names[name_count] = cfg->alloc_fn(cfg,
                        (name_len + 1));
                    if (sni->server_names[name_count] == NULL) {
                        SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
                    }
                    memcpy(sni->server_names[name_count], p, name_len);

                    sni->server_names[name_count][name_len] = '\0';

                    p += name_len;
                    msg_to_go -= name_len;
                    section_to_go -= name_len;
                    sub_section_to_go -= name_len;
                }
            } else {
                p += sub_section_to_go;
                msg_to_go -= sub_section_to_go;
                section_to_go -= sub_section_to_go;
            }
        }

        if ((msg_to_go > 0) || (section_to_go > 0)) {
            SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
        }

        // Skip over the message
        cfg->buf_off += (4 + msg_len);
        cfg->buf_len -= (4 + msg_len);
        cfg->buf_to_go -= (4 + msg_len);

        cfg->input_used_session += (4 + msg_len);
        cfg->input_used_total += (4 + msg_len);
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
            // specifically handle this message in this state
            return sslhaf_decode_packet_v3_handshake(cfg);
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
    } else
    /* Change cipher spec */
    if (cfg->buf_protocol == SSLHAF_PROTOCOL_CHANGE_CIPHER_SPEC) {
        cfg->seen_cipher_change = 1;
    }

    // consume buffer data up to one message
    cfg->buf_off += cfg->buf_to_go;
    cfg->buf_len -= cfg->buf_to_go;

    cfg->input_used_session += cfg->buf_to_go;
    cfg->input_used_total += cfg->buf_to_go;

    cfg->buf_to_go = 0;

    return SSLHAF_OK;
}

/**
 * Deal with a single buffer. We look for a handshake SSL packet, buffer
 * it (possibly across several invocations), then invoke a function to analyse it.
 */
int sslhaf_decode_buffer(sslhaf_cfg_t *cfg,
        const unsigned char *inputbuf, size_t inputlen)
{
    cfg->input_used_session = 0;
    cfg->last_error_code = 0;
    cfg->last_error_line = 0;

    if (cfg->state == SSLHAF_STATE_GOAWAY) {
        return SSLHAF_OK;
    }

    #ifdef SSLHAF_ENABLE_DEBUG
    if (cfg->log_fn != NULL)
        cfg->log_fn(cfg,
            "decode_bucket (inputlen %" SSLHAF_SIZE_T_FMT ")",
                inputbuflen);
    #endif

    // Loop while there's input to process
    while (inputlen > 0) {
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
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
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
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_AGAIN);
                }

                cfg->hello_version = 3;
                // Remember the protocol version used,
                // but only if we don't already have it
                if (cfg->protocol_high == 0) {
                    cfg->protocol_high = inputbuf[0];
                    cfg->protocol_low = inputbuf[1];
                }

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
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
                }

                // Go over the packet length bytes
                inputbuf += 2;
                inputlen -= 2;

                // Go into buffering mode
                cfg->state = SSLHAF_STATE_BUFFER;

                // state the requirement for additional buffered data
                cfg->buf_to_go += len;

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
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
                }

                // Check that it is indeed ClientHello
                if (inputbuf[1] != 1) {
                    if (cfg->log_fn != NULL)
                        cfg->log_fn(cfg,
                            "Not SSLv2 ClientHello (%d)",
                                inputbuf[1]);
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
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
                    SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
                }

                // Go over the packet length (1 byte), message
                // type (1 byte) and version (2 bytes)
                inputbuf += 4;
                inputlen -= 4;

                // Go into buffering mode
                cfg->state = SSLHAF_STATE_BUFFER;

                // state the requirement for additional buffered data
                cfg->buf_to_go = len;

                #ifdef SSLHAF_ENABLE_DEBUG
                if (cfg->log_fn != NULL)
                    cfg->log_fn(cfg,
                        "decode_bucket; buffering protocol %d high %d low %d len %" SSLHAF_SIZE_T_FMT,
                            cfg->buf_protocol,
                            cfg->protocol_high, cfg->protocol_low, len);
                #endif
            }
            else {
                // Unknown protocol
                SSLHAF_RETURN_ERROR(cfg, SSLHAF_INVAL);
            }
        }

        // Are we buffering?
        if (cfg->state == SSLHAF_STATE_BUFFER) {
            if (inputlen > 0) {
                // only buffer what is required
                size_t to_buffer = (cfg->buf_to_go < inputlen) ?
                    cfg->buf_to_go : inputlen;

                if (cfg->buf == NULL) {
                    // allocate buffer space for the first time
                    cfg->buf = cfg->alloc_fn(cfg, to_buffer);
                    if (cfg->buf == NULL) {
                        if (cfg->log_fn != NULL)
                            cfg->log_fn(cfg,
                                "Failed to allocate %" SSLHAF_SIZE_T_FMT " bytes",
                                    to_buffer);
                        SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
                    }
                } else {
                    // allocate additional space to handle the new data
                    unsigned char *old_buf = cfg->buf;

                    cfg->buf = cfg->alloc_fn(cfg,
                        cfg->buf_len + to_buffer);
                    if (cfg->buf == NULL) {
                        cfg->buf = old_buf;
                        if (cfg->log_fn != NULL)
                            cfg->log_fn(cfg,
                                "Failed to allocate %" SSLHAF_SIZE_T_FMT " bytes",
                                    to_buffer);
                        SSLHAF_RETURN_ERROR(cfg, SSLHAF_NOMEM);
                    }

                    // copy old data into head of new buffer
                    memcpy(cfg->buf, old_buf + cfg->buf_off, cfg->buf_len);

                    cfg->buf_off = 0;
                    // buf_len unchanged

                    cfg->free_fn(cfg, old_buf);
                }

                // place inputbuf into the sslhaf buffer
                memcpy(cfg->buf + cfg->buf_off + cfg->buf_len, inputbuf, to_buffer);
                cfg->buf_len += to_buffer;

                inputbuf += to_buffer;
                inputlen -= to_buffer;
            }

            // How much data is available?
            if (cfg->buf_to_go <= cfg->buf_len) {
                int rc;

                // Decode the packet now
                if (cfg->hello_version == 3) {
                    rc = sslhaf_decode_packet_v3(cfg);
                } else {
                    rc = sslhaf_decode_packet_v2(cfg);
                }

                // Has all data in the buffer been used up?
                if (cfg->buf_to_go == 0) {
                    cfg->free_fn(cfg, cfg->buf);
                    cfg->buf = NULL;
                    cfg->buf_off = 0;
                    cfg->buf_len = 0;
                    cfg->buf_to_go = 0;
                }

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
                // There's not enough data, wait for more
                SSLHAF_RETURN_ERROR(cfg, SSLHAF_AGAIN);
            }
        }
    }

    return 1;
}
