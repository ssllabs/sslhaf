/*
 * mod_sslhaf: Apache module for passive SSL client fingerprinting
 * Copyright (c) 2009-2012 Qualys,Inc. All rights reserved.
 *
 * THIS PRODUCT IS NOT READY FOR PRODUCTION USE. DEPLOY AT YOUR OWN RISK.
 * 
 * This product is released under the terms of the General Public Licence
 * version 2 (GPLv2).
 *
 * NO WARRANTY. YOU MUST READ AND AGREE TO THE LICENCE BEFORE YOU USE THIS PROGRAM.
 */
 
/*
 * This Apache module will extract the list of SSL cipher suites
 * offered by HTTP clients during the SSL negotiation phase. The idea
 * is that different clients use different SSL implementations and
 * configure them in different ways. By looking at the differences in
 * the cipher suites we should be able to identify clients, irrespective
 * of what they seem to be (looking at HTTP request headers).
 *
 * This way of fingerprinting is much more reliable than other approaches
 * (e.g. TCP/IP fingerprinting), for the following reasons:
 *
 * - HTTP proxies do not terminate SSL, which means that every client
 *   creates a unique data stream that is sent directly to servers.
 *
 * - NAT will modify TCP/IP packets, but leave SSL data streams
 *   untouched.
 *
 *
 * To compile and install the module, do this:
 *
 *     # apxs -cia mod_sslhaf.c
 *
 * The above script will try to add a LoadModule statement to your
 * configuration file but it will fail if it can't find at least one
 * previous such statement. If that happens (you'll see the error
 * message) you'll need to add the following line manually:
 *
 *     LoadModule sslhaf_module /path/to/modules/mod_sslhaf.so
 *
 * You will also need to add a custom log to record cipher suite information.
 * For example (add to the virtual host where you want the fingerprinting
 * to take place):
 *
 *     CustomLog logs/sslhaf.log "%t %h \"%{SSLHAF_HANDSHAKE}e\" \
 *     \"%{SSLHAF_PROTOCOL}e\" \"%{SSLHAF_SUITES}e\" \"%{SSLHAF_BEAST}e\" \"%{User-Agent}i\"" 
 *
 * As an example, these are the values you'd get from a visit by the Google
 * search engine:
 *
 *     SSLHAF_HANDSHAKE 	2
 *     SSLHAF_PROTOCOL		3.1
 *     SSLHAF_SUITES		04,010080,05,0a
 *
 * The tokens have the following meaning:
 *
 * - SSL_HANDSHAKE contains the handshake version used: 2 and 3 for an SSL v2 and SSL v3+
 *   handshake, respectively. You can see in the example that Google bot uses a SSLv2 handshake,
 *   which means that it is ready to use SSL v2 or better.
 *
 * - SSL_PROTOCOL The second token contains the best SSL/TLS version supported by the client. For
 *   example, SSLv3 is "3.0"; TLS 1.0 is "3.1"; TLS 1.1 is "3.2", etc.
 *
 * - SSLHAF_SUITES contains a list of the supported cipher suites. Each value, a hexadecimal number,
 *   corresponds to one cipher suite. From the example, 0x04 stands for SSL_RSA_WITH_RC4_128_MD5,
 *   0x010080 stands for SSL_CK_RC4_128_WITH_MD5 (a SSLv2 suite) and 0x05 stands
 *   for SSL_RSA_WITH_RC4_128_SHA.
 *
 * - SSLHAF_BEAST is 1 if the 1/n-1 BEAST mitigation was detected, 0 otherwise. 
 *
 * - SSLHAF_COMPRESSION contains the list of compression methods offered by the
 *   client (NULL 00, DEFLATE 01). The field can be NULL, in which case it will appear
 *   in the logs as "-". This happens when SSLv2 handshake is used.
 *
 * - SSLHAF_LOG is defined (and contains "1") only on the first request in a connection. This
 *   variable can be used to reduce the amount of logging (SSL parameters will typically not
 *   change across requests on the same connection). Example:
 *
 *   CustomLog logs/sslhaf.log "YOUR_LOG_STRING_HERE" env=SSLHAF_LOG
 *
 */

#include "ap_config.h" 

#include "apr_lib.h"
#include "apr_hash.h"
#include "apr_optional.h"
#include "apr_sha1.h"
#include "apr_strings.h"
#define APR_WANT_STRFUNC
#include "apr_want.h"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_connection.h"
#include "http_log.h"
#include "http_protocol.h"

#include "mod_log_config.h"

module AP_MODULE_DECLARE_DATA sslhaf_module;

static const char sslhaf_in_filter_name[] = "SSLHAF_IN";
static const char sslhaf_out_filter_name[] = "SSLHAF_OUT";

struct sslhaf_cfg_t {
    /* Inspection state; see above for the constants. */
    int state;

    /* The buffer we use to store the first SSL packet.
     * Allocated from the connection pool.
     */        
    int buf_protocol;
    unsigned char *buf;
    apr_size_t buf_len;
    apr_size_t buf_to_go;
    
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
};

typedef struct sslhaf_cfg_t sslhaf_cfg_t;

#define STATE_START 	0
#define STATE_BUFFER 	1
#define STATE_READING	2
#define STATE_GOAWAY	3

#define BUF_LIMIT 	4096

#define PROTOCOL_CHANGE_CIPHER_SPEC 	20
#define PROTOCOL_HANDSHAKE		22
#define PROTOCOL_APPLICATION		23

/**
 * Convert the bytes given on input into their hexadecimal representation.
 */
char *bytes2hex(apr_pool_t *pool, unsigned char *data, int len) {
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
char *generate_sha1(apr_pool_t *pool, char *data, int len) {
    unsigned char digest[APR_SHA1_DIGESTSIZE];
    apr_sha1_ctx_t context;

    apr_sha1_init(&context);
    apr_sha1_update(&context, (const char *)data, len);
    apr_sha1_final(digest, &context);

    return bytes2hex(pool, digest, APR_SHA1_DIGESTSIZE);
}

/**
 * Convert one byte into its hexadecimal representation.
 */
unsigned char *c2x(unsigned what, unsigned char *where) {
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
static int decode_bucket(ap_filter_t *f, sslhaf_cfg_t *cfg,
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
                cfg->buf = apr_pcalloc(f->c->pool, len);
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
                cfg->buf = apr_pcalloc(f->c->pool, len);
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

/**
 * Monitor outbound data and count buckets. This will help us determine
 * if input data is fragmented (we see more than one inbound bucket before
 * we see one outbound bucket).
 */
static apr_status_t sslhaf_out_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    sslhaf_cfg_t *cfg = ap_get_module_config(f->c->conn_config, &sslhaf_module);
    apr_status_t status;
    apr_bucket *bucket;

    // Return straight away if there's no configuration
    if (cfg == NULL) {
        return ap_pass_brigade(f->next, bb);
    }    
    
    // Loop through the buckets
    for (bucket = APR_BRIGADE_FIRST(bb);
        bucket != APR_BRIGADE_SENTINEL(bb);
        bucket = APR_BUCKET_NEXT(bucket))
    {
        const char *buf = NULL;
        apr_size_t buflen = 0;
        
        if (!(APR_BUCKET_IS_METADATA(bucket))) {
            // Get bucket data
            status = apr_bucket_read(bucket, &buf, &buflen, APR_BLOCK_READ);
            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, status, f->c->base_server,
                    "mod_sslhaf [%s]: Error while reading output bucket",
                    f->c->remote_ip);
                return status;
            }
            
            // Count output buckets
            cfg->out_bucket_count++;
        }
    }                                  
    
    return ap_pass_brigade(f->next, bb);
}

/**
 * This input filter will basicall sniff on a connection and analyse
 * the packets when it detects SSL.
 */
static apr_status_t sslhaf_in_filter(ap_filter_t *f,
                                    apr_bucket_brigade *bb,
                                    ap_input_mode_t mode,
                                    apr_read_type_e block,
                                    apr_off_t readbytes)
{
    sslhaf_cfg_t *cfg = ap_get_module_config(f->c->conn_config, &sslhaf_module);
    apr_status_t status;
    apr_bucket *bucket;
    
    // Return straight away if there's no configuration
    if (cfg == NULL) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }
    
    // Sanity check first
    if (cfg->state == STATE_GOAWAY) {
        return ap_get_brigade(f->next, bb, mode, block, readbytes);
    }

    // Get brigade
    status = ap_get_brigade(f->next, bb, mode, block, readbytes);
    if (status != APR_SUCCESS) {
        // Do not log, since we're passing the status anyway
        cfg->state = STATE_GOAWAY;
        
        return status;
    }

    // Loop through the buckets
    for(bucket = APR_BRIGADE_FIRST(bb);
        bucket != APR_BRIGADE_SENTINEL(bb);
        bucket = APR_BUCKET_NEXT(bucket))
    {
        const char *buf = NULL;
        apr_size_t buflen = 0;
        
        if (!(APR_BUCKET_IS_METADATA(bucket))) {
            // Get bucket data
            status = apr_bucket_read(bucket, &buf, &buflen, APR_BLOCK_READ);
            if (status != APR_SUCCESS) {
                ap_log_error(APLOG_MARK, APLOG_ERR, status, f->c->base_server,
                    "mod_sslhaf [%s]: Error while reading input bucket",
                    f->c->remote_ip);
                return status;
            }
            
            // Look into the bucket                
            if (decode_bucket(f, cfg, (const unsigned char *)buf, buflen) <= 0) {
                cfg->state = STATE_GOAWAY;
            }
        }
    }
    
    return APR_SUCCESS;
}

/**
 * Attach our filter to every incoming connection.
 */
static int sslhaf_pre_conn(conn_rec *c, void *csd) {
    sslhaf_cfg_t *cfg = NULL;
    
    // TODO Can we determine if SSL is enabled on this connection
    //      and don't bother if it isn't? It is actually possible that
    //      someone speaks SSL on a non-SSL connection, but we won't
    //      be able to detect that. It wouldn't matter, though, because
    //      Apache will not process such a request.

    cfg = apr_pcalloc(c->pool, sizeof(*cfg));
    if (cfg == NULL) return OK;
    
    ap_set_module_config(c->conn_config, &sslhaf_module, cfg);

    ap_add_input_filter(sslhaf_in_filter_name, NULL, NULL, c);
    ap_add_output_filter(sslhaf_out_filter_name, NULL, NULL, c);

    #ifdef ENABLE_DEBUG    
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, c->base_server,
        "mod_sslhaf: Connection from %s", c->remote_ip);
    #endif

    return OK;
}

/**
 * Take the textual representation of the client's cipher suite
 * list and attach it to the request.
 */
static int sslhaf_post_request(request_rec *r) {
    sslhaf_cfg_t *cfg = ap_get_module_config(r->connection->conn_config, &sslhaf_module);
    
    if ((cfg != NULL)&&(cfg->tsuites != NULL)) {
        // Make the handshake information available to other modules
        apr_table_setn(r->subprocess_env, "SSLHAF_HANDSHAKE", cfg->thandshake);
        apr_table_setn(r->subprocess_env, "SSLHAF_PROTOCOL", cfg->tprotocol);
        apr_table_setn(r->subprocess_env, "SSLHAF_SUITES", cfg->tsuites);
        
        // BEAST mitigation detection
        if (cfg->in_data_fragments > 1) {
            apr_table_setn(r->subprocess_env, "SSLHAF_BEAST", "1");
        } else {
            apr_table_setn(r->subprocess_env, "SSLHAF_BEAST", "0");
        }
        
        // Expose compression methods
        apr_table_setn(r->subprocess_env, "SSLHAF_COMPRESSION", cfg->compression_methods);

        // Keep track of how many requests there were
        cfg->request_counter++;
        
        // Help to log only once per connection
        if (cfg->request_counter == 1) {
            apr_table_setn(r->subprocess_env, "SSLHAF_LOG", "1");
        }
        
        #if 0
        // Generate a sha1 of the remote address on the first request
        if (cfg->ipaddress_hash == NULL) {
            cfg->ipaddress_hash = generate_sha1(r->connection->pool,
                r->connection->remote_ip, strlen(r->connection->remote_ip));
        }
        
        apr_table_setn(r->subprocess_env, "SSLHAF_IP_HASH", cfg->ipaddress_hash);
        #endif
    }
    
    return DECLINED;
}

/**
 * Main entry point.
 */
static void register_hooks(apr_pool_t *p) {
    static const char * const afterme[] = { "mod_security2.c", NULL };
    
    ap_hook_pre_connection(sslhaf_pre_conn, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(sslhaf_post_request, NULL, afterme, APR_HOOK_REALLY_FIRST);

    ap_register_input_filter(sslhaf_in_filter_name, sslhaf_in_filter,
        NULL, AP_FTYPE_NETWORK - 1);
    ap_register_output_filter(sslhaf_out_filter_name, sslhaf_out_filter,
        NULL, AP_FTYPE_NETWORK - 1);
}

module AP_MODULE_DECLARE_DATA sslhaf_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,                       /* command apr_table_t */
    register_hooks              /* register hooks */
};
