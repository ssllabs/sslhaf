/*

mod_sslhaf: Apache module for passive SSL client fingerprinting

 | THIS PRODUCT IS NOT READY FOR PRODUCTION USE. DEPLOY AT YOUR OWN RISK.

Copyright (c) 2009-2012, Qualys, Inc.
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
 * To compile and install the module, configure and build libsslhaf,
 * then do this:
 *     # apxs -cia -I sslhaf -Lsslhaf/.libs/ -lsslhaf mod_sslhaf.c
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
 *     \"%{SSLHAF_PROTOCOL}e\" \"%{SSLHAF_SUITES}e\" \"%{SSLHAF_COMPRESSION}e\" \
 *     \"%{SSLHAF_BEAST}e\" \"%{SSLHAF_EXTENSIONS_LEN}e\" \"%{SSLHAF_EXTENSIONS}e\" \
 *     \"%{User-Agent}i\""
 *
 * | NOTE A CustomLog directive placed in the main server context,
 * |      will not record any traffic arriving to virtual hosts.
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

#include "sslhaf.h"

module AP_MODULE_DECLARE_DATA mod_sslhaf_module;

static const char mod_sslhaf_in_filter_name[] = "SSLHAF_IN";
static const char mod_sslhaf_out_filter_name[] = "SSLHAF_OUT";

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

/**
 * Monitor outbound data and count buckets. This will help us determine
 * if input data is fragmented (we see more than one inbound bucket before
 * we see one outbound bucket).
 */
static apr_status_t mod_sslhaf_out_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    sslhaf_cfg_t *cfg = ap_get_module_config(f->c->conn_config,
        &mod_sslhaf_module);
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
static apr_status_t mod_sslhaf_in_filter(ap_filter_t *f,
                                         apr_bucket_brigade *bb,
                                         ap_input_mode_t mode,
                                         apr_read_type_e block,
                                         apr_off_t readbytes)
{
    sslhaf_cfg_t *cfg = ap_get_module_config(f->c->conn_config,
        &mod_sslhaf_module);
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
            if (sslhaf_decode_bucket(f,
                    cfg, (const unsigned char *)buf, buflen) <= 0) {
                cfg->state = STATE_GOAWAY;
            }
        }
    }

    return APR_SUCCESS;
}

/**
 * Attach our filter to every incoming connection.
 */
static int mod_sslhaf_pre_conn(conn_rec *c, void *csd) {
    sslhaf_cfg_t *cfg = NULL;

    // TODO Can we determine if SSL is enabled on this connection
    //      and don't bother if it isn't? It is actually possible that
    //      someone speaks SSL on a non-SSL connection, but we won't
    //      be able to detect that. It wouldn't matter, though, because
    //      Apache will not process such a request.

    cfg = apr_pcalloc(c->pool, sizeof(*cfg));
    if (cfg == NULL) return OK;

    ap_set_module_config(c->conn_config, &mod_sslhaf_module, cfg);

    ap_add_input_filter(mod_sslhaf_in_filter_name, NULL, NULL, c);
    ap_add_output_filter(mod_sslhaf_out_filter_name, NULL, NULL, c);

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
static int mod_sslhaf_post_request(request_rec *r) {
    sslhaf_cfg_t *cfg = ap_get_module_config(r->connection->conn_config,
        &mod_sslhaf_module);

    if ((cfg != NULL)&&(cfg->tsuites != NULL)) {
        // Release the packet buffer if we're still holding it
        if (cfg->buf != NULL) {
            free(cfg->buf);
            cfg->buf = NULL;
        }

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

        // Expose extension data
        char *extensions_len = apr_psprintf(r->pool, "%d", cfg->extensions_len);
        apr_table_setn(r->subprocess_env, "SSLHAF_EXTENSIONS_LEN", extensions_len);
        apr_table_setn(r->subprocess_env, "SSLHAF_EXTENSIONS", cfg->extensions);

        // Keep track of how many requests there were
        cfg->request_counter++;

        // Help to log only once per connection
        if (cfg->request_counter == 1) {
            apr_table_setn(r->subprocess_env, "SSLHAF_LOG", "1");
        }

        #if 0
        // Generate a sha1 of the remote address on the first request
        if (cfg->ipaddress_hash == NULL) {
            cfg->ipaddress_hash = mod_sslhaf_generate_sha1(r->connection->pool,
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
static void mod_sslhaf_register_hooks(apr_pool_t *p) {
    static const char * const afterme[] = { "mod_security2.c", NULL };

    ap_hook_pre_connection(mod_sslhaf_pre_conn, NULL, NULL, APR_HOOK_MIDDLE);
    ap_hook_post_read_request(mod_sslhaf_post_request, NULL, afterme, APR_HOOK_REALLY_FIRST);

    ap_register_input_filter(mod_sslhaf_in_filter_name, mod_sslhaf_in_filter,
        NULL, AP_FTYPE_NETWORK - 1);
    ap_register_output_filter(mod_sslhaf_out_filter_name, mod_sslhaf_out_filter,
        NULL, AP_FTYPE_NETWORK - 1);
}

module AP_MODULE_DECLARE_DATA mod_sslhaf_module = {
    STANDARD20_MODULE_STUFF,
    NULL,                       /* create per-dir config */
    NULL,                       /* merge per-dir config */
    NULL,                       /* server config */
    NULL,                       /* merge server config */
    NULL,                       /* command apr_table_t */
    mod_sslhaf_register_hooks   /* register hooks */
};
