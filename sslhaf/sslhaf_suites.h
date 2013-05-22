#ifndef SSLHAF_SUITES
#define SSLHAF_SUITES

static const struct sslhaf_suite_desc sslhaf_suite_unknown = {
    "UNKNOWN", 0xffffffff, 0 };

static const struct sslhaf_suite_desc ssl2_suite_descriptions[] = {
    { "SSL_CK_RC4_128_WITH_MD5", 0x010080, 128 },
    { "SSL_CK_RC4_128_EXPORT40_WITH_MD5", 0x020080, 40 },
    { "SSL_CK_RC2_128_CBC_WITH_MD5", 0x030080, 128 },
    { "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5", 0x040080, 40 },
    { "SSL_CK_IDEA_128_CBC_WITH_MD5", 0x050080, 128 },
    { "SSL_CK_DES_64_CBC_WITH_MD5", 0x060040, 56 },
    { "SSL_CK_DES_192_EDE3_CBC_WITH_MD5", 0x0700c0, 168 },
    { "SSL_CK_RC4_64_WITH_MD5", 0x080080, 64 },

};

static const struct sslhaf_suite_desc *get_ssl2_suite_description(uint32_t id) {
    switch (id) {
        case 0x010080:
            return &ssl2_suite_descriptions[0];
        case 0x020080:
            return &ssl2_suite_descriptions[1];
        case 0x030080:
            return &ssl2_suite_descriptions[2];
        case 0x040080:
            return &ssl2_suite_descriptions[3];
        case 0x050080:
            return &ssl2_suite_descriptions[4];
        case 0x060040:
            return &ssl2_suite_descriptions[5];
        case 0x0700c0:
            return &ssl2_suite_descriptions[6];
        case 0x080080:
            return &ssl2_suite_descriptions[7];

    };

    return &sslhaf_suite_unknown;
}

static const struct sslhaf_suite_desc tls_suite_descriptions[] = {
    { "", , 0 },
    { "TLS_NULL_WITH_NULL_NULL", 0x00, 0 },
    { "TLS_RSA_WITH_NULL_MD5", 0x01, 0 },
    { "TLS_RSA_WITH_NULL_SHA", 0x02, 0 },
    { "TLS_RSA_EXPORT_WITH_RC4_40_MD5", 0x03, 40 },
    { "TLS_RSA_WITH_RC4_128_MD5", 0x04, 128 },
    { "TLS_RSA_WITH_RC4_128_SHA", 0x05, 128 },
    { "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5", 0x06, 40 },
    { "TLS_RSA_WITH_IDEA_CBC_SHA", 0x07, 128 },
    { "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x08, 40 },
    { "TLS_RSA_WITH_DES_CBC_SHA", 0x09, 56 },
    { "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0a, 168 },
    { "TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x0b, 40 },
    { "TLS_DH_DSS_WITH_DES_CBC_SHA", 0x0c, 56 },
    { "TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA", 0x0d, 168 },
    { "TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x0e, 40 },
    { "TLS_DH_RSA_WITH_DES_CBC_SHA", 0x0f, 56 },
    { "TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA", 0x10, 168 },
    { "TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA", 0x11, 40 },
    { "TLS_DHE_DSS_WITH_DES_CBC_SHA", 0x12, 56 },
    { "TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA", 0x13, 168 },
    { "TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA", 0x14, 40 },
    { "TLS_DHE_RSA_WITH_DES_CBC_SHA", 0x15, 56 },
    { "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA", 0x16, 168 },
    { "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5", 0x17, 40 },
    { "TLS_DH_anon_WITH_RC4_128_MD5", 0x18, 128 },
    { "TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA", 0x19, 40 },
    { "TLS_DH_anon_WITH_DES_CBC_SHA", 0x1a, 56 },
    { "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA", 0x1b, 168 },
    { "SSL_FORTEZZA_KEA_WITH_NULL_SHA", 0x1c, 0 },
    { "SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA", 0x1d, 96 },
    { "TLS_KRB5_WITH_DES_CBC_SHA", 0x1e, 56 },
    { "TLS_KRB5_WITH_3DES_EDE_CBC_SHA", 0x1f, 168 },
    { "TLS_KRB5_WITH_RC4_128_SHA", 0x20, 128 },
    { "TLS_KRB5_WITH_IDEA_CBC_SHA", 0x21, 128 },
    { "TLS_KRB5_WITH_DES_CBC_MD5", 0x22, 56 },
    { "TLS_KRB5_WITH_3DES_EDE_CBC_MD5", 0x23, 168 },
    { "TLS_KRB5_WITH_RC4_128_MD5", 0x24, 128 },
    { "TLS_KRB5_WITH_IDEA_CBC_MD5", 0x25, 128 },
    { "TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA", 0x26, 40 },
    { "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA", 0x27, 40 },
    { "TLS_KRB5_EXPORT_WITH_RC4_40_SHA", 0x28, 40 },
    { "TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5", 0x29, 40 },
    { "TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5", 0x2a, 40 },
    { "TLS_KRB5_EXPORT_WITH_RC4_40_MD5", 0x2b, 40 },
    { "TLS_PSK_WITH_NULL_SHA", 0x2c, 0 },
    { "TLS_DHE_PSK_WITH_NULL_SHA", 0x2d, 0 },
    { "TLS_RSA_PSK_WITH_NULL_SHA", 0x2e, 0 },
    { "TLS_RSA_WITH_AES_128_CBC_SHA", 0x2f, 128 },
    { "TLS_DH_DSS_WITH_AES_128_CBC_SHA", 0x30, 128 },
    { "TLS_DH_RSA_WITH_AES_128_CBC_SHA", 0x31, 128 },
    { "TLS_DHE_DSS_WITH_AES_128_CBC_SHA", 0x32, 128 },
    { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA", 0x33, 128 },
    { "TLS_DH_anon_WITH_AES_128_CBC_SHA", 0x34, 128 },
    { "TLS_RSA_WITH_AES_256_CBC_SHA", 0x35, 256 },
    { "TLS_DH_DSS_WITH_AES_256_CBC_SHA", 0x36, 256 },
    { "TLS_DH_RSA_WITH_AES_256_CBC_SHA", 0x37, 256 },
    { "TLS_DHE_DSS_WITH_AES_256_CBC_SHA", 0x38, 256 },
    { "TLS_DHE_RSA_WITH_AES_256_CBC_SHA", 0x39, 256 },
    { "TLS_DH_anon_WITH_AES_256_CBC_SHA", 0x3a, 256 },
    { "TLS_RSA_WITH_NULL_SHA256", 0x3b, 0 },
    { "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x3c, 128 },
    { "TLS_RSA_WITH_AES_256_CBC_SHA256", 0x3d, 256 },
    { "TLS_DH_DSS_WITH_AES_128_CBC_SHA256", 0x3e, 128 },
    { "TLS_DH_RSA_WITH_AES_128_CBC_SHA256", 0x3f, 128 },
    { "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256", 0x40, 128 },
    { "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x41, 128 },
    { "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA", 0x42, 128 },
    { "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x43, 128 },
    { "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA", 0x44, 128 },
    { "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA", 0x45, 128 },
    { "TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA", 0x46, 128 },
    { "TLS_RSA_EXPORT1024_WITH_RC4_56_MD5", 0x60, 56 },
    { "TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5", 0x61, 56 },
    { "TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", 0x62, 56 },
    { "TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA", 0x63, 56 },
    { "TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", 0x64, 56 },
    { "TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA", 0x65, 56 },
    { "TLS_DHE_DSS_WITH_RC4_128_SHA", 0x66, 128 },
    { "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256", 0x67, 128 },
    { "TLS_DH_DSS_WITH_AES_256_CBC_SHA256", 0x68, 256 },
    { "TLS_DH_RSA_WITH_AES_256_CBC_SHA256", 0x69, 256 },
    { "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256", 0x6a, 256 },
    { "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256", 0x6b, 256 },
    { "TLS_DH_anon_WITH_AES_128_CBC_SHA256", 0x6c, 128 },
    { "TLS_DH_anon_WITH_AES_256_CBC_SHA256", 0x6d, 256 },
    { "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x84, 256 },
    { "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA", 0x85, 256 },
    { "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x86, 256 },
    { "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA", 0x87, 256 },
    { "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA", 0x88, 256 },
    { "TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA", 0x89, 256 },
    { "TLS_PSK_WITH_RC4_128_SHA", 0x8a, 128 },
    { "TLS_PSK_WITH_3DES_EDE_CBC_SHA", 0x8b, 168 },
    { "TLS_PSK_WITH_AES_128_CBC_SHA", 0x8c, 128 },
    { "TLS_PSK_WITH_AES_256_CBC_SHA", 0x8d, 256 },
    { "TLS_DHE_PSK_WITH_RC4_128_SHA", 0x8e, 128 },
    { "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA", 0x8f, 168 },
    { "TLS_DHE_PSK_WITH_AES_128_CBC_SHA", 0x90, 128 },
    { "TLS_DHE_PSK_WITH_AES_256_CBC_SHA", 0x91, 256 },
    { "TLS_RSA_PSK_WITH_RC4_128_SHA", 0x92, 128 },
    { "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA", 0x93, 168 },
    { "TLS_RSA_PSK_WITH_AES_128_CBC_SHA", 0x94, 128 },
    { "TLS_RSA_PSK_WITH_AES_256_CBC_SHA", 0x95, 256 },
    { "TLS_RSA_WITH_SEED_CBC_SHA", 0x96, 128 },
    { "TLS_DH_DSS_WITH_SEED_CBC_SHA", 0x97, 128 },
    { "TLS_DH_RSA_WITH_SEED_CBC_SHA", 0x98, 128 },
    { "TLS_DHE_DSS_WITH_SEED_CBC_SHA", 0x99, 128 },
    { "TLS_DHE_RSA_WITH_SEED_CBC_SHA", 0x9a, 128 },
    { "TLS_DH_anon_WITH_SEED_CBC_SHA", 0x9b, 128 },
    { "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x9c, 128 },
    { "TLS_RSA_WITH_AES_256_GCM_SHA384", 0x9d, 256 },
    { "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x9e, 128 },
    { "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 0x9f, 256 },
    { "TLS_DH_RSA_WITH_AES_128_GCM_SHA256", 0xa0, 128 },
    { "TLS_DH_RSA_WITH_AES_256_GCM_SHA384", 0xa1, 256 },
    { "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256", 0xa2, 128 },
    { "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384", 0xa3, 256 },
    { "TLS_DH_DSS_WITH_AES_128_GCM_SHA256", 0xa4, 128 },
    { "TLS_DH_DSS_WITH_AES_256_GCM_SHA384", 0xa5, 256 },
    { "TLS_DH_anon_WITH_AES_128_GCM_SHA256", 0xa6, 128 },
    { "TLS_DH_anon_WITH_AES_256_GCM_SHA384", 0xa7, 256 },
    { "TLS_ECDH_ECDSA_WITH_NULL_SHA", 0xc001, 0 },
    { "TLS_ECDH_ECDSA_WITH_RC4_128_SHA", 0xc002, 128 },
    { "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xc003, 168 },
    { "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA", 0xc004, 128 },
    { "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA", 0xc005, 256 },
    { "TLS_ECDHE_ECDSA_WITH_NULL_SHA", 0xc006, 0 },
    { "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA", 0xc007, 128 },
    { "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA", 0xc008, 168 },
    { "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xc009, 128 },
    { "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA", 0xc00a, 256 },
    { "TLS_ECDH_RSA_WITH_NULL_SHA", 0xc00b, 0 },
    { "TLS_ECDH_RSA_WITH_RC4_128_SHA", 0xc00c, 128 },
    { "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA", 0xc00d, 168 },
    { "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA", 0xc00e, 128 },
    { "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA", 0xc00f, 256 },
    { "TLS_ECDHE_RSA_WITH_NULL_SHA", 0xc010, 0 },
    { "TLS_ECDHE_RSA_WITH_RC4_128_SHA", 0xc011, 128 },
    { "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", 0xc012, 168 },
    { "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xc013, 128 },
    { "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 0xc014, 256 },
    { "TLS_ECDH_anon_WITH_NULL_SHA", 0xc015, 0 },
    { "TLS_ECDH_anon_WITH_RC4_128_SHA", 0xc016, 128 },
    { "TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA", 0xc017, 168 },
    { "TLS_ECDH_anon_WITH_AES_128_CBC_SHA", 0xc018, 128 },
    { "TLS_ECDH_anon_WITH_AES_256_CBC_SHA", 0xc019, 256 },
    { "TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA", 0xc01a, 168 },
    { "TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA", 0xc01b, 168 },
    { "TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA", 0xc01c, 168 },
    { "TLS_SRP_SHA_WITH_AES_128_CBC_SHA", 0xc01d, 128 },
    { "TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA", 0xc01e, 128 },
    { "TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA", 0xc01f, 128 },
    { "TLS_SRP_SHA_WITH_AES_256_CBC_SHA", 0xc020, 256 },
    { "TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA", 0xc021, 256 },
    { "TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA", 0xc022, 256 },
    { "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xc023, 128 },
    { "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384", 0xc024, 256 },
    { "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256", 0xc025, 128 },
    { "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384", 0xc026, 256 },
    { "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xc027, 128 },
    { "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 0xc028, 256 },
    { "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256", 0xc029, 128 },
    { "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384", 0xc02a, 256 },
    { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02b, 128 },
    { "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 0xc02c, 256 },
    { "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256", 0xc02d, 128 },
    { "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384", 0xc02e, 256 },
    { "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 0xc02f, 128 },
    { "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 0xc030, 256 },
    { "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256", 0xc031, 128 },
    { "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384", 0xc032, 256 },
    { "SSL_RSA_FIPS_WITH_DES_CBC_SHA", 0xfefe, 56 },
    { "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", 0xfeff, 168 },
    { "TLS_EMPTY_RENEGOTIATION_INFO_SCSV", 0xff, 0 },
    { "SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA", 0xffe0, 168 },
    { "SSL_RSA_FIPS_WITH_DES_CBC_SHA", 0xffe1, 56 },

};

static const struct sslhaf_suite_desc *get_tls_suite_description(uint32_t id) {
    switch (id) {
        case :
            return &tls_suite_descriptions[0];
        case 0x00:
            return &tls_suite_descriptions[1];
        case 0x01:
            return &tls_suite_descriptions[2];
        case 0x02:
            return &tls_suite_descriptions[3];
        case 0x03:
            return &tls_suite_descriptions[4];
        case 0x04:
            return &tls_suite_descriptions[5];
        case 0x05:
            return &tls_suite_descriptions[6];
        case 0x06:
            return &tls_suite_descriptions[7];
        case 0x07:
            return &tls_suite_descriptions[8];
        case 0x08:
            return &tls_suite_descriptions[9];
        case 0x09:
            return &tls_suite_descriptions[10];
        case 0x0a:
            return &tls_suite_descriptions[11];
        case 0x0b:
            return &tls_suite_descriptions[12];
        case 0x0c:
            return &tls_suite_descriptions[13];
        case 0x0d:
            return &tls_suite_descriptions[14];
        case 0x0e:
            return &tls_suite_descriptions[15];
        case 0x0f:
            return &tls_suite_descriptions[16];
        case 0x10:
            return &tls_suite_descriptions[17];
        case 0x11:
            return &tls_suite_descriptions[18];
        case 0x12:
            return &tls_suite_descriptions[19];
        case 0x13:
            return &tls_suite_descriptions[20];
        case 0x14:
            return &tls_suite_descriptions[21];
        case 0x15:
            return &tls_suite_descriptions[22];
        case 0x16:
            return &tls_suite_descriptions[23];
        case 0x17:
            return &tls_suite_descriptions[24];
        case 0x18:
            return &tls_suite_descriptions[25];
        case 0x19:
            return &tls_suite_descriptions[26];
        case 0x1a:
            return &tls_suite_descriptions[27];
        case 0x1b:
            return &tls_suite_descriptions[28];
        case 0x1c:
            return &tls_suite_descriptions[29];
        case 0x1d:
            return &tls_suite_descriptions[30];
        case 0x1e:
            return &tls_suite_descriptions[31];
        case 0x1f:
            return &tls_suite_descriptions[32];
        case 0x20:
            return &tls_suite_descriptions[33];
        case 0x21:
            return &tls_suite_descriptions[34];
        case 0x22:
            return &tls_suite_descriptions[35];
        case 0x23:
            return &tls_suite_descriptions[36];
        case 0x24:
            return &tls_suite_descriptions[37];
        case 0x25:
            return &tls_suite_descriptions[38];
        case 0x26:
            return &tls_suite_descriptions[39];
        case 0x27:
            return &tls_suite_descriptions[40];
        case 0x28:
            return &tls_suite_descriptions[41];
        case 0x29:
            return &tls_suite_descriptions[42];
        case 0x2a:
            return &tls_suite_descriptions[43];
        case 0x2b:
            return &tls_suite_descriptions[44];
        case 0x2c:
            return &tls_suite_descriptions[45];
        case 0x2d:
            return &tls_suite_descriptions[46];
        case 0x2e:
            return &tls_suite_descriptions[47];
        case 0x2f:
            return &tls_suite_descriptions[48];
        case 0x30:
            return &tls_suite_descriptions[49];
        case 0x31:
            return &tls_suite_descriptions[50];
        case 0x32:
            return &tls_suite_descriptions[51];
        case 0x33:
            return &tls_suite_descriptions[52];
        case 0x34:
            return &tls_suite_descriptions[53];
        case 0x35:
            return &tls_suite_descriptions[54];
        case 0x36:
            return &tls_suite_descriptions[55];
        case 0x37:
            return &tls_suite_descriptions[56];
        case 0x38:
            return &tls_suite_descriptions[57];
        case 0x39:
            return &tls_suite_descriptions[58];
        case 0x3a:
            return &tls_suite_descriptions[59];
        case 0x3b:
            return &tls_suite_descriptions[60];
        case 0x3c:
            return &tls_suite_descriptions[61];
        case 0x3d:
            return &tls_suite_descriptions[62];
        case 0x3e:
            return &tls_suite_descriptions[63];
        case 0x3f:
            return &tls_suite_descriptions[64];
        case 0x40:
            return &tls_suite_descriptions[65];
        case 0x41:
            return &tls_suite_descriptions[66];
        case 0x42:
            return &tls_suite_descriptions[67];
        case 0x43:
            return &tls_suite_descriptions[68];
        case 0x44:
            return &tls_suite_descriptions[69];
        case 0x45:
            return &tls_suite_descriptions[70];
        case 0x46:
            return &tls_suite_descriptions[71];
        case 0x60:
            return &tls_suite_descriptions[72];
        case 0x61:
            return &tls_suite_descriptions[73];
        case 0x62:
            return &tls_suite_descriptions[74];
        case 0x63:
            return &tls_suite_descriptions[75];
        case 0x64:
            return &tls_suite_descriptions[76];
        case 0x65:
            return &tls_suite_descriptions[77];
        case 0x66:
            return &tls_suite_descriptions[78];
        case 0x67:
            return &tls_suite_descriptions[79];
        case 0x68:
            return &tls_suite_descriptions[80];
        case 0x69:
            return &tls_suite_descriptions[81];
        case 0x6a:
            return &tls_suite_descriptions[82];
        case 0x6b:
            return &tls_suite_descriptions[83];
        case 0x6c:
            return &tls_suite_descriptions[84];
        case 0x6d:
            return &tls_suite_descriptions[85];
        case 0x84:
            return &tls_suite_descriptions[86];
        case 0x85:
            return &tls_suite_descriptions[87];
        case 0x86:
            return &tls_suite_descriptions[88];
        case 0x87:
            return &tls_suite_descriptions[89];
        case 0x88:
            return &tls_suite_descriptions[90];
        case 0x89:
            return &tls_suite_descriptions[91];
        case 0x8a:
            return &tls_suite_descriptions[92];
        case 0x8b:
            return &tls_suite_descriptions[93];
        case 0x8c:
            return &tls_suite_descriptions[94];
        case 0x8d:
            return &tls_suite_descriptions[95];
        case 0x8e:
            return &tls_suite_descriptions[96];
        case 0x8f:
            return &tls_suite_descriptions[97];
        case 0x90:
            return &tls_suite_descriptions[98];
        case 0x91:
            return &tls_suite_descriptions[99];
        case 0x92:
            return &tls_suite_descriptions[100];
        case 0x93:
            return &tls_suite_descriptions[101];
        case 0x94:
            return &tls_suite_descriptions[102];
        case 0x95:
            return &tls_suite_descriptions[103];
        case 0x96:
            return &tls_suite_descriptions[104];
        case 0x97:
            return &tls_suite_descriptions[105];
        case 0x98:
            return &tls_suite_descriptions[106];
        case 0x99:
            return &tls_suite_descriptions[107];
        case 0x9a:
            return &tls_suite_descriptions[108];
        case 0x9b:
            return &tls_suite_descriptions[109];
        case 0x9c:
            return &tls_suite_descriptions[110];
        case 0x9d:
            return &tls_suite_descriptions[111];
        case 0x9e:
            return &tls_suite_descriptions[112];
        case 0x9f:
            return &tls_suite_descriptions[113];
        case 0xa0:
            return &tls_suite_descriptions[114];
        case 0xa1:
            return &tls_suite_descriptions[115];
        case 0xa2:
            return &tls_suite_descriptions[116];
        case 0xa3:
            return &tls_suite_descriptions[117];
        case 0xa4:
            return &tls_suite_descriptions[118];
        case 0xa5:
            return &tls_suite_descriptions[119];
        case 0xa6:
            return &tls_suite_descriptions[120];
        case 0xa7:
            return &tls_suite_descriptions[121];
        case 0xc001:
            return &tls_suite_descriptions[122];
        case 0xc002:
            return &tls_suite_descriptions[123];
        case 0xc003:
            return &tls_suite_descriptions[124];
        case 0xc004:
            return &tls_suite_descriptions[125];
        case 0xc005:
            return &tls_suite_descriptions[126];
        case 0xc006:
            return &tls_suite_descriptions[127];
        case 0xc007:
            return &tls_suite_descriptions[128];
        case 0xc008:
            return &tls_suite_descriptions[129];
        case 0xc009:
            return &tls_suite_descriptions[130];
        case 0xc00a:
            return &tls_suite_descriptions[131];
        case 0xc00b:
            return &tls_suite_descriptions[132];
        case 0xc00c:
            return &tls_suite_descriptions[133];
        case 0xc00d:
            return &tls_suite_descriptions[134];
        case 0xc00e:
            return &tls_suite_descriptions[135];
        case 0xc00f:
            return &tls_suite_descriptions[136];
        case 0xc010:
            return &tls_suite_descriptions[137];
        case 0xc011:
            return &tls_suite_descriptions[138];
        case 0xc012:
            return &tls_suite_descriptions[139];
        case 0xc013:
            return &tls_suite_descriptions[140];
        case 0xc014:
            return &tls_suite_descriptions[141];
        case 0xc015:
            return &tls_suite_descriptions[142];
        case 0xc016:
            return &tls_suite_descriptions[143];
        case 0xc017:
            return &tls_suite_descriptions[144];
        case 0xc018:
            return &tls_suite_descriptions[145];
        case 0xc019:
            return &tls_suite_descriptions[146];
        case 0xc01a:
            return &tls_suite_descriptions[147];
        case 0xc01b:
            return &tls_suite_descriptions[148];
        case 0xc01c:
            return &tls_suite_descriptions[149];
        case 0xc01d:
            return &tls_suite_descriptions[150];
        case 0xc01e:
            return &tls_suite_descriptions[151];
        case 0xc01f:
            return &tls_suite_descriptions[152];
        case 0xc020:
            return &tls_suite_descriptions[153];
        case 0xc021:
            return &tls_suite_descriptions[154];
        case 0xc022:
            return &tls_suite_descriptions[155];
        case 0xc023:
            return &tls_suite_descriptions[156];
        case 0xc024:
            return &tls_suite_descriptions[157];
        case 0xc025:
            return &tls_suite_descriptions[158];
        case 0xc026:
            return &tls_suite_descriptions[159];
        case 0xc027:
            return &tls_suite_descriptions[160];
        case 0xc028:
            return &tls_suite_descriptions[161];
        case 0xc029:
            return &tls_suite_descriptions[162];
        case 0xc02a:
            return &tls_suite_descriptions[163];
        case 0xc02b:
            return &tls_suite_descriptions[164];
        case 0xc02c:
            return &tls_suite_descriptions[165];
        case 0xc02d:
            return &tls_suite_descriptions[166];
        case 0xc02e:
            return &tls_suite_descriptions[167];
        case 0xc02f:
            return &tls_suite_descriptions[168];
        case 0xc030:
            return &tls_suite_descriptions[169];
        case 0xc031:
            return &tls_suite_descriptions[170];
        case 0xc032:
            return &tls_suite_descriptions[171];
        case 0xfefe:
            return &tls_suite_descriptions[172];
        case 0xfeff:
            return &tls_suite_descriptions[173];
        case 0xff:
            return &tls_suite_descriptions[174];
        case 0xffe0:
            return &tls_suite_descriptions[175];
        case 0xffe1:
            return &tls_suite_descriptions[176];

    };

    return &sslhaf_suite_unknown;
}

const struct sslhaf_suite_desc *get_suite_description(uint32_t id) {
    const struct sslhaf_suite_desc *suite;

    if (id & 0xff0000)
        return get_ssl2_suite_description(id);

    return get_tls_suite_description(id);
}

#endif /* SSLHAF_SUITES */
