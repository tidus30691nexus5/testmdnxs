#ifndef _NGX_JA3_SSL_H_
#define _NGX_JA3_SSL_H_

#include <ngx_config.h>
#include <ngx_core.h>
//#include <openssl/ssl.h>
#include <ngx_event_openssl.h>
#include "ngx_ja3_module.h"
#define NGX_JA_MAX_ITEMS 64

#include <ngx_http.h>


/*
 * ===============================
 *  OpenSSL version guard
 * ===============================
 */
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "ngx_http_ja_module requires OpenSSL >= 1.1.1"
#endif

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#error "OpenSSL 3.x is NOT supported for JA3/JA4 (no raw ClientHello)"
#endif


/*
 * ===============================
 *  Forward declarations
 * ===============================
 */
 int ngx_ja_client_hello_cb(SSL *ssl, int *al, void *arg);



typedef struct {
    uint16_t tls_version;

    uint16_t ciphers[NGX_JA_MAX_ITEMS];
    uint8_t  cipher_cnt;
//uint16_t ciphers;

    uint16_t exts[NGX_JA_MAX_ITEMS];
    uint8_t  ext_cnt;
//uint16_t exts;


    uint16_t curves[NGX_JA_MAX_ITEMS];
    uint8_t  curve_cnt;
//uint16_t curves;

    uint8_t  ec_pf[NGX_JA_MAX_ITEMS];
    uint8_t  ec_pf_cnt;
   // uint8_t  ec_pf;


     /* ---------- JA3 ---------- */
    u_char ja3[256];
    u_char ja3_len;

    u_char ja3s[256];
    u_char ja3s_len;

    u_char ja3_md5[16];
    uint64_t ja3_xx64;


    /* JA4 */
    u_char ja4[32];
    u_char ja4_len;

    //JA4OS
    u_char   ja4os[16];
    u_char   ja4os_len;

     uint64_t ja4_xx64;


} ngx_ja_fp_t;

ngx_int_t ngx_ja_parse_client_helloVER3(
    const u_char *data, size_t len, ngx_ja_fp_t *fp);

ngx_int_t ngx_ja4_build(ngx_ja_fp_t *fp);


ngx_int_t ngx_ja_ssl_init(ngx_conf_t *cf, ngx_http_ja_conf_t *conf);

ngx_ja_fp_t *ngx_ja_ssl_get_fp(SSL *ssl);
#endif
