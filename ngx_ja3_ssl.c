#include "ngx_ja3_ssl.h"
//#include <openssl/bytestring.h>


#include <ngx_ja3_module.h>
#include <openssl/opensslv.h>



#include "ngx_ja3_builder.h"
#include "ngx_ja4_builder.h"
#include "ngx_ja4_os.h"


#include <openssl/md5.h>
#include "xxhash.h"

//cache 
#include "ngx_ja3_cache.h"


//fix ssl 
#include <ngx_event_openssl.h>
#include <ngx_http_ssl_module.h>



#define NGX_JA_IS_GREASE(x) (((x) & 0x0f0f) == 0x0a0a)
#define READ_U8(p)   (*(p)++)
#define READ_U16(p)  ((uint16_t)((p)[0] << 8 | (p)[1])); (p) += 2
#define READ_U24(p)  ((uint32_t)((p)[0] << 16 | (p)[1] << 8 | (p)[2])); (p) += 3

#define CHECK_LEN(p, end, need) \
    if ((size_t)((end) - (p)) < (need)) return -1;


/*
 * RFC 5246 / 8446 ClientHello
 */
/*
 * data = raw ClientHello handshake
 * len  = total length
 *
 * return 0 = OK
 * return -1 = parse error
 */
ngx_int_t
ngx_ja_parse_client_helloVER3(const u_char *data, size_t len, ngx_ja_fp_t *fp)
{
    const u_char *p   = data;
    const u_char *end = data + len;

    /* ---- Handshake Header ---- */
    CHECK_LEN(p, end, 4);

    uint8_t hs_type = READ_U8(p);
    if (hs_type != 0x01) {
        return NGX_ERROR; /* not ClientHello */
    }

    uint32_t hs_len = READ_U24(p);
    if ((size_t)(end - p) < hs_len) {
        return NGX_ERROR;
    }

    /* ---- ClientHello ---- */

    /* legacy_version */
    CHECK_LEN(p, end, 2);
    fp->tls_version = READ_U16(p);

    /* random */
    CHECK_LEN(p, end, 32);
    p += 32;

    /* session id */
    CHECK_LEN(p, end, 1);
    uint8_t sid_len = READ_U8(p);
    CHECK_LEN(p, end, sid_len);
    p += sid_len;

    /* cipher suites */
    CHECK_LEN(p, end, 2);
    uint16_t cipher_len = READ_U16(p);
    CHECK_LEN(p, end, cipher_len);

    fp->cipher_cnt = 0;
    for (uint16_t i = 0; i + 1 < cipher_len; i += 2) {
        if (fp->cipher_cnt < 128) {
            uint16_t cs = (p[i] << 8) | p[i + 1];
            fp->ciphers[fp->cipher_cnt++] = cs;
        }
    }
    p += cipher_len;

    /* compression methods */
    CHECK_LEN(p, end, 1);
    uint8_t comp_len = READ_U8(p);
    CHECK_LEN(p, end, comp_len);
    p += comp_len;

    /* ---- Extensions ---- */
    if (p == end) {
        return NGX_OK; /* no extensions */
    }

    CHECK_LEN(p, end, 2);
    uint16_t ext_total_len = READ_U16(p);
    CHECK_LEN(p, end, ext_total_len);

    const u_char *ext_end = p + ext_total_len;

    while (p + 4 <= ext_end) {
        uint16_t ext_type = READ_U16(p);
        uint16_t ext_len  = READ_U16(p);

        if (fp->ext_cnt < 128) {
            fp->exts[fp->ext_cnt++] = ext_type;
        }

        /* ---- specific extensions ---- */
        if (ext_type == 10) { /* supported_groups */
            const u_char *q = p;
            CHECK_LEN(q, ext_end, 2);
            uint16_t glen = READ_U16(q);

            while (glen >= 2 && q + 2 <= ext_end) {
                if (fp->curve_cnt < 64) {
                    fp->curves[fp->curve_cnt++] =
                        (q[0] << 8) | q[1];
                }
                q += 2;
                glen -= 2;
            }
        }

        if (ext_type == 11) { /* ec_point_formats */
            const u_char *q = p;
            CHECK_LEN(q, ext_end, 1);
            uint8_t plen = READ_U8(q);

            while (plen-- && q < ext_end) {
                if (fp->ec_pf_cnt < 16) {
                    fp->ec_pf[fp->ec_pf_cnt++] = *q;
                }
                q++;
            }
        }

        p += ext_len;
    }

    return NGX_OK;
}

//, ngx_pool_t *pool
ngx_int_t
ngx_ja_parse_client_hello(SSL *ssl, ngx_ja_fp_t *fp)
{
    const unsigned char *p;
    size_t len;
    int *exts;
    size_t extlen;

    

    /* =======================
     * 1. TLS VERSION
     * ======================= */
    fp->tls_version = SSL_client_hello_get0_legacy_version(ssl);

    /* =======================
     * 2. CIPHER SUITES
     * ======================= */
    fp->cipher_cnt = 0;

    len = SSL_client_hello_get0_ciphers(ssl, &p);
    if (len >= 2) {
        for (size_t i = 0;
             i + 1 < len && fp->cipher_cnt < NGX_JA_MAX_ITEMS;
             i += 2)
        {
            uint16_t cs = (p[i] << 8) | p[i + 1];
            if (!NGX_JA_IS_GREASE(cs)) {
                fp->ciphers[fp->cipher_cnt++] = cs;
            }
        }
    }

    /* =======================
     * 3. EXTENSIONS
     * ======================= */
    fp->ext_cnt = 0;

    if (SSL_client_hello_get1_extensions_present(ssl, &exts, &extlen) == 1) {
        for (size_t i = 0;
             i < extlen && fp->ext_cnt < NGX_JA_MAX_ITEMS;
             i++)
        {
            uint16_t e = (uint16_t) exts[i];
            if (!NGX_JA_IS_GREASE(e)) {
                fp->exts[fp->ext_cnt++] = e;
            }
        }
        OPENSSL_free(exts);
    }

    /* =======================
     * 4. SUPPORTED GROUPS
     * ======================= */
    fp->curve_cnt = 0;

    if (SSL_client_hello_get0_ext(
            ssl, TLSEXT_TYPE_supported_groups, &p, &len) == 1 && len >= 2)
    {
        /* byte 0–1 = length */
        for (size_t i = 2;
             i + 1 < len && fp->curve_cnt < NGX_JA_MAX_ITEMS;
             i += 2)
        {
            uint16_t g = (p[i] << 8) | p[i + 1];
            if (!NGX_JA_IS_GREASE(g)) {
                fp->curves[fp->curve_cnt++] = g;
            }
        }
    }

    /* =======================
     * 5. EC POINT FORMATS
     * ======================= */
    fp->ec_pf_cnt = 0;

    if (SSL_client_hello_get0_ext(
            ssl, TLSEXT_TYPE_ec_point_formats, &p, &len) == 1 && len >= 1)
    {
        /* byte 0 = length */
        for (size_t i = 1;
             i < len && fp->ec_pf_cnt < NGX_JA_MAX_ITEMS;
             i++)
        {
            fp->ec_pf[fp->ec_pf_cnt++] = p[i];
        }
    }

    return NGX_OK;
}



//hash 


static void
ngx_ja_hash(ngx_ja_fp_t *fp)
{
    /* ---- MD5 ---- */
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, fp->ja3, fp->ja3_len);
    MD5_Final(fp->ja3_md5, &ctx);

    /* ---- xxHash64 ---- */
    fp->ja3_xx64 = XXH64(fp->ja3, fp->ja3_len, 0);

    /* ---- JA4 hash (xxh64) ---- */
    fp->ja4_xx64 = XXH64(fp->ja4, fp->ja4_len, 0);
}


// callback


// func browser
/*
static int
ngx_ja_client_hello_cb(SSL *ssl, int *al, void *arg)
{
    const u_char *data;
    size_t len;

    if (!SSL_client_hello_get0_raw(ssl, &data, &len))
        return SSL_CLIENT_HELLO_SUCCESS;

    ngx_ja_fp_t *fp = OPENSSL_zalloc(sizeof(*fp));
    if (!fp) return SSL_CLIENT_HELLO_SUCCESS;

    ngx_ja_parse_client_hello(data, len, fp);

    // build fingerprints
    ngx_ja3_build(fp);
    ngx_ja4_build(fp);

    // hash 
    ngx_ja_hash(fp);

    SSL_set_ex_data(ssl, ngx_ja_ex_index, fp);
    return SSL_CLIENT_HELLO_SUCCESS;
}

*/


/* ============================================================
 * INIT
 * ============================================================ */


 /*
ngx_int_t
ngx_ja_ssl_init(ngx_conf_t *cf)
{
    ngx_http_ssl_srv_conf_t  *sscf;

    // allocate OpenSSL ex_data index 
    ngx_ja_ssl_ex_index = SSL_get_ex_new_index(
        0, NULL, NULL, NULL, NULL
    );

    if (ngx_ja_ssl_ex_index == -1) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "ja3: SSL_get_ex_new_index failed");
        return NGX_ERROR;
    }

    // get http ssl srv conf
    sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    if (sscf == NULL || sscf->ssl.ctx == NULL) {
        ngx_log_error(NGX_LOG_EMERG, cf->log, 0,
                      "ja3: ngx_http_ssl_module not found");
        return NGX_ERROR;
    }

    // register ClientHello callback 
    SSL_CTX_set_client_hello_cb(sscf->ssl.ctx,
                                ngx_ja_client_hello_cb,
                                NULL);

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0,
                  "ja3: ClientHello hook installed");

    return NGX_OK;
}

*/

//version on ask ios 
static ngx_int_t ngx_ja_ex_index = -1;
static ngx_shm_zone_t *ngx_ja_shm_zone = NULL;
static ngx_ja_cache_ctx_t *ngx_ja_cache_ctx = NULL;

/* ---------- SHM INIT ---------- */

static ngx_int_t
ngx_ja_cache_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_ja_cache_ctx_t *octx = data;
    ngx_ja_cache_ctx_t *ctx;

    ctx = shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->slab = octx->slab;
        return NGX_OK;
    }

    ctx->slab = (ngx_slab_pool_t *) shm_zone->shm.addr;

    if (shm_zone->shm.exists) {
        ctx->sh = ctx->slab->data;
        return NGX_OK;
    }

    ctx->sh = ngx_slab_alloc(ctx->slab, sizeof(ngx_ja_cache_shctx_t));
    if (ctx->sh == NULL) return NGX_ERROR;

    ctx->slab->data = ctx->sh;

    ngx_rbtree_init(&ctx->sh->rbtree, &ctx->sh->sentinel,
                    ngx_rbtree_insert_value);

    return NGX_OK;
}

/* ---------- SSL INIT ---------- */

ngx_int_t
ngx_ja_ssl_init(ngx_conf_t *cf, ngx_http_ja_conf_t *conf)
{
    /*
    SSL_CTX *ssl_ctx;

    ssl_ctx = ngx_ssl_get_ssl_ctx(cf);
    if (ssl_ctx == NULL) return NGX_ERROR;
*/
    ngx_http_ssl_srv_conf_t  *sscf;

sscf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
if (sscf == NULL || sscf->ssl.ctx == NULL) {
    return NGX_ERROR;
}

SSL_CTX *ssl_ctx = sscf->ssl.ctx;


    /* ex_data index */
    if (ngx_ja_ex_index == -1) {
        ngx_ja_ex_index = SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
        if (ngx_ja_ex_index == -1) return NGX_ERROR;
    }

    // chỉ hỗ trợ chuẩn openssl 1.1.1W ( 3.x không hỗ trợ nên không dùng)
    /* ClientHello hook */
    SSL_CTX_set_client_hello_cb(ssl_ctx, ngx_ja_client_hello_cb, NULL);

    /* SHM cache */
    if (conf->enable_cache) {
        ngx_str_t name = ngx_string("ja_fp_cache");

        ngx_ja_cache_ctx = ngx_pcalloc(cf->pool, sizeof(*ngx_ja_cache_ctx));
        if (!ngx_ja_cache_ctx) return NGX_ERROR;

        // set size full will return null  => not crash app 
        ngx_ja_shm_zone = ngx_shared_memory_add(
            cf, &name, conf->shm_size, &ngx_http_ja3_module);

        if (ngx_ja_shm_zone == NULL) return NGX_ERROR;

        ngx_ja_shm_zone->init = ngx_ja_cache_init;
        ngx_ja_shm_zone->data = ngx_ja_cache_ctx;
    }

    return NGX_OK;
}

//get fp 
ngx_ja_fp_t *
ngx_ja_ssl_get_fp(SSL *ssl)
{
    ngx_ja_fp_t *fp;

    /* 1️⃣ fast path: ex_data */
    fp = SSL_get_ex_data(ssl, ngx_ja_ex_index);
    if (fp) return fp;

    /* 2️⃣ cache disabled */
    if (!ngx_ja_cache_ctx) return NULL;

    /* 3️⃣ lookup SHM cache */
    uint32_t key = (uint32_t)(uintptr_t)ssl;
    ngx_rbtree_node_t *node = ngx_ja_cache_ctx->sh->rbtree.root;
    ngx_rbtree_node_t *sentinel = ngx_ja_cache_ctx->sh->rbtree.sentinel;

    while (node != sentinel) {
        ngx_ja_cache_node_t *cn = (ngx_ja_cache_node_t *) node;

        if (key < cn->hash) {
            node = node->left;
        } else if (key > cn->hash) {
            node = node->right;
        } else {
            cn->last_seen = ngx_current_msec;
            SSL_set_ex_data(ssl, ngx_ja_ex_index, &cn->fp);
            return &cn->fp;
        }
    }

    return NULL;
}


/*
 * =========================================================
 *  ClientHello callback – CORE OF ENTIRE ENGINE
 * =========================================================
 */
int
ngx_ja_client_hello_cb(SSL *ssl, int *al, void *arg)
{
    //const unsigned char *data = NULL;
    //size_t len = 0;

    
    ngx_ja_fp_t *fp;
    ngx_uint_t use_cache;

 //   ngx_connection_t  *c;
  //  ngx_pool_t        *pool;
    // c = ngx_ssl_get_connection(ssl);
   // pool = c->pool;

    /* -----------------------------------------------------
     * 1️⃣ Lấy raw ClientHello (OpenSSL safe)
     V3.x  suppport
     * ----------------------------------------------------- */
/*
     if (SSL_client_hello_get0_raw(ssl, &data, &len) != 1 ||
        data == NULL || len == 0)
    {
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    */

    /* -----------------------------------------------------
     * 2️⃣ Nếu đã có fp (resumed session)
     * ----------------------------------------------------- */
    fp = SSL_get_ex_data(ssl, ngx_ja_ex_index);
    if (fp != NULL) {
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    /* -----------------------------------------------------
     * 3️⃣ Quyết định dùng cache hay không
     * ----------------------------------------------------- */
    use_cache = (ngx_ja_cache_ctx != NULL);

    /* -----------------------------------------------------
     * 4️⃣ Allocate fingerprint (1 lần / TLS)
     * ----------------------------------------------------- */
    fp = OPENSSL_zalloc(sizeof(ngx_ja_fp_t));
    if (fp == NULL) {
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    /* -----------------------------------------------------
     * 5️⃣ Parse ClientHello (RFC compliant)
     * ----------------------------------------------------- */
   /*
   // use case v3
     if (ngx_ja_parse_client_hello(data, len, fp) != NGX_OK) {
        OPENSSL_free(fp);
        return SSL_CLIENT_HELLO_SUCCESS;
    }
*/

if (ngx_ja_parse_client_hello(ssl, fp) != NGX_OK) {
        OPENSSL_free(fp);
        return SSL_CLIENT_HELLO_SUCCESS;
    }


    /* -----------------------------------------------------
     * 6️⃣ Build JA3 / JA4
     * ----------------------------------------------------- */
    ngx_ja3_build(fp);
    ngx_ja4_build(fp);

    /* -----------------------------------------------------
     * 7️⃣ Detect OS từ JA4 signals (🔥 ĐÚNG CHỖ 🔥)
     * ----------------------------------------------------- */
    ngx_ja4_set_os(fp);
   

    /* -----------------------------------------------------
     * 8️⃣ Hash (JA3 MD5 / xx64 + JA4 xx64)
     * ----------------------------------------------------- */
    ngx_ja_hash(fp);

    /* -----------------------------------------------------
     * 9️⃣ Insert SHM cache (nếu bật)
     * ----------------------------------------------------- */
    if (use_cache) {
        ngx_ja_cache_node_t *cn;

        cn = ngx_slab_alloc_locked(
                ngx_ja_cache_ctx->slab,
                sizeof(ngx_ja_cache_node_t));

        if (cn != NULL) {
            cn->magic     = NGX_JA_CACHE_MAGIC;
            cn->hash      = (uint32_t)(uintptr_t) ssl;
            cn->last_seen = ngx_current_msec;

            /* struct copy – no pointer alias */
            cn->fp = *fp;

            ngx_rbtree_insert(
                &ngx_ja_cache_ctx->sh->rbtree,
                (ngx_rbtree_node_t *) cn
            );
        }
    }

    /* -----------------------------------------------------
     * 🔟 Attach fp to SSL – HTTP phase chỉ đọc
     * ----------------------------------------------------- */
    SSL_set_ex_data(ssl, ngx_ja_ex_index, fp);

    return SSL_CLIENT_HELLO_SUCCESS;
}
