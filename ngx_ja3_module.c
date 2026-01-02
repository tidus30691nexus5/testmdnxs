#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include "ngx_ja3_module.h"
#include "ngx_ja3_ssl.h"
#include "ngx_ja3_cache.h"

/*
 * =========================================================
 *  HTTP VARIABLE HANDLERS (READ-ONLY, ZERO ALLOC)
 * =========================================================
 */

static ngx_ja_fp_t *
ngx_http_ja_get_fp(ngx_http_request_t *r)
{
    SSL *ssl;

    if (r->connection == NULL || r->connection->ssl == NULL)
        return NULL;

    ssl = r->connection->ssl->connection;
    if (ssl == NULL)
        return NULL;

    return ngx_ja_ssl_get_fp(ssl);
}

/* ---------------- string variables ---------------- */

#define NGX_JA_VAR_STRING(name, field, lenfield)                 \
static ngx_int_t                                                  \
ngx_http_##name##_var(ngx_http_request_t *r,                     \
                      ngx_http_variable_value_t *v,               \
                      uintptr_t data)                             \
{                                                                 \
    ngx_ja_fp_t *fp = ngx_http_ja_get_fp(r);                      \
    if (fp == NULL || fp->lenfield == 0) {                        \
        v->not_found = 1;                                         \
        return NGX_OK;                                            \
    }                                                             \
                                                                  \
    v->data = fp->field;                                          \
    v->len = fp->lenfield;                                        \
    v->valid = 1;                                                 \
    v->no_cacheable = 0;                                          \
    v->not_found = 0;                                             \
    return NGX_OK;                                                \
}

#define ADD_VAR(name, handler)                                 \
    do {                                                       \
        ngx_str_t  vname = ngx_string(name);                  \
        v = ngx_http_add_variable(cf, &vname,                 \
                                  NGX_HTTP_VAR_CHANGEABLE);  \
        if (v == NULL) {                                      \
            return NGX_ERROR;                                 \
        }                                                      \
        v->get_handler = handler;                             \
        v->data = 0;                                          \
    } while (0)

NGX_JA_VAR_STRING(ja3,    ja3,    ja3_len)
NGX_JA_VAR_STRING(ja3s,   ja3s,   ja3s_len)
NGX_JA_VAR_STRING(ja4,    ja4,    ja4_len)
NGX_JA_VAR_STRING(ja4os,  ja4os,  ja4os_len)

/* ---------------- hash variables ---------------- */

static ngx_int_t
ngx_http_ja3hash_var(ngx_http_request_t *r,
                     ngx_http_variable_value_t *v,
                     uintptr_t data)
{
    ngx_ja_fp_t *fp = ngx_http_ja_get_fp(r);
    static u_char hex[32];

    if (fp == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    ngx_hex_dump(hex, fp->ja3_md5, 16);

    v->data = hex;
    v->len = 32;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ja3hash_xx64_var(ngx_http_request_t *r,
                          ngx_http_variable_value_t *v,
                          uintptr_t data)
{
    ngx_ja_fp_t *fp = ngx_http_ja_get_fp(r);
    static u_char buf[32];

    if (fp == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ngx_sprintf(buf, "%uxL", fp->ja3_xx64) - buf;
    v->data = buf;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

static ngx_int_t
ngx_http_ja4hash_var(ngx_http_request_t *r,
                     ngx_http_variable_value_t *v,
                     uintptr_t data)
{
    ngx_ja_fp_t *fp = ngx_http_ja_get_fp(r);
    static u_char buf[32];

    if (fp == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->len = ngx_sprintf(buf, "%uxL", fp->ja4_xx64) - buf;
    v->data = buf;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ja_add_variables(ngx_conf_t *cf)
{
   
 ngx_http_variable_t *v; 
    ADD_VAR("ja3",      ngx_http_ja3_var);
    ADD_VAR("ja3s",     ngx_http_ja3s_var);
    ADD_VAR("ja4",      ngx_http_ja4_var);
    ADD_VAR("ja4os",    ngx_http_ja4os_var);
    ADD_VAR("ja3hash",  ngx_http_ja3hash_var);
    ADD_VAR("ja3hash64",ngx_http_ja3hash_xx64_var);
    ADD_VAR("ja4hash",  ngx_http_ja4hash_var);

    

    return NGX_OK;
}



/*
 * =========================================================
 *  DIRECTIVES
 * =========================================================
 */
/*
typedef struct {
    ngx_flag_t ja3;
    ngx_flag_t ja4;

    ngx_flag_t enable_cache;
    size_t     shm_size;
    ngx_msec_t cache_ttl;
} ngx_http_ja_conf_t;
*/
/* ---------------- directives ---------------- */

static ngx_command_t ngx_http_ja_commands[] = {

    { ngx_string("ja3"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ja_conf_t, ja3),
      NULL },

    { ngx_string("ja4"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ja_conf_t, ja4),
      NULL },

    { ngx_string("ja_cache"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_ja_conf_t, enable_cache),
      NULL },

    { ngx_string("ja_cache_size"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja_conf_t, shm_size),
      NULL },

    { ngx_string("ja_cache_ttl"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja_conf_t, cache_ttl),
      NULL },

    ngx_null_command
};

/*
 * =========================================================
 *  CONF CREATE / MERGE
 * =========================================================
 */

static void *
ngx_http_ja_create_conf(ngx_conf_t *cf)
{
    ngx_http_ja_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(*conf));
    if (conf == NULL)
        return NULL;

    conf->ja3 = NGX_CONF_UNSET;
    conf->ja4 = NGX_CONF_UNSET;
    conf->enable_cache = NGX_CONF_UNSET;

    conf->shm_size = NGX_CONF_UNSET_SIZE;
    conf->cache_ttl = NGX_CONF_UNSET_MSEC;

    return conf;
}

static char *
ngx_http_ja_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ja_conf_t *prev = parent;
    ngx_http_ja_conf_t *conf = child;

    ngx_conf_merge_value(conf->ja3, prev->ja3, 0);
    ngx_conf_merge_value(conf->ja4, prev->ja4, 0);
    ngx_conf_merge_value(conf->enable_cache, prev->enable_cache, 1);

    ngx_conf_merge_size_value(conf->shm_size, prev->shm_size, 64 * 1024 * 1024);
    ngx_conf_merge_msec_value(conf->cache_ttl, prev->cache_ttl, 300000);

    return NGX_CONF_OK;
}

/*
 * =========================================================
 *  MODULE INIT (SSL HOOK)
 * =========================================================
 */

static ngx_int_t
ngx_http_ja_init(ngx_conf_t *cf)
{
    ngx_http_ja_conf_t *conf;

    conf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ja3_module);
    if (conf == NULL)
        return NGX_ERROR;

    return ngx_ja_ssl_init(cf, conf);
}

/*
 * =========================================================
 *  MODULE CONTEXT
 * =========================================================
 */

static ngx_http_module_t ngx_http_ja_module_ctx = {
     ngx_http_ja_add_variables, /* preconfiguration */
    ngx_http_ja_init,  /* postconfiguration */

  

    NULL,
    NULL,

    NULL,
    NULL,
      ngx_http_ja_create_conf, /* main conf */
    ngx_http_ja_merge_conf,
};

/*
 * =========================================================
 *  MODULE DEFINITION
 * =========================================================
 */

ngx_module_t ngx_http_ja3_module = {
    NGX_MODULE_V1,
    &ngx_http_ja_module_ctx,
    ngx_http_ja_commands,
    NGX_HTTP_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};
