#ifndef _NGX_HTTP_JA3_MODULE_H_
#define _NGX_HTTP_JA3_MODULE_H_

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t ja3;
    
} ngx_ja3_ctx_t;


typedef struct {
    ngx_flag_t ja3;
    ngx_flag_t ja4;

    ngx_flag_t enable_cache;
    size_t     shm_size;
    ngx_msec_t cache_ttl;
} ngx_http_ja_conf_t;



extern ngx_module_t ngx_http_ja3_module;

#endif
