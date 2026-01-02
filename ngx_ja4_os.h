#ifndef _NGX_JA4_OS_H_
#define _NGX_JA4_OS_H_

#include <ngx_config.h>
#include <ngx_core.h>

typedef enum {
    NGX_JA4_OS_UNKNOWN = 0,
    NGX_JA4_OS_WINDOWS,
    NGX_JA4_OS_MACOS,
    NGX_JA4_OS_LINUX,
    NGX_JA4_OS_ANDROID,
    NGX_JA4_OS_IOS
} ngx_ja4_os_t;

/*
ngx_ja4_os_t ngx_ja4_detect_os(
    ngx_ja_fp_t *fp,
    ngx_str_t *ua);
*/
ngx_ja4_os_t ngx_ja4_detect_os(
    ngx_ja_fp_t *fp);

ngx_str_t ngx_ja4_os_name(ngx_ja4_os_t os);

static void ngx_ja4_set_os(ngx_ja_fp_t *fp)

#endif
