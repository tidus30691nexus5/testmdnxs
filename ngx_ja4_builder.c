
//#include <openssl/evp.h>
#include "ngx_ja4_builder.h"

/* map TLS version to short */
static ngx_inline uint8_t
ngx_tls_ver_short(uint16_t v)
{
    switch (v) {
    case 0x0304: return 13;
    case 0x0303: return 12;
    case 0x0302: return 11;
    case 0x0301: return 10;
    default:     return 0;
    }
}

ngx_int_t
ngx_ja4_build(ngx_ja_fp_t *fp)
{
    u_char *p = fp->ja4;

    /* t = tcp */
    *p++ = 't';

    /* TLS version */
    p = ngx_sprintf(p, "%d", ngx_tls_ver_short(fp->tls_version));

    /* direction = client */
    *p++ = 'd';

    /* cipher count */
    p = ngx_sprintf(p, "%d", fp->cipher_cnt);

    /* extension count */
    p = ngx_sprintf(p, "%d", fp->ext_cnt);

    /* ALPN (hardcode h2 for now) */
    *p++ = 'h';
    *p++ = '2';

    /* simple FNV-1a hash (no xxhash dep) */
    uint64_t h = 1469598103934665603ULL;

    for (uint8_t i = 0; i < fp->cipher_cnt; i++) {
        h ^= fp->ciphers[i];
        h *= 1099511628211ULL;
    }

    for (uint8_t i = 0; i < fp->ext_cnt; i++) {
        h ^= fp->exts[i];
        h *= 1099511628211ULL;
    }

    /* append hash */
    p = ngx_sprintf(p, "_%ux", (uint32_t)(h & 0xfffff));

    fp->ja4_len = (u_char)(p - fp->ja4);
    return NGX_OK;
}
