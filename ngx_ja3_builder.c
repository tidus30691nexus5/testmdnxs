#include "ngx_ja3_builder.h"

/* append helpers (zero alloc) */

static ngx_inline u_char *
ngx_append_u16(u_char *p, uint16_t v)
{
    return ngx_sprintf(p, "%ui", v);
}

static ngx_inline u_char *
ngx_append_list_u16(u_char *p, uint16_t *arr, uint8_t n)
{
    for (uint8_t i = 0; i < n; i++) {
        p = ngx_append_u16(p, arr[i]);
        if (i + 1 < n) *p++ = '-';
    }
    return p;
}

static ngx_inline u_char *
ngx_append_list_u8(u_char *p, uint8_t *arr, uint8_t n)
{
    for (uint8_t i = 0; i < n; i++) {
        p = ngx_sprintf(p, "%ui", arr[i]);
        if (i + 1 < n) *p++ = '-';
    }
    return p;
}

/* ================= JA3 ================= */

void
ngx_ja3_build(ngx_ja_fp_t *fp)
{
    u_char *p = fp->ja3;

    /* TLSVersion */
    p = ngx_append_u16(p, fp->tls_version);
    *p++ = ',';

    /* CipherSuites */
    p = ngx_append_list_u16(p, fp->ciphers, fp->cipher_cnt);
    *p++ = ',';

    /* Extensions */
    p = ngx_append_list_u16(p, fp->exts, fp->ext_cnt);
    *p++ = ',';

    /* EllipticCurves */
    p = ngx_append_list_u16(p, fp->curves, fp->curve_cnt);
    *p++ = ',';

    /* ECPointFormats */
    p = ngx_append_list_u8(p, fp->ec_pf, fp->ec_pf_cnt);

    fp->ja3_len = p - fp->ja3;
}

/* ================= JA3S (SERVER) ================= */
/* Với nginx: JA3S = negotiated cipher + ext order */

void
ngx_ja3s_build(ngx_ja_fp_t *fp, uint16_t server_cipher)
{
    u_char *p = fp->ja3s;

    p = ngx_append_u16(p, fp->tls_version);
    *p++ = ',';

    p = ngx_append_u16(p, server_cipher);
    *p++ = ',';

    p = ngx_append_list_u16(p, fp->exts, fp->ext_cnt);
    *p++ = ',';

    p = ngx_append_list_u16(p, fp->curves, fp->curve_cnt);
    *p++ = ',';

    p = ngx_append_list_u8(p, fp->ec_pf, fp->ec_pf_cnt);

    fp->ja3s_len = p - fp->ja3s;
}
