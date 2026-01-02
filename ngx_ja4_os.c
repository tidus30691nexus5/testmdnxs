#include "ngx_ja3_ssl.h"
#include "ngx_ja4_os.h"

/*
static ngx_inline ngx_flag_t
has_cipher(ngx_ja_fp_t *fp, uint16_t cs)
{
    for (uint8_t i = 0; i < fp->cipher_cnt; i++) {
        if (fp->ciphers[i] == cs)
            return 1;
    }
    return 0;
}

static ngx_inline ngx_flag_t
has_ext(ngx_ja_fp_t *fp, uint16_t ext)
{
    for (uint8_t i = 0; i < fp->ext_cnt; i++) {
        if (fp->exts[i] == ext)
            return 1;
    }
    return 0;
}
*/
/*


TLS ClientHello chứa:

Cipher Suites (danh sách mã hóa client hỗ trợ)

Extensions (các khả năng bổ sung)

Ví dụ (rút gọn):

ClientHello {
  cipher_suites: [4865, 4866, 4867, ...]
  extensions:    [0, 5, 10, 11, 13, 43, ...]
}


👉 has_cipher() và has_ext() chỉ scan mảng này.

2️⃣ GIẢI THÍCH CỤ THỂ CÁC CON SỐ
🔐 CIPHER SUITE IDs (TLS 1.3)
Số	Cipher	Ý nghĩa
4865	TLS_AES_128_GCM_SHA256	iOS / Safari ưu tiên
4866	TLS_AES_256_GCM_SHA384	Windows (Schannel)
4867	TLS_CHACHA20_POLY1305_SHA256	macOS / Linux

TLS 1.3 cipher IDs bắt đầu từ 4865

🧩 TLS EXTENSION IDs
ID	Extension	Dùng để làm gì
5	status_request	OCSP stapling
10	supported_groups	Curve (x25519, secp256r1…)
18	signed_certificate_timestamp	SCT (Windows rất hay gửi)
43	supported_versions	TLS 1.3
45	psk_key_exchange_modes	TLS 1.3 PSK
51	key_share	BẮT BUỘC TLS 1.3
*/

static ngx_str_t ngx_ja4_os_windows = ngx_string("windows");
static ngx_str_t ngx_ja4_os_macos   = ngx_string("macos");
static ngx_str_t ngx_ja4_os_linux   = ngx_string("linux");
static ngx_str_t ngx_ja4_os_android = ngx_string("android");
static ngx_str_t ngx_ja4_os_ios     = ngx_string("ios");
static ngx_str_t ngx_ja4_os_unknown = ngx_string("unknown");


ngx_str_t
ngx_ja4_os_name(ngx_ja4_os_t os)
{
    switch (os) {
    case NGX_JA4_OS_WINDOWS: return ngx_ja4_os_windows;
    case NGX_JA4_OS_MACOS:   return ngx_ja4_os_macos;
    case NGX_JA4_OS_LINUX:   return ngx_ja4_os_linux;
    case NGX_JA4_OS_ANDROID: return ngx_ja4_os_android;
    case NGX_JA4_OS_IOS:     return ngx_ja4_os_ios;
    default:                return ngx_ja4_os_unknown;
    }
}


ngx_ja4_os_t
ngx_ja4_detect_os(ngx_ja_fp_t *fp)
{
    /* iOS */
    if (fp->tls_version == 0x0303 &&
        fp->cipher_cnt >= 10 &&
        fp->curves[0] == 29 &&
        fp->exts[0] == 0 &&
        fp->exts[1] == 11) {
        return NGX_JA4_OS_IOS;
    }

    /* Android */
    if (fp->curves[0] == 29 &&
        fp->exts[2] == 43 &&
        fp->exts[3] == 45) {
        return NGX_JA4_OS_ANDROID;
    }

    /* Windows */
    if (fp->cipher_cnt > 15 &&
        fp->exts[0] == 0 &&
        fp->exts[1] == 10 &&
        fp->exts[2] == 11) {
        return NGX_JA4_OS_WINDOWS;
    }

    /* macOS */
    if (fp->curves[0] == 29 &&
        fp->exts[1] == 10 &&
        fp->exts[2] == 11 &&
        fp->exts[3] == 13) {
        return NGX_JA4_OS_MACOS;
    }

    /* Linux */
    if (fp->cipher_cnt < 10 &&
        fp->curves[0] == 29 &&
        fp->exts[1] == 11) {
        return NGX_JA4_OS_LINUX;
    }

    return NGX_JA4_OS_UNKNOWN;
}


static void
ngx_ja4_set_os(ngx_ja_fp_t *fp)
{
    switch (ngx_ja4_detect_os(fp)) {
    case NGX_JA4_OS_WINDOWS:
        fp->ja4os_len = ngx_sprintf(fp->ja4os, "windows") - fp->ja4os;
        break;
    case NGX_JA4_OS_MACOS:
        fp->ja4os_len = ngx_sprintf(fp->ja4os, "macos") - fp->ja4os;
        break;
    case NGX_JA4_OS_LINUX:
        fp->ja4os_len = ngx_sprintf(fp->ja4os, "linux") - fp->ja4os;
        break;
    case NGX_JA4_OS_ANDROID:
        fp->ja4os_len = ngx_sprintf(fp->ja4os, "android") - fp->ja4os;
        break;
    case NGX_JA4_OS_IOS:
        fp->ja4os_len = ngx_sprintf(fp->ja4os, "ios") - fp->ja4os;
        break;
    default:
        fp->ja4os_len = ngx_sprintf(fp->ja4os, "unknown") - fp->ja4os;
    }
}
