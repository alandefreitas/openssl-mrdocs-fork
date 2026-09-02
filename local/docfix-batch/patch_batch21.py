#!/usr/bin/env python3
"""Documentation repair batch 21: capped MrDocs undocumented-symbol list."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"
ok, missing = [], []


def patch_both(rel, old, new, label):
    paths = [INC / rel]
    if not rel.endswith(".in"):
        paths.append(INC / (rel + ".in"))
    found = False
    for path in paths:
        if not path.exists():
            continue
        found = True
        text = path.read_text(encoding="utf-8")
        if old not in text:
            print(f"  MISS: {path.name} :: {label}")
            missing.append(f"{path.name}:{label}")
            continue
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"  OK: {path.name} :: {label}")
        ok.append(f"{path.name}:{label}")
    if not found:
        missing.append(f"{rel}:{label}:no-file")


def patch_one(rel, old, new, label):
    path = INC / rel
    if not path.exists():
        print(f"  MISS: {rel} :: {label}:no-file")
        missing.append(f"{rel}:{label}:no-file")
        return
    text = path.read_text(encoding="utf-8")
    if old not in text:
        print(f"  MISS: {path.name} :: {label}")
        missing.append(f"{path.name}:{label}")
        return
    path.write_text(text.replace(old, new, 1), encoding="utf-8")
    print(f"  OK: {path.name} :: {label}")
    ok.append(f"{path.name}:{label}")


print("=== batch 21 ===")

# ----- asn1.h / asn1.h.in -----

patch_both(
    "asn1.h",
    """OSSL_DEPRECATEDIN_1_1_0 unsigned char *ASN1_STRING_data(ASN1_STRING *x);
""",
    """/**
 * @brief Return a mutable pointer to the raw octets stored in an ASN1_STRING (deprecated).
 * @param x ASN.1 string to query.
 * @return Pointer to internal data (may be NULL); prefer ASN1_STRING_get0_data().
 */
OSSL_DEPRECATEDIN_1_1_0 unsigned char *ASN1_STRING_data(ASN1_STRING *x);
""",
    "ASN1_STRING_data",
)

patch_both(
    "asn1.h",
    """int ASN1_ENUMERATED_get_int64(int64_t *pr, const ASN1_ENUMERATED *a);
""",
    """/**
 * @brief Convert an ASN1_ENUMERATED to a signed 64-bit integer.
 * @param pr Receives the converted value on success.
 * @param a ASN.1 ENUMERATED value to convert.
 * @return 1 on success, or 0 if @p a is NULL or the value does not fit in int64_t.
 */
int ASN1_ENUMERATED_get_int64(int64_t *pr, const ASN1_ENUMERATED *a);
""",
    "ASN1_ENUMERATED_get_int64",
)

patch_both(
    "asn1.h",
    """ASN1_TYPE *ASN1_generate_nconf(const char *str, CONF *nconf);
""",
    """/**
 * @brief Build an ASN1_TYPE from an ASN.1 generation string, resolving CONF macros.
 * @param str Generation template (ASN1_generate_nconf(3) syntax).
 * @param nconf Optional CONF providing name/value substitutions, or NULL.
 * @return Newly allocated ASN1_TYPE, or NULL on error; free with ASN1_TYPE_free().
 */
ASN1_TYPE *ASN1_generate_nconf(const char *str, CONF *nconf);
""",
    "ASN1_generate_nconf",
)

# ----- bio.h / bio.h.in -----

patch_both(
    "bio.h",
    """OSSL_DEPRECATEDIN_3_0 BIO_callback_fn BIO_get_callback(const BIO *b);
OSSL_DEPRECATEDIN_3_0 void BIO_set_callback(BIO *b, BIO_callback_fn callback);
""",
    """/**
 * @brief Return the legacy BIO callback previously set with BIO_set_callback() (deprecated).
 * @param b BIO to query.
 * @return Callback function pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 BIO_callback_fn BIO_get_callback(const BIO *b);
/**
 * @brief Install a legacy pre/post I/O callback on a BIO (deprecated; prefer BIO_set_callback_ex).
 * @param b BIO whose callback is replaced.
 * @param callback Legacy callback function, or NULL to clear.
 */
OSSL_DEPRECATEDIN_3_0 void BIO_set_callback(BIO *b, BIO_callback_fn callback);
""",
    "BIO_get/set_callback",
)

patch_both(
    "bio.h",
    """BIO_callback_fn_ex BIO_get_callback_ex(const BIO *b);
""",
    """/**
 * @brief Return the extended BIO callback installed with BIO_set_callback_ex().
 * @param b BIO to query.
 * @return Extended callback, or NULL if unset.
 */
BIO_callback_fn_ex BIO_get_callback_ex(const BIO *b);
""",
    "BIO_get_callback_ex",
)

patch_both(
    "bio.h",
    """char *BIO_get_callback_arg(const BIO *b);
""",
    """/**
 * @brief Return the opaque callback-argument pointer stored on a BIO.
 * @param b BIO to query.
 * @return Pointer previously passed to BIO_set_callback_arg(), or NULL.
 */
char *BIO_get_callback_arg(const BIO *b);
""",
    "BIO_get_callback_arg",
)

patch_both(
    "bio.h",
    """/* Prefix and suffix callback in ASN1 BIO */
typedef int asn1_ps_func(BIO *b, unsigned char **pbuf, int *plen,
    void *parg);
""",
    """/**
 * @brief Prefix/suffix producer for an ASN.1 filter BIO (BIO_f_asn1).
 * @param b ASN.1 BIO requesting prefix or suffix octets.
 * @param pbuf Receives a pointer to the produced buffer (owned per BIO_asn1_set_* contract).
 * @param plen Receives the number of bytes at *@p pbuf.
 * @param parg Opaque pointer from BIO_asn1_set_prefix() / BIO_asn1_set_suffix().
 * @return 1 on success, or <=0 on failure.
 */
typedef int asn1_ps_func(BIO *b, unsigned char **pbuf, int *plen,
    void *parg);
""",
    "asn1_ps_func",
)

patch_both(
    "bio.h",
    """int BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix,
    asn1_ps_func **pprefix_free);
""",
    """/**
 * @brief Retrieve the ASN.1 prefix producer and optional free callback from a BIO.
 * @param b ASN.1 filter BIO (BIO_f_asn1).
 * @param pprefix Receives the prefix producer, or NULL if unset.
 * @param pprefix_free Receives the matching free callback, or NULL if unset.
 * @return 1 on success, or 0 on failure.
 */
int BIO_asn1_get_prefix(BIO *b, asn1_ps_func **pprefix,
    asn1_ps_func **pprefix_free);
""",
    "BIO_asn1_get_prefix",
)

patch_both(
    "bio.h",
    """int BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix,
    asn1_ps_func **psuffix_free);
""",
    """/**
 * @brief Retrieve the ASN.1 suffix producer and optional free callback from a BIO.
 * @param b ASN.1 filter BIO (BIO_f_asn1).
 * @param psuffix Receives the suffix producer, or NULL if unset.
 * @param psuffix_free Receives the matching free callback, or NULL if unset.
 * @return 1 on success, or 0 on failure.
 */
int BIO_asn1_get_suffix(BIO *b, asn1_ps_func **psuffix,
    asn1_ps_func **psuffix_free);
""",
    "BIO_asn1_get_suffix",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_file(void);
""",
    """/**
 * @brief Return the BIO_METHOD for stdio FILE-backed source/sink BIOs.
 * @return Pointer to the internal file BIO method table.
 */
const BIO_METHOD *BIO_s_file(void);
""",
    "BIO_s_file",
)

patch_both(
    "bio.h",
    """__owur int BIO_recvmmsg(BIO *b, BIO_MSG *msg,
    size_t stride, size_t num_msg, uint64_t flags,
    size_t *msgs_processed);
""",
    """/**
 * @brief Receive multiple datagram messages through a BIO (recvmmsg-style).
 * @param b Datagram-capable BIO.
 * @param msg Array of BIO_MSG descriptors to fill.
 * @param stride Byte stride between consecutive BIO_MSG elements.
 * @param num_msg Number of messages that may be received into @p msg.
 * @param flags Implementation-specific receive flags (often 0).
 * @param msgs_processed Receives how many messages were filled.
 * @return 1 on success, 0 on retry/failure (check BIO_should_retry()).
 */
__owur int BIO_recvmmsg(BIO *b, BIO_MSG *msg,
    size_t stride, size_t num_msg, uint64_t flags,
    size_t *msgs_processed);
""",
    "BIO_recvmmsg",
)

patch_both(
    "bio.h",
    """int BIO_indent(BIO *b, int indent, int max);
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
""",
    """/**
 * @brief Write up to @p max spaces of indentation to a BIO.
 * @param b Destination BIO.
 * @param indent Desired indentation depth in spaces.
 * @param max Maximum spaces actually written (clamps @p indent).
 * @return 1 on success, or 0 on write failure.
 */
int BIO_indent(BIO *b, int indent, int max);
/**
 * @brief Invoke a type-specific control operation on a BIO.
 * @param bp BIO to control.
 * @param cmd BIO_CTRL_* (or type-specific) command code.
 * @param larg Integer/long argument for @p cmd.
 * @param parg Pointer argument for @p cmd, or NULL.
 * @return Command-specific long result; often 1 for success and 0/negative for failure.
 */
long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);
""",
    "BIO_indent/BIO_ctrl",
)

patch_both(
    "bio.h",
    """BIO *BIO_dup_chain(BIO *in);
""",
    """/**
 * @brief Duplicate an entire BIO chain, copying type-specific state where supported.
 * @param in Head of the chain to duplicate.
 * @return Newly allocated chain mirroring @p in, or NULL on failure.
 */
BIO *BIO_dup_chain(BIO *in);
""",
    "BIO_dup_chain",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_dgram_mem(void);
""",
    """/**
 * @brief Return the BIO_METHOD for an in-memory datagram BIO.
 * @return Pointer to the internal dgram-mem method table.
 */
const BIO_METHOD *BIO_s_dgram_mem(void);
""",
    "BIO_s_dgram_mem",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_accept(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a passive TCP accept socket BIO.
 * @return Pointer to the internal accept method table.
 */
const BIO_METHOD *BIO_s_accept(void);
""",
    "BIO_s_accept",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_f_null(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a null filter that discards writes and yields EOF on reads.
 * @return Pointer to the internal null-filter method table.
 */
const BIO_METHOD *BIO_f_null(void);
""",
    "BIO_f_null",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_datagram(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a datagram (UDP) socket BIO.
 * @return Pointer to the internal datagram method table.
 */
const BIO_METHOD *BIO_s_datagram(void);
""",
    "BIO_s_datagram",
)

patch_both(
    "bio.h",
    """int BIO_do_connect_retry(BIO *bio, int timeout, int nap_milliseconds);
""",
    """/**
 * @brief Drive BIO_do_connect() with retries until connected, failed, or @p timeout elapses.
 * @param bio Connect BIO to advance.
 * @param timeout Overall timeout in seconds; 0 waits forever; <0 tries once without sleeping.
 * @param nap_milliseconds Sleep between non-blocking retries (or <=0 for a default nap).
 * @return 1 when connected, <=0 on failure or expiry (see BIO_should_retry()).
 */
int BIO_do_connect_retry(BIO *bio, int timeout, int nap_milliseconds);
""",
    "BIO_do_connect_retry",
)

patch_both(
    "bio.h",
    """int BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
    void *u, const void *s, int len, int indent);
int BIO_dump(BIO *b, const void *bytes, int len);
""",
    """int BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
    void *u, const void *s, int len, int indent);
/**
 * @brief Hex-dump @p len bytes at @p bytes to a BIO (no leading indent).
 * @param b Destination BIO.
 * @param bytes Bytes to dump.
 * @param len Number of bytes at @p bytes.
 * @return 1 on success, or 0 on error.
 */
int BIO_dump(BIO *b, const void *bytes, int len);
""",
    "BIO_dump",
)

patch_both(
    "bio.h",
    """BIO_ADDR *BIO_ADDR_new(void);
""",
    """/**
 * @brief Allocate a zero-initialized BIO_ADDR for socket address APIs.
 * @return New BIO_ADDR, or NULL on failure; free with BIO_ADDR_free().
 */
BIO_ADDR *BIO_ADDR_new(void);
""",
    "BIO_ADDR_new",
)

patch_both(
    "bio.h",
    """BIO_ADDR *BIO_ADDR_dup(const BIO_ADDR *ap);
""",
    """/**
 * @brief Duplicate a BIO_ADDR, copying its family and address bytes.
 * @param ap Address to copy, or NULL.
 * @return Newly allocated copy, or NULL on failure / if @p ap is NULL.
 */
BIO_ADDR *BIO_ADDR_dup(const BIO_ADDR *ap);
""",
    "BIO_ADDR_dup",
)

patch_both(
    "bio.h",
    """char *BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric);
char *BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric);
""",
    """/**
 * @brief Format the host portion of a BIO_ADDR as an allocated string.
 * @param ap Address to format.
 * @param numeric Non-zero to prefer numeric form (NI_NUMERICHOST); 0 may resolve a name.
 * @return Newly allocated NUL-terminated string; free with OPENSSL_free(), or NULL on error.
 */
char *BIO_ADDR_hostname_string(const BIO_ADDR *ap, int numeric);
/**
 * @brief Format the service/port portion of a BIO_ADDR as an allocated string.
 * @param ap Address to format.
 * @param numeric Non-zero to prefer a numeric port (NI_NUMERICSERV); 0 may use a service name.
 * @return Newly allocated NUL-terminated string; free with OPENSSL_free(), or NULL on error.
 */
char *BIO_ADDR_service_string(const BIO_ADDR *ap, int numeric);
""",
    "BIO_ADDR_hostname/service_string",
)

patch_both(
    "bio.h",
    """OSSL_DEPRECATEDIN_1_1_0 int BIO_accept(int sock, char **ip_port);
""",
    """/**
 * @brief Accept a connection on a listening socket and return peer host:port text (deprecated).
 * @param sock Listening socket fd from BIO_get_accept_socket().
 * @param ip_port Receives an allocated "host:port" string for the peer; free with OPENSSL_free().
 * @return Accepted socket fd on success, or -1 on error.
 */
OSSL_DEPRECATEDIN_1_1_0 int BIO_accept(int sock, char **ip_port);
""",
    "BIO_accept",
)

patch_both(
    "bio.h",
    """int BIO_listen(int sock, const BIO_ADDR *addr, int options);
int BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options);
""",
    """/**
 * @brief Bind and listen on a socket using @p addr and BIO_SOCK_* @p options.
 * @param sock Socket file descriptor to put into listening state.
 * @param addr Local address to bind (may be NULL for an already-bound socket).
 * @param options BIO_SOCK_* flags such as BIO_SOCK_REUSEADDR.
 * @return 1 on success, or 0 on failure.
 */
int BIO_listen(int sock, const BIO_ADDR *addr, int options);
/**
 * @brief Accept a connection on @p accept_sock, optionally capturing the peer address.
 * @param accept_sock Listening socket.
 * @param addr Optional BIO_ADDR filled with the peer address, or NULL.
 * @param options BIO_SOCK_* flags applied to the accepted socket (for example non-blocking).
 * @return Accepted socket fd on success, or -1 on failure.
 */
int BIO_accept_ex(int accept_sock, BIO_ADDR *addr, int options);
""",
    "BIO_listen/BIO_accept_ex",
)

patch_both(
    "bio.h",
    """BIO *BIO_new_accept(const char *host_port);
""",
    """/**
 * @brief Create an accept BIO bound to @p host_port (host:port or port-only form).
 * @param host_port Local bind specification parsed like BIO_set_accept_name().
 * @return New accept BIO, or NULL on failure; free with BIO_free_all().
 */
BIO *BIO_new_accept(const char *host_port);
""",
    "BIO_new_accept",
)

patch_both(
    "bio.h",
    """int BIO_new_bio_dgram_pair(BIO **bio1, size_t writebuf1,
    BIO **bio2, size_t writebuf2);
""",
    """/**
 * @brief Create a connected pair of in-memory datagram BIOs.
 * @param bio1 Receives the first BIO of the pair.
 * @param writebuf1 Write-buffer size for @p bio1 (0 selects a default).
 * @param bio2 Receives the second BIO of the pair.
 * @param writebuf2 Write-buffer size for @p bio2 (0 selects a default).
 * @return 1 on success, or 0 on failure.
 */
int BIO_new_bio_dgram_pair(BIO **bio1, size_t writebuf1,
    BIO **bio2, size_t writebuf2);
""",
    "BIO_new_bio_dgram_pair",
)

patch_both(
    "bio.h",
    """void BIO_copy_next_retry(BIO *b);
""",
    """/**
 * @brief Copy retry reason/flags from the next BIO in the chain onto @p b.
 * @param b BIO whose retry state is updated from BIO_next(b).
 */
void BIO_copy_next_retry(BIO *b);
""",
    "BIO_copy_next_retry",
)

patch_both(
    "bio.h",
    """int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
""",
    """/**
 * @brief Format a string into @p buf like vsnprintf, using OpenSSL's portable formatter.
 * @param buf Destination buffer.
 * @param n Capacity of @p buf in bytes (including the trailing NUL).
 * @param format printf-style format string.
 * @param args Variable-argument list for @p format.
 * @return Length that would have been written excluding the NUL, or -1 on encoding error.
 */
int BIO_vsnprintf(char *buf, size_t n, const char *format, va_list args)
""",
    "BIO_vsnprintf",
)

# ----- blowfish.h -----

patch_one(
    "blowfish.h",
    """OSSL_DEPRECATEDIN_3_0 void BF_set_key(BF_KEY *key, int len,
    const unsigned char *data);
""",
    """/**
 * @brief Expand a raw Blowfish key into a BF_KEY schedule (deprecated).
 * @param key Destination key schedule.
 * @param len Number of key bytes at @p data (1..56 typical; longer keys are truncated per Blowfish).
 * @param data Raw key octets.
 */
OSSL_DEPRECATEDIN_3_0 void BF_set_key(BF_KEY *key, int len,
    const unsigned char *data);
""",
    "BF_set_key",
)

patch_one(
    "blowfish.h",
    """OSSL_DEPRECATEDIN_3_0 const char *BF_options(void);
""",
    """/**
 * @brief Return a short string describing the compiled Blowfish implementation (deprecated).
 * @return Static implementation tag such as "blowfish(ptr)"; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const char *BF_options(void);
""",
    "BF_options",
)

# ----- bn.h -----

patch_one(
    "bn.h",
    """int BN_get_flags(const BIGNUM *b, int n);
""",
    """/**
 * @brief Test whether the given BN_FLG_* bits are set on a BIGNUM.
 * @param b BIGNUM to query.
 * @param n Flag mask (for example BN_FLG_CONSTTIME).
 * @return @p n bits that are set on @p b (0 if none).
 */
int BN_get_flags(const BIGNUM *b, int n);
""",
    "BN_get_flags",
)

patch_one(
    "bn.h",
    """int BN_is_zero(const BIGNUM *a);
""",
    """/**
 * @brief Test whether a BIGNUM is zero.
 * @param a Value to test.
 * @return 1 if @p a is zero, or 0 otherwise.
 */
int BN_is_zero(const BIGNUM *a);
""",
    "BN_is_zero",
)

patch_one(
    "bn.h",
    """int BN_is_word(const BIGNUM *a, const BN_ULONG w);
int BN_is_odd(const BIGNUM *a);
""",
    """/**
 * @brief Test whether a BIGNUM equals the single word @p w (including sign of zero).
 * @param a Value to test.
 * @param w Word value to compare against.
 * @return 1 if @p a equals @p w, or 0 otherwise.
 */
int BN_is_word(const BIGNUM *a, const BN_ULONG w);
/**
 * @brief Test whether a BIGNUM is odd.
 * @param a Value to test.
 * @return 1 if the least-significant bit of @p a is set, or 0 otherwise.
 */
int BN_is_odd(const BIGNUM *a);
""",
    "BN_is_word/BN_is_odd",
)

patch_one(
    "bn.h",
    """void BN_CTX_end(BN_CTX *ctx);
""",
    """/**
 * @brief End a BN_CTX temporary frame started with BN_CTX_start(), releasing its BN_CTX_get() values.
 * @param ctx Context whose current frame is popped.
 */
void BN_CTX_end(BN_CTX *ctx);
""",
    "BN_CTX_end",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
void BN_swap(BIGNUM *a, BIGNUM *b);
""",
    """/**
 * @brief Copy BIGNUM @p b into @p a, resizing @p a as needed.
 * @param a Destination (must be non-NULL).
 * @param b Source value.
 * @return @p a on success, or NULL on allocation failure.
 */
BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b);
/**
 * @brief Exchange the values of two BIGNUMs in constant time relative to their limb counts.
 * @param a First value.
 * @param b Second value.
 */
void BN_swap(BIGNUM *a, BIGNUM *b);
""",
    "BN_copy/BN_swap",
)

patch_one(
    "bn.h",
    """int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
""",
    """/**
 * @brief Encode a BIGNUM as fixed-length little-endian unsigned bytes with zero padding.
 * @param a Value to encode (absolute value; sign is ignored).
 * @param to Destination buffer of @p tolen bytes.
 * @param tolen Required output length; must be large enough for @p a.
 * @return @p tolen on success, or -1 if @p tolen is too small or on error.
 */
int BN_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen);
""",
    "BN_bn2lebinpad",
)

patch_one(
    "bn.h",
    """BIGNUM *BN_native2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    """/**
 * @brief Decode a native-endian unsigned byte string into a BIGNUM.
 * @param s Input bytes in host endianness.
 * @param len Number of bytes at @p s.
 * @param ret Optional existing BIGNUM to reuse, or NULL to allocate.
 * @return Result BIGNUM (same as @p ret when non-NULL), or NULL on error.
 */
BIGNUM *BN_native2bn(const unsigned char *s, int len, BIGNUM *ret);
""",
    "BN_native2bn",
)

patch_one(
    "bn.h",
    """int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
""",
    """/**
 * @brief Compute a non-negative remainder @p r = @p m mod @p d (0 <= r < |d|).
 * @param r Destination remainder.
 * @param m Dividend.
 * @param d Modulus (must be non-zero).
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx);
/**
 * @brief Modular addition: @p r = (@p a + @p b) mod @p m with non-negative result.
 * @param r Destination.
 * @param a First addend.
 * @param b Second addend.
 * @param m Modulus.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_add(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
""",
    "BN_nnmod/BN_mod_add",
)

patch_one(
    "bn.h",
    """int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);
""",
    """/**
 * @brief Left-shift then reduce quickly: @p r = (@p a << @p n) mod @p m (assumes 0 <= a < m).
 * @param r Destination.
 * @param a Value already reduced modulo @p m.
 * @param n Number of bits to shift left (non-negative).
 * @param m Modulus.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);
""",
    "BN_mod_lshift_quick",
)

patch_one(
    "bn.h",
    """BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
""",
    """/**
 * @brief Return @p a modulo word @p w.
 * @param a Dividend.
 * @param w Modulus word (must be non-zero).
 * @return Remainder in [0, w), or (BN_ULONG)-1 on error.
 */
BN_ULONG BN_mod_word(const BIGNUM *a, BN_ULONG w);
""",
    "BN_mod_word",
)

patch_one(
    "bn.h",
    """int BN_mul_word(BIGNUM *a, BN_ULONG w);
""",
    """/**
 * @brief Multiply BIGNUM @p a by word @p w in place: a := a * w.
 * @param a Value to scale (updated in place).
 * @param w Multiplier word.
 * @return 1 on success, or 0 on error.
 */
int BN_mul_word(BIGNUM *a, BN_ULONG w);
""",
    "BN_mul_word",
)

patch_one(
    "bn.h",
    """int BN_sub_word(BIGNUM *a, BN_ULONG w);
""",
    """/**
 * @brief Subtract word @p w from BIGNUM @p a in place: a := a - w.
 * @param a Value to update.
 * @param w Word to subtract.
 * @return 1 on success, or 0 on error.
 */
int BN_sub_word(BIGNUM *a, BN_ULONG w);
""",
    "BN_sub_word",
)

patch_one(
    "bn.h",
    """int BN_cmp(const BIGNUM *a, const BIGNUM *b);
""",
    """/**
 * @brief Compare two BIGNUMs considering sign.
 * @param a First value (NULL treated as zero).
 * @param b Second value (NULL treated as zero).
 * @return -1 if a < b, 0 if equal, or 1 if a > b.
 */
int BN_cmp(const BIGNUM *a, const BIGNUM *b);
""",
    "BN_cmp",
)

patch_one(
    "bn.h",
    """int BN_is_bit_set(const BIGNUM *a, int n);
""",
    """/**
 * @brief Test whether bit @p n of a BIGNUM is set.
 * @param a Value to test.
 * @param n Bit index (0 is the least-significant bit).
 * @return 1 if the bit is set, or 0 otherwise.
 */
int BN_is_bit_set(const BIGNUM *a, int n);
""",
    "BN_is_bit_set",
)

patch_one(
    "bn.h",
    """int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *m_ctx);
""",
    """/**
 * @brief Montgomery modular dual exponentiation: r = a1^p1 * a2^p2 mod m.
 * @param r Destination.
 * @param a1 First base.
 * @param p1 First exponent.
 * @param a2 Second base.
 * @param p2 Second exponent.
 * @param m Odd modulus matching @p m_ctx.
 * @param ctx BN_CTX scratch space.
 * @param m_ctx Montgomery context for @p m.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_exp2_mont(BIGNUM *r, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *m_ctx);
""",
    "BN_mod_exp2_mont",
)

patch_one(
    "bn.h",
    """int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
""",
    """/**
 * @brief Compute a reciprocal @p r = 2^@p len / @p m for BN_div-style quotient estimation.
 * @param r Destination reciprocal.
 * @param m Divisor.
 * @param len Bit precision of the reciprocal.
 * @param ctx BN_CTX scratch space.
 * @return @p len on success, or -1 on error.
 */
int BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
""",
    "BN_reciprocal",
)

patch_one(
    "bn.h",
    """int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
""",
    """/**
 * @brief Compute the greatest common divisor of @p a and @p b.
 * @param r Destination for gcd(|a|, |b|).
 * @param a First value.
 * @param b Second value.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_gcd(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
""",
    "BN_gcd",
)

patch_one(
    "bn.h",
    """void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);
""",
    """/**
 * @brief Conditionally swap the top @p nwords limbs (and top/neg) of two BIGNUMs in constant time.
 * @param swap Non-zero to swap, or zero to leave @p a and @p b unchanged (must be 0 or 1).
 * @param a First BIGNUM (must have at least @p nwords usable limbs).
 * @param b Second BIGNUM (same size requirement as @p a).
 * @param nwords Number of limbs to exchange.
 */
void BN_consttime_swap(BN_ULONG swap, BIGNUM *a, BIGNUM *b, int nwords);
""",
    "BN_consttime_swap",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_3_0
int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
""",
    """/**
 * @brief Test whether @p p is prime using Miller-Rabin (deprecated; prefer BN_check_prime).
 * @param p Candidate integer.
 * @param nchecks Number of Miller-Rabin rounds, or BN_prime_checks for a default.
 * @param ctx Optional BN_CTX, or NULL to allocate internally.
 * @param cb Optional progress callback, or NULL.
 * @return 1 if probably prime, 0 if composite, or -1 on error.
 */
OSSL_DEPRECATEDIN_3_0
int BN_is_prime_ex(const BIGNUM *p, int nchecks, BN_CTX *ctx, BN_GENCB *cb);
""",
    "BN_is_prime_ex",
)

patch_one(
    "bn.h",
    """int BN_check_prime(const BIGNUM *p, BN_CTX *ctx, BN_GENCB *cb);
""",
    """/**
 * @brief Test whether @p p is prime using the library's default primality checks.
 * @param p Candidate integer.
 * @param ctx Optional BN_CTX, or NULL to allocate internally.
 * @param cb Optional progress callback, or NULL.
 * @return 1 if probably prime, 0 if composite, or -1 on error.
 */
int BN_check_prime(const BIGNUM *p, BN_CTX *ctx, BN_GENCB *cb);
""",
    "BN_check_prime",
)

patch_one(
    "bn.h",
    """BN_MONT_CTX *BN_MONT_CTX_new(void);
""",
    """/**
 * @brief Allocate an empty Montgomery multiplication context.
 * @return New BN_MONT_CTX, or NULL on failure; free with BN_MONT_CTX_free().
 */
BN_MONT_CTX *BN_MONT_CTX_new(void);
""",
    "BN_MONT_CTX_new",
)

patch_one(
    "bn.h",
    """int BN_BLINDING_is_current_thread(BN_BLINDING *b);
""",
    """/**
 * @brief Report whether @p b is marked as owned by the calling thread.
 * @param b Blinding state to query.
 * @return 1 if owned by this thread, or 0 otherwise.
 */
int BN_BLINDING_is_current_thread(BN_BLINDING *b);
""",
    "BN_BLINDING_is_current_thread",
)

patch_one(
    "bn.h",
    """OSSL_DEPRECATEDIN_0_9_8
int BN_get_params(int which); /* 0, mul, 1 high, 2 low, 3 mont */
""",
    """/**
 * @brief Return a legacy BN library tuning parameter (deprecated no-op on modern OpenSSL).
 * @param which Selector historically meaning 0=mul, 1=high, 2=low, 3=mont.
 * @return Stored parameter value (typically 0 in current builds).
 */
OSSL_DEPRECATEDIN_0_9_8
int BN_get_params(int which); /* 0, mul, 1 high, 2 low, 3 mont */
""",
    "BN_get_params",
)

patch_one(
    "bn.h",
    """/* r = a mod p */
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);
""",
    """/**
 * @brief Reduce @p a modulo an irreducible GF(2^m) polynomial given as an int array: r = a mod p.
 * @param r Destination.
 * @param a Value to reduce.
 * @param p Descending exponent list of the irreducible, terminated by -1 (and ending in 0).
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);
""",
    "BN_GF2m_mod_arr",
)

patch_one(
    "bn.h",
    """int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
""",
    """/**
 * @brief Fast reduction of @p a modulo the NIST P-521 prime.
 * @param r Destination (may equal @p a).
 * @param a Value to reduce (non-negative).
 * @param p Must be the NIST P-521 prime (unused for the fast path but retained for API shape).
 * @param ctx BN_CTX scratch space (may be unused).
 * @return 1 on success, or 0 on error.
 */
int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
""",
    "BN_nist_mod_521",
)

# ----- conf.h -----

patch_both(
    "conf.h",
    """STACK_OF(CONF_VALUE) *NCONF_get_section(const CONF *conf,
    const char *section);
""",
    """/**
 * @brief Return all name/value pairs belonging to a CONF section.
 * @param conf Configuration to query.
 * @param section Section name ("" or NULL selects the default section).
 * @return Internal stack of CONF_VALUE, or NULL if missing/on error; do not free.
 */
STACK_OF(CONF_VALUE) *NCONF_get_section(const CONF *conf,
    const char *section);
""",
    "NCONF_get_section",
)

# ----- conftypes.h -----

patch_one(
    "conftypes.h",
    """struct conf_method_st {
    const char *name;
""",
    """struct conf_method_st {
    /** Short name identifying this CONF_METHOD implementation. */
    const char *name;
""",
    "conf_method_st::name",
)

# ----- core.h -----

patch_one(
    "core.h",
    """    /** Identifier selecting how @c ptr should be interpreted for this item. */
    unsigned int id;
    void *ptr;
};
""",
    """    /** Identifier selecting how @c ptr should be interpreted for this item. */
    unsigned int id;
    /** Pointer payload whose meaning depends on @c id (array terminator uses NULL). */
    void *ptr;
};
""",
    "ossl_item_st::ptr",
)

patch_one(
    "core.h",
    """    const OSSL_DISPATCH *implementation;
    const char *algorithm_description;
};
""",
    """    const OSSL_DISPATCH *implementation;
    /** Optional human-readable description of the algorithm implementation. */
    const char *algorithm_description;
};
""",
    "algorithm_description",
)

patch_one(
    "core.h",
    """    void *data; /* value being passed in or out */
    size_t data_size; /* data size */
    size_t return_size; /* returned content size */
};
""",
    """    void *data; /* value being passed in or out */
    /** Size in bytes of the buffer at @c data (or of the pointed-to value for PTR types). */
    size_t data_size;
    /** On output, size of the value written (or needed) when the parameter is used for results. */
    size_t return_size;
};
""",
    "data_size/return_size",
)

patch_one(
    "core.h",
    """typedef int(OSSL_provider_init_fn)(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx);
""",
    """/**
 * @brief Provider module entry-point signature invoked when OpenSSL loads the provider.
 * @param handle Core handle for this provider instance.
 * @param in Dispatch table of functions the core offers the provider.
 * @param out Receives the provider's dispatch table of exported functions.
 * @param provctx Receives an optional provider-side context pointer.
 * @return 1 on success, or 0 on failure.
 */
typedef int(OSSL_provider_init_fn)(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out,
    void **provctx);
""",
    "OSSL_provider_init_fn",
)

patch_one(
    "core.h",
    """typedef int(OSSL_CALLBACK)(const OSSL_PARAM params[], void *arg);
typedef int(OSSL_INOUT_CALLBACK)(const OSSL_PARAM in_params[],
    OSSL_PARAM out_params[], void *arg);
""",
    """/**
 * @brief Generic provider/libcrypto callback receiving an OSSL_PARAM array.
 * @param params Parameter array describing the event or request (may be empty).
 * @param arg Caller-supplied opaque pointer.
 * @return 1 on success, or 0 on failure.
 */
typedef int(OSSL_CALLBACK)(const OSSL_PARAM params[], void *arg);
/**
 * @brief Callback that both consumes input parameters and may populate output parameters.
 * @param in_params Input parameter array from the caller.
 * @param out_params Optional output parameter array to fill, or NULL.
 * @param arg Caller-supplied opaque pointer.
 * @return 1 on success, or 0 on failure.
 */
typedef int(OSSL_INOUT_CALLBACK)(const OSSL_PARAM in_params[],
    OSSL_PARAM out_params[], void *arg);
""",
    "OSSL_CALLBACK/OSSL_INOUT_CALLBACK",
)

patch_one(
    "core.h",
    """typedef int(OSSL_PASSPHRASE_CALLBACK)(char *pass, size_t pass_size,
    size_t *pass_len,
    const OSSL_PARAM params[], void *arg);
""",
    """/**
 * @brief Callback that obtains a passphrase, optionally guided by OSSL_PARAM descriptors.
 * @param pass Output buffer for the passphrase octets (not necessarily NUL-terminated).
 * @param pass_size Capacity of @p pass in bytes.
 * @param pass_len Receives the number of bytes written to @p pass.
 * @param params Optional parameters describing UI prompts / verification, or NULL.
 * @param arg Caller-supplied opaque pointer.
 * @return 1 on success, or 0 on failure / cancellation.
 */
typedef int(OSSL_PASSPHRASE_CALLBACK)(char *pass, size_t pass_size,
    size_t *pass_len,
    const OSSL_PARAM params[], void *arg);
""",
    "OSSL_PASSPHRASE_CALLBACK",
)

# ----- crypto.h -----

patch_both(
    "crypto.h",
    """size_t OPENSSL_strlcat(char *dst, const char *src, size_t siz);
""",
    """/**
 * @brief Append @p src onto @p dst with OpenSSL's bounded strlcat semantics.
 * @param dst Destination buffer already containing a NUL-terminated prefix.
 * @param src NUL-terminated string to append.
 * @param siz Total capacity of @p dst in bytes.
 * @return Length of the string OPENSSL_strlcat tried to create (strlen(initial dst)+strlen(src)).
 */
size_t OPENSSL_strlcat(char *dst, const char *src, size_t siz);
""",
    "OPENSSL_strlcat",
)

patch_both(
    "crypto.h",
    """/*
 * These functions return the values of OPENSSL_VERSION_MAJOR,
 * OPENSSL_VERSION_MINOR, OPENSSL_VERSION_PATCH, OPENSSL_VERSION_PRE_RELEASE
 * and OPENSSL_VERSION_BUILD_METADATA, respectively.
 */
unsigned int OPENSSL_version_major(void);
""",
    """/**
 * @brief Return the OpenSSL library major version (OPENSSL_VERSION_MAJOR).
 * @return Major version number from the build-time OPENSSL_VERSION_* macros.
 */
unsigned int OPENSSL_version_major(void);
""",
    "OPENSSL_version_major",
)

patch_both(
    "crypto.h",
    """int OPENSSL_issetugid(void);
""",
    """/**
 * @brief Report whether the process is running setuid/setgid (or otherwise "tainted").
 * @return Non-zero if privileged credentials differ from real ones (or platform equivalent), else 0.
 */
int OPENSSL_issetugid(void);
""",
    "OPENSSL_issetugid",
)

patch_both(
    "crypto.h",
    """typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
""",
    """/**
 * @brief Callback invoked when an ex_data slot is freed or the owning object is destroyed.
 * @param parent Object that owns the CRYPTO_EX_DATA.
 * @param ptr Pointer value previously stored in the slot.
 * @param ad Ex-data bag for @p parent.
 * @param idx Ex-data index being cleared.
 * @param argl Long argument registered with CRYPTO_get_ex_new_index().
 * @param argp Pointer argument registered with CRYPTO_get_ex_new_index().
 */
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
""",
    "CRYPTO_EX_free",
)

patch_both(
    "crypto.h",
    """/* No longer use an index. */
int CRYPTO_free_ex_index(int class_index, int idx);
""",
    """/**
 * @brief Release an application ex_data index previously allocated for a class (historically a no-op cleanup).
 * @param class_index CRYPTO_EX_INDEX_* identifying the object class.
 * @param idx Index returned by CRYPTO_get_ex_new_index().
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_free_ex_index(int class_index, int idx);
""",
    "CRYPTO_free_ex_index",
)

patch_both(
    "crypto.h",
    """typedef void *(*CRYPTO_realloc_fn)(void *addr, size_t num, const char *file,
    int line);
""",
    """/**
 * @brief Reallocator callback type used by CRYPTO_set_mem_functions().
 * @param addr Existing allocation to resize, or NULL to allocate.
 * @param num Desired new size in bytes.
 * @param file Source file recorded with the (re)allocation.
 * @param line Source line recorded with the (re)allocation.
 * @return Resized memory, or NULL on failure.
 */
typedef void *(*CRYPTO_realloc_fn)(void *addr, size_t num, const char *file,
    int line);
""",
    "CRYPTO_realloc_fn",
)

patch_both(
    "crypto.h",
    """OSSL_CRYPTO_ALLOC void *CRYPTO_malloc(size_t num, const char *file, int line);
""",
    """/**
 * @brief Allocate @p num bytes using the installed CRYPTO malloc callback.
 * @param num Number of bytes to allocate.
 * @param file Source file for tracking (usually OPENSSL_FILE).
 * @param line Source line for tracking (usually OPENSSL_LINE).
 * @return Newly allocated memory, or NULL on failure.
 */
OSSL_CRYPTO_ALLOC void *CRYPTO_malloc(size_t num, const char *file, int line);
""",
    "CRYPTO_malloc",
)

patch_both(
    "crypto.h",
    """OSSL_CRYPTO_ALLOC void *CRYPTO_secure_malloc(size_t num, const char *file, int line);
""",
    """/**
 * @brief Allocate @p num bytes from the secure heap (after CRYPTO_secure_malloc_init()).
 * @param num Number of bytes to allocate.
 * @param file Source file for tracking (usually OPENSSL_FILE).
 * @param line Source line for tracking (usually OPENSSL_LINE).
 * @return Secure allocation, or NULL on failure.
 */
OSSL_CRYPTO_ALLOC void *CRYPTO_secure_malloc(size_t num, const char *file, int line);
""",
    "CRYPTO_secure_malloc",
)

patch_both(
    "crypto.h",
    """int OPENSSL_gmtime_diff(int *pday, int *psec,
    const struct tm *from, const struct tm *to);
""",
    """/**
 * @brief Compute the day/second difference between two broken-down UTC times.
 * @param pday Receives the whole-day difference (@p to - @p from).
 * @param psec Receives the remaining second difference after whole days are removed.
 * @param from Starting time (UTC).
 * @param to Ending time (UTC).
 * @return 1 on success, or 0 on failure.
 */
int OPENSSL_gmtime_diff(int *pday, int *psec,
    const struct tm *from, const struct tm *to);
""",
    "OPENSSL_gmtime_diff",
)

patch_both(
    "crypto.h",
    """typedef LONG CRYPTO_ONCE;
#define CRYPTO_ONCE_STATIC_INIT 0
""",
    """/**
 * @brief Once-control type used with CRYPTO_THREAD_run_once() on Windows builds.
 */
typedef LONG CRYPTO_ONCE;
#define CRYPTO_ONCE_STATIC_INIT 0
""",
    "CRYPTO_ONCE_win",
)

patch_both(
    "crypto.h",
    """typedef pthread_once_t CRYPTO_ONCE;
""",
    """/**
 * @brief Once-control type used with CRYPTO_THREAD_run_once() on POSIX builds.
 */
typedef pthread_once_t CRYPTO_ONCE;
""",
    "CRYPTO_ONCE_pthread",
)

patch_both(
    "crypto.h",
    """#if !defined(CRYPTO_ONCE_STATIC_INIT)
typedef unsigned int CRYPTO_ONCE;
""",
    """#if !defined(CRYPTO_ONCE_STATIC_INIT)
/**
 * @brief Once-control type used with CRYPTO_THREAD_run_once() when threads are disabled.
 */
typedef unsigned int CRYPTO_ONCE;
""",
    "CRYPTO_ONCE_nothread",
)

patch_both(
    "crypto.h",
    """void OSSL_sleep(uint64_t millis);
""",
    """/**
 * @brief Sleep the calling thread for approximately @p millis milliseconds.
 * @param millis Duration to sleep; platforms may round up to their timer resolution.
 */
void OSSL_sleep(uint64_t millis);
""",
    "OSSL_sleep",
)

# ----- cryptoerr_legacy.h -----

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_BIO_strings(void);
""",
    """/**
 * @brief Load BIO library error strings into the error queue (deprecated no-op in OpenSSL 3+).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_BIO_strings(void);
""",
    "ERR_load_BIO_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_CONF_strings(void);
""",
    """/**
 * @brief Load CONF library error strings into the error queue (deprecated no-op in OpenSSL 3+).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_CONF_strings(void);
""",
    "ERR_load_CONF_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_PEM_strings(void);
OSSL_DEPRECATEDIN_3_0 int ERR_load_PKCS12_strings(void);
""",
    """/**
 * @brief Load PEM library error strings into the error queue (deprecated no-op in OpenSSL 3+).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_PEM_strings(void);
/**
 * @brief Load PKCS#12 library error strings into the error queue (deprecated no-op in OpenSSL 3+).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_PKCS12_strings(void);
""",
    "ERR_load_PEM/PKCS12_strings",
)

# ----- dh.h -----

patch_one(
    "dh.h",
    """OSSL_DEPRECATEDIN_3_0 long DH_get_length(const DH *dh);
""",
    """/**
 * @brief Return the optional private-value length hint stored on a DH object (deprecated).
 * @param dh DH object to query.
 * @return Preferred secret-exponent length in bits, or 0 if the default should be used.
 */
OSSL_DEPRECATEDIN_3_0 long DH_get_length(const DH *dh);
""",
    "DH_get_length",
)

# ----- dsa.h -----

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_p(const DSA *d);
""",
    """/**
 * @brief Return the DSA prime modulus p without duplicating it (deprecated).
 * @param d DSA object to query.
 * @return Internal BIGNUM pointer for p, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_p(const DSA *d);
""",
    "DSA_get0_p",
)

# ----- err.h -----

patch_both(
    "err.h",
    """static ossl_unused ossl_inline int ERR_FATAL_ERROR(unsigned long errcode)
{
    return (ERR_GET_RFLAGS(errcode) & ERR_RFLAG_FATAL) != 0;
}
""",
    """/**
 * @brief Return whether a packed error code is marked fatal.
 * @param errcode Error code as returned by ERR_get_error() or ERR_peek_error().
 * @return Non-zero if ERR_RFLAG_FATAL is set on @p errcode, otherwise 0.
 */
static ossl_unused ossl_inline int ERR_FATAL_ERROR(unsigned long errcode)
{
    return (ERR_GET_RFLAGS(errcode) & ERR_RFLAG_FATAL) != 0;
}
""",
    "ERR_FATAL_ERROR",
)

# ----- evp.h -----

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2));
""",
    """/**
 * @brief Set the ctrl callback on a custom EVP_MD method (deprecated).
 * @param md Digest method being constructed.
 * @param ctrl Callback handling EVP_MD_CTRL_* commands for digest contexts.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0
int EVP_MD_meth_set_ctrl(EVP_MD *md, int (*ctrl)(EVP_MD_CTX *ctx, int cmd, int p1, void *p2));
""",
    "EVP_MD_meth_set_ctrl",
)

patch_one(
    "evp.h",
    """int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
""",
    """/**
 * @brief Send a cipher-specific control request to an EVP_CIPHER_CTX.
 * @param ctx Cipher context to control.
 * @param type EVP_CTRL_* command code.
 * @param arg Integer argument for @p type.
 * @param ptr Pointer argument for @p type, or NULL.
 * @return 1 on success, <=0 on failure (command-specific).
 */
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);
""",
    "EVP_CIPHER_CTX_ctrl",
)

patch_one(
    "evp.h",
    """int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
""",
    """/**
 * @brief Derive a PBE key and IV and initialize @p ctx for encryption/decryption (PKCS #5 v1.5).
 * @param ctx Cipher context to initialize.
 * @param pass Password octets (may be NULL if @p passlen is 0).
 * @param passlen Password length in bytes, or -1 to use strlen(@p pass).
 */
int PKCS5_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
""",
    "PKCS5_PBE_keyivgen",
)

# Fix PKCS5 - need full prototype. Re-read and patch properly if truncated.
# Will verify after run.

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst,
""",
    """/**
 * @brief Copy all callbacks and flags from one EVP_PKEY_METHOD to another (deprecated).
 * @param dst Destination method (existing object overwritten).
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_copy(EVP_PKEY_METHOD *dst,
""",
    "EVP_PKEY_meth_copy",
)

patch_one(
    "evp.h",
    """OSSL_PROVIDER *EVP_KEM_get0_provider(const EVP_KEM *wrap);
""",
    """/**
 * @brief Return the provider that implemented a fetched EVP_KEM algorithm.
 * @param wrap KEM method from EVP_KEM_fetch().
 * @return Provider handle, or NULL if unavailable; do not free.
 */
OSSL_PROVIDER *EVP_KEM_get0_provider(const EVP_KEM *wrap);
""",
    "EVP_KEM_get0_provider",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_param_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));
""",
    """/**
 * @brief Set the domain-parameter validation callback on an EVP_PKEY_METHOD (deprecated).
 * @param pmeth Method being constructed.
 * @param check Callback that returns 1 if @p pkey parameters are valid, or 0 otherwise.
 */
OSSL_DEPRECATEDIN_3_0 void EVP_PKEY_meth_set_param_check(EVP_PKEY_METHOD *pmeth, int (*check)(EVP_PKEY *pkey));
""",
    "EVP_PKEY_meth_set_param_check",
)

# ----- kdf.h -----

patch_one(
    "kdf.h",
    """void EVP_KDF_free(EVP_KDF *kdf);
EVP_KDF *EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);
""",
    """/**
 * @brief Release a reference to a fetched EVP_KDF method.
 * @param kdf Method from EVP_KDF_fetch(), or NULL.
 */
void EVP_KDF_free(EVP_KDF *kdf);
/**
 * @brief Fetch a key-derivation algorithm implementation from providers.
 * @param libctx Library context, or NULL for the default.
 * @param algorithm KDF name such as "HKDF" or "PBKDF2".
 * @param properties Optional provider property query, or NULL.
 * @return Fetched EVP_KDF with refcount 1, or NULL on error; free with EVP_KDF_free().
 */
EVP_KDF *EVP_KDF_fetch(OSSL_LIB_CTX *libctx, const char *algorithm,
    const char *properties);
""",
    "EVP_KDF_free/fetch",
)

patch_one(
    "kdf.h",
    """EVP_KDF_CTX *EVP_KDF_CTX_new(EVP_KDF *kdf);
""",
    """/**
 * @brief Allocate a key-derivation context for a fetched EVP_KDF.
 * @param kdf Algorithm from EVP_KDF_fetch() (not consumed; may be freed after).
 * @return New context, or NULL on failure; free with EVP_KDF_CTX_free().
 */
EVP_KDF_CTX *EVP_KDF_CTX_new(EVP_KDF *kdf);
""",
    "EVP_KDF_CTX_new",
)

patch_one(
    "kdf.h",
    """int EVP_KDF_is_a(const EVP_KDF *kdf, const char *name);
""",
    """/**
 * @brief Test whether an EVP_KDF implementation is known by @p name.
 * @param kdf Fetched KDF method.
 * @param name Algorithm name or synonym to match.
 * @return 1 if @p name identifies @p kdf, or 0 otherwise.
 */
int EVP_KDF_is_a(const EVP_KDF *kdf, const char *name);
""",
    "EVP_KDF_is_a",
)

patch_one(
    "kdf.h",
    """const OSSL_PROVIDER *EVP_KDF_get0_provider(const EVP_KDF *kdf);
const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx);
""",
    """/**
 * @brief Return the provider that implemented a fetched EVP_KDF.
 * @param kdf KDF method to query.
 * @return Provider handle, or NULL; do not free.
 */
const OSSL_PROVIDER *EVP_KDF_get0_provider(const EVP_KDF *kdf);
/**
 * @brief Return the EVP_KDF method associated with a derivation context.
 * @param ctx KDF context from EVP_KDF_CTX_new().
 * @return Borrowed EVP_KDF pointer; do not free.
 */
const EVP_KDF *EVP_KDF_CTX_kdf(EVP_KDF_CTX *ctx);
""",
    "EVP_KDF_get0_provider/CTX_kdf",
)

patch_one(
    "kdf.h",
    """int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
    const OSSL_PARAM params[]);
""",
    """/**
 * @brief Derive keying material into @p key using the parameters bound to @p ctx.
 * @param ctx Initialized KDF context.
 * @param key Output buffer for the derived key.
 * @param keylen Number of bytes to write to @p key.
 * @param params Optional additional OSSL_PARAM array, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KDF_derive(EVP_KDF_CTX *ctx, unsigned char *key, size_t keylen,
    const OSSL_PARAM params[]);
""",
    "EVP_KDF_derive",
)

patch_one(
    "kdf.h",
    """int EVP_KDF_CTX_get_params(EVP_KDF_CTX *ctx, OSSL_PARAM params[]);
""",
    """/**
 * @brief Retrieve gettable parameters from an EVP_KDF_CTX.
 * @param ctx KDF context to query.
 * @param params Parameter array describing the values to fetch.
 * @return 1 on success, or 0 on failure.
 */
int EVP_KDF_CTX_get_params(EVP_KDF_CTX *ctx, OSSL_PARAM params[]);
""",
    "EVP_KDF_CTX_get_params",
)

patch_one(
    "kdf.h",
    """const OSSL_PARAM *EVP_KDF_gettable_params(const EVP_KDF *kdf);
""",
    """/**
 * @brief Describe the parameters that can be read from an EVP_KDF via EVP_KDF_get_params().
 * @param kdf KDF method to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_construct_end(); do not free.
 */
const OSSL_PARAM *EVP_KDF_gettable_params(const EVP_KDF *kdf);
""",
    "EVP_KDF_gettable_params",
)

patch_one(
    "kdf.h",
    """const OSSL_PARAM *EVP_KDF_settable_ctx_params(const EVP_KDF *kdf);
""",
    """/**
 * @brief Describe context parameters that can be set before deriving with @p kdf.
 * @param kdf KDF method to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_construct_end(); do not free.
 */
const OSSL_PARAM *EVP_KDF_settable_ctx_params(const EVP_KDF *kdf);
""",
    "EVP_KDF_settable_ctx_params",
)

patch_one(
    "kdf.h",
    """const OSSL_PARAM *EVP_KDF_CTX_settable_params(EVP_KDF_CTX *ctx);
""",
    """/**
 * @brief Describe parameters currently settable on an EVP_KDF_CTX instance.
 * @param ctx KDF context to query.
 * @return Array of OSSL_PARAM descriptors terminated by OSSL_PARAM_construct_end(); do not free.
 */
const OSSL_PARAM *EVP_KDF_CTX_settable_params(EVP_KDF_CTX *ctx);
""",
    "EVP_KDF_CTX_settable_params",
)

patch_one(
    "kdf.h",
    """int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *ctx,
""",
    """/**
 * @brief Append octets to the HKDF info/context parameter on a PKEY HKDF context.
 * @param ctx Key derivation context configured for HKDF.
 */
int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX *ctx,
""",
    "EVP_PKEY_CTX_add1_hkdf_info",
)

# ----- params.h -----

patch_one(
    "params.h",
    """OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key);
const OSSL_PARAM *OSSL_PARAM_locate_const(const OSSL_PARAM *p, const char *key);
""",
    """OSSL_PARAM *OSSL_PARAM_locate(OSSL_PARAM *p, const char *key);
/**
 * @brief Find the first OSSL_PARAM in a const array whose key matches @p key.
 * @param p Parameter array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @param key Parameter name to search for.
 * @return Pointer to the matching element, or NULL if not found.
 */
const OSSL_PARAM *OSSL_PARAM_locate_const(const OSSL_PARAM *p, const char *key);
""",
    "OSSL_PARAM_locate_const",
)

patch_one(
    "params.h",
    """OSSL_PARAM *OSSL_PARAM_dup(const OSSL_PARAM *p);
OSSL_PARAM *OSSL_PARAM_merge(const OSSL_PARAM *p1, const OSSL_PARAM *p2);
""",
    """OSSL_PARAM *OSSL_PARAM_dup(const OSSL_PARAM *p);
/**
 * @brief Merge two OSSL_PARAM arrays, with @p p2 overriding duplicate keys from @p p1.
 * @param p1 First array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @param p2 Second array terminated by OSSL_PARAM_construct_end(), or NULL.
 * @return Newly allocated merged array freed with OSSL_PARAM_free(), or NULL on failure.
 */
OSSL_PARAM *OSSL_PARAM_merge(const OSSL_PARAM *p1, const OSSL_PARAM *p2);
""",
    "OSSL_PARAM_merge",
)

# ----- rc2.h -----

patch_one(
    "rc2.h",
    """typedef struct rc2_key_st {
    RC2_INT data[64];
} RC2_KEY;
""",
    """/**
 * @brief Expanded RC2 key schedule used by the deprecated low-level RC2_* encryptors.
 */
typedef struct rc2_key_st {
    /** 64-word expanded key table produced by RC2_set_key(). */
    RC2_INT data[64];
} RC2_KEY;
""",
    "RC2_KEY",
)

patch_one(
    "rc2.h",
    """OSSL_DEPRECATEDIN_3_0 void RC2_set_key(RC2_KEY *key, int len,
    const unsigned char *data, int bits);
OSSL_DEPRECATEDIN_3_0 void RC2_ecb_encrypt(const unsigned char *in,
    unsigned char *out, RC2_KEY *key,
    int enc);
OSSL_DEPRECATEDIN_3_0 void RC2_encrypt(unsigned long *data, RC2_KEY *key);
OSSL_DEPRECATEDIN_3_0 void RC2_decrypt(unsigned long *data, RC2_KEY *key);
OSSL_DEPRECATEDIN_3_0 void RC2_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *ks, unsigned char *iv,
    int enc);
OSSL_DEPRECATEDIN_3_0 void RC2_cfb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *schedule,
    unsigned char *ivec,
    int *num, int enc);
OSSL_DEPRECATEDIN_3_0 void RC2_ofb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *schedule,
    unsigned char *ivec,
    int *num);
""",
    """/**
 * @brief Expand a raw RC2 key into an RC2_KEY schedule (deprecated).
 * @param key Destination schedule.
 * @param len Number of key bytes at @p data.
 * @param data Raw key octets.
 * @param bits Effective key bits for RC2 (typically 8..1024; 0 selects a default of 1024).
 */
OSSL_DEPRECATEDIN_3_0 void RC2_set_key(RC2_KEY *key, int len,
    const unsigned char *data, int bits);
/**
 * @brief Encrypt or decrypt one RC2 block in ECB mode (deprecated).
 * @param in 8-byte input block.
 * @param out 8-byte output block (may equal @p in).
 * @param key Expanded key from RC2_set_key().
 * @param enc RC2_ENCRYPT to encrypt, or RC2_DECRYPT to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void RC2_ecb_encrypt(const unsigned char *in,
    unsigned char *out, RC2_KEY *key,
    int enc);
/**
 * @brief Encrypt one RC2 block held as two host-endian longs (deprecated).
 * @param data Two-element array holding the 64-bit block.
 * @param key Expanded key from RC2_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void RC2_encrypt(unsigned long *data, RC2_KEY *key);
/**
 * @brief Decrypt one RC2 block held as two host-endian longs (deprecated).
 * @param data Two-element array holding the 64-bit block.
 * @param key Expanded key from RC2_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void RC2_decrypt(unsigned long *data, RC2_KEY *key);
/**
 * @brief Encrypt or decrypt with RC2 in CBC mode (deprecated).
 * @param in Input bytes of length @p length.
 * @param out Output buffer of at least @p length bytes.
 * @param length Number of bytes to process (should be a multiple of RC2_BLOCK).
 * @param ks Expanded key from RC2_set_key().
 * @param iv 8-byte IV; updated to the last ciphertext block.
 * @param enc RC2_ENCRYPT or RC2_DECRYPT.
 */
OSSL_DEPRECATEDIN_3_0 void RC2_cbc_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *ks, unsigned char *iv,
    int enc);
/**
 * @brief Encrypt or decrypt with RC2 in 64-bit CFB mode (deprecated).
 * @param in Input bytes.
 * @param out Output buffer of at least @p length bytes.
 * @param length Number of bytes to process.
 * @param schedule Expanded key from RC2_set_key().
 * @param ivec 8-byte IV, updated in place.
 * @param num Offset into the CFB stream (0..7), updated in place.
 * @param enc RC2_ENCRYPT or RC2_DECRYPT.
 */
OSSL_DEPRECATEDIN_3_0 void RC2_cfb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *schedule,
    unsigned char *ivec,
    int *num, int enc);
/**
 * @brief Encrypt or decrypt with RC2 in 64-bit OFB mode (deprecated).
 * @param in Input bytes.
 * @param out Output buffer of at least @p length bytes.
 * @param length Number of bytes to process.
 * @param schedule Expanded key from RC2_set_key().
 * @param ivec 8-byte IV, updated in place.
 * @param num Offset into the OFB keystream (0..7), updated in place.
 */
OSSL_DEPRECATEDIN_3_0 void RC2_ofb64_encrypt(const unsigned char *in,
    unsigned char *out, long length,
    RC2_KEY *schedule,
    unsigned char *ivec,
    int *num);
""",
    "RC2_* encryptors",
)

# ----- rsa.h -----

patch_one(
    "rsa.h",
    """int EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(EVP_PKEY_CTX *ctx,
    const char *mdname,
    const char *mdprops);
""",
    """/**
 * @brief Set the message digest used when generating an RSA-PSS key via an EVP_PKEY_CTX.
 * @param ctx Keygen context for RSA-PSS.
 * @param mdname Digest name such as "SHA256".
 * @param mdprops Optional property query for fetching the digest, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int EVP_PKEY_CTX_set_rsa_pss_keygen_md_name(EVP_PKEY_CTX *ctx,
    const char *mdname,
    const char *mdprops);
""",
    "EVP_PKEY_CTX_set_rsa_pss_keygen_md_name",
)

# ----- ssl.h -----

patch_both(
    "ssl.h",
    """void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cb)(SSL *ssl, void *arg),
    void *arg);
""",
    """/**
 * @brief Install a certificate-selection callback invoked during handshake certificate setup.
 * @param c SSL_CTX that owns the callback.
 * @param cb Callback that should install certs/keys on @p ssl and return 1 on success, 0 to defer, or <0 on error.
 * @param arg Opaque pointer passed to @p cb.
 */
void SSL_CTX_set_cert_cb(SSL_CTX *c, int (*cb)(SSL *ssl, void *arg),
    void *arg);
""",
    "SSL_CTX_set_cert_cb",
)

patch_both(
    "ssl.h",
    """OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_2_client_method(void);
""",
    """/**
 * @brief Return the SSL_METHOD for a TLS 1.2 client-only stack (deprecated).
 * @return Internal method pointer; prefer TLS_client_method() with version bounds.
 */
OSSL_DEPRECATEDIN_1_1_0 __owur const SSL_METHOD *TLSv1_2_client_method(void);
""",
    "TLSv1_2_client_method",
)

patch_both(
    "ssl.h",
    """void (*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl, int type,
    int val);
""",
    """/**
 * @brief Return the info callback previously set on an SSL with SSL_set_info_callback().
 * @param ssl SSL object to query.
 * @return Callback pointer, or NULL if unset.
 */
void (*SSL_get_info_callback(const SSL *ssl))(const SSL *ssl, int type,
    int val);
""",
    "SSL_get_info_callback",
)

patch_both(
    "ssl.h",
    """__owur int SSL_set_session_ticket_ext_cb(SSL *s,
    tls_session_ticket_ext_cb_fn cb,
    void *arg);
""",
    """/**
 * @brief Install a callback that processes the TLS session-ticket extension on an SSL.
 * @param s SSL connection.
 * @param cb Callback invoked with ticket extension data, or NULL to clear.
 * @param arg Opaque pointer passed to @p cb.
 * @return 1 on success, or 0 on failure.
 */
__owur int SSL_set_session_ticket_ext_cb(SSL *s,
    tls_session_ticket_ext_cb_fn cb,
    void *arg);
""",
    "SSL_set_session_ticket_ext_cb",
)

# ----- stack.h -----

patch_one(
    "stack.h",
    """typedef void *(*OPENSSL_sk_copyfunc)(const void *);
""",
    """/**
 * @brief Deep-copy callback used by OPENSSL_sk_deep_copy() to duplicate one stack element.
 * @param p Element to copy.
 * @return Newly allocated copy of @p p, or NULL on failure.
 */
typedef void *(*OPENSSL_sk_copyfunc)(const void *);
""",
    "OPENSSL_sk_copyfunc",
)

patch_one(
    "stack.h",
    """void *OPENSSL_sk_value(const OPENSSL_STACK *, int);
""",
    """/**
 * @brief Return the element at index @p idx in a stack (no bounds checking beyond returning NULL).
 * @param st Stack to query.
 * @param idx Zero-based index.
 * @return Element pointer, or NULL if @p idx is out of range.
 */
void *OPENSSL_sk_value(const OPENSSL_STACK *st, int idx);
""",
    "OPENSSL_sk_value",
)

patch_one(
    "stack.h",
    """OPENSSL_STACK *OPENSSL_sk_new(OPENSSL_sk_compfunc cmp);
OPENSSL_STACK *OPENSSL_sk_new_null(void);
""",
    """/**
 * @brief Allocate an empty stack with an optional comparison function.
 * @param cmp Comparison callback for OPENSSL_sk_find()/sort, or NULL.
 * @return New stack, or NULL on failure; free with OPENSSL_sk_free().
 */
OPENSSL_STACK *OPENSSL_sk_new(OPENSSL_sk_compfunc cmp);
/**
 * @brief Allocate an empty stack with no comparison function.
 * @return New stack, or NULL on failure; free with OPENSSL_sk_free().
 */
OPENSSL_STACK *OPENSSL_sk_new_null(void);
""",
    "OPENSSL_sk_new/new_null",
)

patch_one(
    "stack.h",
    """int OPENSSL_sk_reserve(OPENSSL_STACK *st, int n);
void OPENSSL_sk_free(OPENSSL_STACK *);
void OPENSSL_sk_pop_free(OPENSSL_STACK *st, void (*func)(void *));
OPENSSL_STACK *OPENSSL_sk_deep_copy(const OPENSSL_STACK *,
    OPENSSL_sk_copyfunc c,
    OPENSSL_sk_freefunc f);
""",
    """/**
 * @brief Ensure a stack's internal array can hold at least @p n elements without reallocating.
 * @param st Stack to resize.
 * @param n Desired capacity.
 * @return 1 on success, or 0 on allocation failure.
 */
int OPENSSL_sk_reserve(OPENSSL_STACK *st, int n);
/**
 * @brief Free a stack structure without freeing its elements.
 * @param st Stack to free, or NULL.
 */
void OPENSSL_sk_free(OPENSSL_STACK *st);
/**
 * @brief Pop and free every element, then free the stack.
 * @param st Stack to destroy, or NULL.
 * @param func Destructor applied to each element (must accept the element pointer).
 */
void OPENSSL_sk_pop_free(OPENSSL_STACK *st, void (*func)(void *));
/**
 * @brief Deep-copy a stack by duplicating each element with @p c.
 * @param st Source stack.
 * @param c Element copy callback.
 * @param f Element free callback used to clean up on failure (and by callers later).
 * @return Newly allocated stack, or NULL on failure.
 */
OPENSSL_STACK *OPENSSL_sk_deep_copy(const OPENSSL_STACK *st,
    OPENSSL_sk_copyfunc c,
    OPENSSL_sk_freefunc f);
""",
    "OPENSSL_sk_reserve/free/pop_free/deep_copy",
)

patch_one(
    "stack.h",
    """int OPENSSL_sk_insert(OPENSSL_STACK *sk, const void *data, int where);
""",
    """/**
 * @brief Insert @p data before index @p where (appending if @p where is out of range).
 * @param sk Stack to modify.
 * @param data Element pointer to store (not copied).
 * @param where Insertion index.
 * @return New number of elements, or 0 on failure.
 */
int OPENSSL_sk_insert(OPENSSL_STACK *sk, const void *data, int where);
""",
    "OPENSSL_sk_insert",
)

patch_one(
    "stack.h",
    """void *OPENSSL_sk_delete_ptr(OPENSSL_STACK *st, const void *p);
""",
    """/**
 * @brief Delete the first stack element whose pointer equals @p p.
 * @param st Stack to modify.
 * @param p Element pointer to remove.
 * @return The removed pointer, or NULL if not found.
 */
void *OPENSSL_sk_delete_ptr(OPENSSL_STACK *st, const void *p);
""",
    "OPENSSL_sk_delete_ptr",
)

patch_one(
    "stack.h",
    """int OPENSSL_sk_find_ex(OPENSSL_STACK *st, const void *data);
""",
    """/**
 * @brief Search for @p data; if absent, return the insertion index of the nearest greater element.
 * @param st Stack to search (sorted when a comparison function is set).
 * @param data Key passed to the comparison function.
 * @return Matching index, or a negative encoding of the insertion point when not found.
 */
int OPENSSL_sk_find_ex(OPENSSL_STACK *st, const void *data);
""",
    "OPENSSL_sk_find_ex",
)

patch_one(
    "stack.h",
    """void *OPENSSL_sk_pop(OPENSSL_STACK *st);
void OPENSSL_sk_zero(OPENSSL_STACK *st);
""",
    """/**
 * @brief Remove and return the last element of a stack.
 * @param st Stack to modify.
 * @return Former top element, or NULL if @p st is empty/NULL.
 */
void *OPENSSL_sk_pop(OPENSSL_STACK *st);
/**
 * @brief Clear a stack to zero elements without freeing the element pointers.
 * @param st Stack to reset, or NULL.
 */
void OPENSSL_sk_zero(OPENSSL_STACK *st);
""",
    "OPENSSL_sk_pop/zero",
)

patch_one(
    "stack.h",
    """int OPENSSL_sk_is_sorted(const OPENSSL_STACK *st);
""",
    """/**
 * @brief Report whether a stack is marked sorted under its comparison function.
 * @param st Stack to query.
 * @return 1 if sorted (or empty/no cmp), or 0 otherwise.
 */
int OPENSSL_sk_is_sorted(const OPENSSL_STACK *st);
""",
    "OPENSSL_sk_is_sorted",
)

# ----- types.h -----

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_PRINTABLESTRING;
""",
    """/** @brief ASN.1 PrintableString stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_PRINTABLESTRING;
""",
    "ASN1_PRINTABLESTRING",
)

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_T61STRING;
""",
    """/** @brief ASN.1 TeletexString/T61String stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_T61STRING;
""",
    "ASN1_T61STRING",
)

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
""",
    """/** @brief ASN.1 UniversalString stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_UNIVERSALSTRING;
""",
    "ASN1_UNIVERSALSTRING",
)

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_UTCTIME;
typedef struct asn1_string_st ASN1_TIME;
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
""",
    """/** @brief ASN.1 UTCTime value stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_UTCTIME;
/** @brief ASN.1 Time choice (UTCTime or GeneralizedTime) stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_TIME;
/** @brief ASN.1 GeneralizedTime value stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_GENERALIZEDTIME;
""",
    "ASN1_UTCTIME/TIME/GENERALIZEDTIME",
)

patch_one(
    "types.h",
    """typedef struct asn1_string_st ASN1_UTF8STRING;
""",
    """/** @brief ASN.1 UTF8String stored as an asn1_string_st. */
typedef struct asn1_string_st ASN1_UTF8STRING;
""",
    "ASN1_UTF8STRING",
)

patch_one(
    "types.h",
    """typedef int ASN1_BOOLEAN;
typedef int ASN1_NULL;
""",
    """/** @brief ASN.1 BOOLEAN represented as an int (-1 unset, 0 FALSE, 0xff TRUE). */
typedef int ASN1_BOOLEAN;
/** @brief ASN.1 NULL placeholder type (no payload). */
typedef int ASN1_NULL;
""",
    "ASN1_BOOLEAN/NULL",
)

patch_one(
    "types.h",
    """typedef struct bio_st BIO;
""",
    """/**
 * @brief Opaque Basic I/O abstraction (filters and source/sink streams).
 */
typedef struct bio_st BIO;
""",
    "BIO",
)

patch_one(
    "types.h",
    """typedef struct bn_mont_ctx_st BN_MONT_CTX;
""",
    """/**
 * @brief Montgomery multiplication context for a fixed odd modulus (BN_MONT_CTX_*).
 */
typedef struct bn_mont_ctx_st BN_MONT_CTX;
""",
    "BN_MONT_CTX",
)

patch_one(
    "types.h",
    """typedef struct bn_gencb_st BN_GENCB;
""",
    """/**
 * @brief Progress-callback object used by prime generation and similar BN routines.
 */
typedef struct bn_gencb_st BN_GENCB;
""",
    "BN_GENCB",
)

patch_one(
    "types.h",
    """STACK_OF(BIGNUM);
STACK_OF(BIGNUM_const);
""",
    """/** @brief STACK_OF container for mutable BIGNUM pointers. */
STACK_OF(BIGNUM);
/** @brief STACK_OF container for const BIGNUM pointers. */
STACK_OF(BIGNUM_const);
""",
    "STACK_OF(BIGNUM*)",
)

patch_one(
    "types.h",
    """typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_st EVP_MD;
""",
    """/**
 * @brief Opaque symmetric-cipher operation context (EVP_Encrypt*/EVP_Decrypt*/EVP_Cipher*).
 */
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
/**
 * @brief Opaque message-digest method (algorithm implementation) used with EVP_MD_CTX.
 */
typedef struct evp_md_st EVP_MD;
""",
    "EVP_CIPHER_CTX/EVP_MD",
)

patch_one(
    "types.h",
    """typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
""",
    """/**
 * @brief Opaque legacy method table implementing an EVP_PKEY algorithm (deprecated in 3.0).
 */
typedef struct evp_pkey_method_st EVP_PKEY_METHOD;
""",
    "EVP_PKEY_METHOD",
)

patch_one(
    "types.h",
    """typedef struct evp_kdf_st EVP_KDF;
""",
    """/**
 * @brief Opaque key-derivation function method returned by EVP_KDF_fetch().
 */
typedef struct evp_kdf_st EVP_KDF;
""",
    "EVP_KDF",
)

patch_one(
    "types.h",
    """typedef struct evp_rand_ctx_st EVP_RAND_CTX;
""",
    """/**
 * @brief Opaque RAND operation context created from an EVP_RAND method.
 */
typedef struct evp_rand_ctx_st EVP_RAND_CTX;
""",
    "EVP_RAND_CTX",
)

patch_one(
    "types.h",
    """typedef struct evp_keyexch_st EVP_KEYEXCH;
""",
    """/**
 * @brief Opaque key-exchange algorithm method (EVP_KEYEXCH_fetch).
 */
typedef struct evp_keyexch_st EVP_KEYEXCH;
""",
    "EVP_KEYEXCH",
)

patch_one(
    "types.h",
    """typedef struct evp_signature_st EVP_SIGNATURE;
""",
    """/**
 * @brief Opaque signature algorithm method (EVP_SIGNATURE_fetch).
 */
typedef struct evp_signature_st EVP_SIGNATURE;
""",
    "EVP_SIGNATURE",
)

patch_one(
    "types.h",
    """typedef struct evp_asym_cipher_st EVP_ASYM_CIPHER;
""",
    """/**
 * @brief Opaque asymmetric cipher method (EVP_ASYM_CIPHER_fetch).
 */
typedef struct evp_asym_cipher_st EVP_ASYM_CIPHER;
""",
    "EVP_ASYM_CIPHER",
)

patch_one(
    "types.h",
    """typedef struct dh_st DH;
""",
    """/**
 * @brief Opaque Diffie-Hellman key/parameters object (deprecated low-level DH_* API).
 */
typedef struct dh_st DH;
""",
    "DH",
)

patch_one(
    "types.h",
    """typedef struct dsa_st DSA;
typedef struct dsa_method DSA_METHOD;
""",
    """/**
 * @brief Opaque DSA key/parameters object (deprecated low-level DSA_* API).
 */
typedef struct dsa_st DSA;
/**
 * @brief Opaque DSA_METHOD table of low-level DSA callbacks (deprecated).
 */
typedef struct dsa_method DSA_METHOD;
""",
    "DSA/DSA_METHOD",
)

patch_one(
    "types.h",
    """typedef struct X509_name_st X509_NAME;
typedef struct X509_pubkey_st X509_PUBKEY;
""",
    """/**
 * @brief Opaque X.509 distinguished name (SEQUENCE OF RelativeDistinguishedName).
 */
typedef struct X509_name_st X509_NAME;
/**
 * @brief Opaque SubjectPublicKeyInfo container (algorithm + public key BIT STRING).
 */
typedef struct X509_pubkey_st X509_PUBKEY;
""",
    "X509_NAME/X509_PUBKEY",
)

patch_one(
    "types.h",
    """typedef struct x509_store_ctx_st X509_STORE_CTX;
""",
    """/**
 * @brief Opaque certificate-verification context (one chain validation attempt).
 */
typedef struct x509_store_ctx_st X509_STORE_CTX;
""",
    "X509_STORE_CTX",
)

patch_one(
    "types.h",
    """typedef struct x509_lookup_method_st X509_LOOKUP_METHOD;
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;
""",
    """/**
 * @brief Opaque method table describing how an X509_LOOKUP finds certificates/CRLs.
 */
typedef struct x509_lookup_method_st X509_LOOKUP_METHOD;
/**
 * @brief Opaque verification-parameter object (purpose, trust, time, flags, …).
 */
typedef struct X509_VERIFY_PARAM_st X509_VERIFY_PARAM;
""",
    "X509_LOOKUP_METHOD/X509_VERIFY_PARAM",
)

patch_one(
    "types.h",
    """typedef struct v3_ext_ctx X509V3_CTX;
""",
    """/**
 * @brief Opaque context passed to X.509v3 extension helpers (issuer/subject/cert/request).
 */
typedef struct v3_ext_ctx X509V3_CTX;
""",
    "X509V3_CTX",
)

patch_one(
    "types.h",
    """typedef struct ui_method_st UI_METHOD;
""",
    """/**
 * @brief Opaque UI_METHOD table implementing interactive user prompting.
 */
typedef struct ui_method_st UI_METHOD;
""",
    "UI_METHOD",
)

patch_one(
    "types.h",
    """typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
""",
    """/**
 * @brief Opaque node in an X.509 certificate policy tree.
 */
typedef struct X509_POLICY_NODE_st X509_POLICY_NODE;
/**
 * @brief Opaque single depth level within an X.509 certificate policy tree.
 */
typedef struct X509_POLICY_LEVEL_st X509_POLICY_LEVEL;
""",
    "X509_POLICY_NODE/LEVEL",
)

patch_one(
    "types.h",
    """typedef struct DIST_POINT_st DIST_POINT;
""",
    """/**
 * @brief Opaque CRL distribution-point structure from a certificate extension.
 */
typedef struct DIST_POINT_st DIST_POINT;
""",
    "DIST_POINT",
)

patch_one(
    "types.h",
    """typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
""",
    """/**
 * @brief Opaque bag of application-specific ex_data slots attached to OpenSSL objects.
 */
typedef struct crypto_ex_data_st CRYPTO_EX_DATA;
""",
    "CRYPTO_EX_DATA",
)

patch_one(
    "types.h",
    """typedef struct sct_ctx_st SCT_CTX;
""",
    """/**
 * @brief Opaque context used when verifying Certificate Transparency SCTs.
 */
typedef struct sct_ctx_st SCT_CTX;
""",
    "SCT_CTX",
)

patch_one(
    "types.h",
    """typedef struct ctlog_store_st CTLOG_STORE;
""",
    """/**
 * @brief Opaque store of Certificate Transparency logs trusted for SCT verification.
 */
typedef struct ctlog_store_st CTLOG_STORE;
""",
    "CTLOG_STORE",
)

patch_one(
    "types.h",
    """typedef struct ossl_dispatch_st OSSL_DISPATCH;
""",
    """/**
 * @brief Function-pointer dispatch table entry exchanged between libcrypto and providers.
 */
typedef struct ossl_dispatch_st OSSL_DISPATCH;
""",
    "OSSL_DISPATCH",
)

patch_one(
    "types.h",
    """typedef struct ossl_param_st OSSL_PARAM;
""",
    """/**
 * @brief Key/type/data triple used to pass parameters across provider boundaries.
 */
typedef struct ossl_param_st OSSL_PARAM;
""",
    "OSSL_PARAM",
)

patch_one(
    "types.h",
    """typedef struct ossl_decoder_ctx_st OSSL_DECODER_CTX;
""",
    """/**
 * @brief Opaque context that drives OSSL_DECODER providers when decoding keys/objects.
 */
typedef struct ossl_decoder_ctx_st OSSL_DECODER_CTX;
""",
    "OSSL_DECODER_CTX",
)

# ----- x509.h -----

patch_both(
    "x509.h",
    """    X509_PKEY *x_pkey;
    EVP_CIPHER_INFO enc_cipher;
    /** Length in bytes of the encrypted private-key material at @c enc_data. */
""",
    """    X509_PKEY *x_pkey;
    /** Cipher algorithm/parameters used when @c enc_data holds an encrypted private key. */
    EVP_CIPHER_INFO enc_cipher;
    /** Length in bytes of the encrypted private-key material at @c enc_data. */
""",
    "X509_info_st::enc_cipher",
)

patch_both(
    "x509.h",
    """int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent);
""",
    """/**
 * @brief Hex-dump an ASN.1 signature BIT/OCTET STRING to a BIO with indentation.
 * @param bp Destination BIO.
 * @param sig Signature bytes to dump.
 * @param indent Number of spaces prefixed to each output line.
 * @return 1 on success, or 0 on failure.
 */
int X509_signature_dump(BIO *bp, const ASN1_STRING *sig, int indent);
""",
    "X509_signature_dump",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_3_0 int i2d_EC_PUBKEY_fp(FILE *fp, const EC_KEY *eckey);
""",
    """/**
 * @brief Write an EC public key in SubjectPublicKeyInfo DER form to a FILE (deprecated).
 * @param fp Destination stdio stream.
 * @param eckey EC key whose public key is encoded.
 * @return Number of bytes written, or <=0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int i2d_EC_PUBKEY_fp(FILE *fp, const EC_KEY *eckey);
""",
    "i2d_EC_PUBKEY_fp",
)

patch_both(
    "x509.h",
    """int i2d_PKCS8_bio(BIO *bp, const X509_SIG *p8);
""",
    """/**
 * @brief Write an encrypted PKCS#8 private key (X509_SIG) in DER form to a BIO.
 * @param bp Destination BIO.
 * @param p8 Encrypted private-key structure.
 * @return Number of bytes written, or <=0 on error.
 */
int i2d_PKCS8_bio(BIO *bp, const X509_SIG *p8);
""",
    "i2d_PKCS8_bio",
)

patch_both(
    "x509.h",
    """int X509_CRL_set_issuer_name(X509_CRL *x, const X509_NAME *name);
""",
    """/**
 * @brief Set the issuer distinguished name on a certificate revocation list.
 * @param x CRL to update.
 * @param name Issuer name to copy into @p x.
 * @return 1 on success, or 0 on failure.
 */
int X509_CRL_set_issuer_name(X509_CRL *x, const X509_NAME *name);
""",
    "X509_CRL_set_issuer_name",
)

patch_both(
    "x509.h",
    """OSSL_DEPRECATEDIN_1_1_0 ASN1_TIME *X509_CRL_get_nextUpdate(X509_CRL *crl);
""",
    """/**
 * @brief Return the nextUpdate field of a CRL (deprecated; prefer X509_CRL_get0_nextUpdate).
 * @param crl CRL to query.
 * @return Internal ASN1_TIME pointer, or NULL if absent; do not free.
 */
OSSL_DEPRECATEDIN_1_1_0 ASN1_TIME *X509_CRL_get_nextUpdate(X509_CRL *crl);
""",
    "X509_CRL_get_nextUpdate",
)

patch_both(
    "x509.h",
    """int X509_ocspid_print(BIO *bp, X509 *x);
""",
    """/**
 * @brief Print OCSP subject/public-key hashes for a certificate to a BIO.
 * @param bp Destination BIO.
 * @param x Certificate whose OCSP hashes are printed.
 * @return 1 on success, or 0 on failure.
 */
int X509_ocspid_print(BIO *bp, X509 *x);
""",
    "X509_ocspid_print",
)

patch_both(
    "x509.h",
    """int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag,
    unsigned long cflag);
int X509_REQ_print(BIO *bp, X509_REQ *req);
""",
    """int X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflag,
    unsigned long cflag);
/**
 * @brief Print a certificate request to a BIO using default name/content flags.
 * @param bp Destination BIO.
 * @param req Certificate request to print.
 * @return 1 on success, or 0 on failure.
 */
int X509_REQ_print(BIO *bp, X509_REQ *req);
""",
    "X509_REQ_print",
)

patch_both(
    "x509.h",
    """ASN1_OBJECT *X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY *ne);
ASN1_STRING *X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne);
""",
    """/**
 * @brief Return the attribute type OID of an X509_NAME_ENTRY.
 * @param ne Name entry to query.
 * @return Internal ASN1_OBJECT pointer, or NULL; do not free.
 */
ASN1_OBJECT *X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY *ne);
/**
 * @brief Return the attribute value string of an X509_NAME_ENTRY.
 * @param ne Name entry to query.
 * @return Internal ASN1_STRING pointer, or NULL; do not free.
 */
ASN1_STRING *X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *ne);
""",
    "X509_NAME_ENTRY_get_object/data",
)

patch_both(
    "x509.h",
    """int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid, int lastpos);
""",
    """/**
 * @brief Find the next attribute on an EVP_PKEY whose type NID equals @p nid.
 * @param key Key whose attribute stack is searched.
 * @param nid Attribute type NID to match.
 * @param lastpos Index to search after (-1 to start from the beginning).
 * @return Attribute index, or -1 if not found.
 */
int EVP_PKEY_get_attr_by_NID(const EVP_PKEY *key, int nid, int lastpos);
""",
    "EVP_PKEY_get_attr_by_NID",
)

# ----- x509_vfy.h -----

patch_both(
    "x509_vfy.h",
    """X509_LOOKUP_TYPE X509_OBJECT_get_type(const X509_OBJECT *a);
""",
    """/**
 * @brief Return whether an X509_OBJECT holds a certificate, CRL, or nothing.
 * @param a Object to query.
 * @return X509_LU_X509, X509_LU_CRL, or X509_LU_NONE.
 */
X509_LOOKUP_TYPE X509_OBJECT_get_type(const X509_OBJECT *a);
""",
    "X509_OBJECT_get_type",
)

# ----- x509v3.h -----

patch_both(
    "x509v3.h",
    """void PROXY_POLICY_free(PROXY_POLICY *a);
""",
    """/**
 * @brief Free a PROXY_POLICY structure and its OID/policy octets.
 * @param a Policy object to free, or NULL.
 */
void PROXY_POLICY_free(PROXY_POLICY *a);
""",
    "PROXY_POLICY_free",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
