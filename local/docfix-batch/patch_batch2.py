#!/usr/bin/env python3
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

# async.h
patch_both("async.h",
"""typedef struct async_job_st ASYNC_JOB;
typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;""",
"""typedef struct async_job_st ASYNC_JOB;
/**
 * @brief Opaque wait context describing file descriptors an ASYNC_JOB is blocked on.
 */
typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;""",
"ASYNC_WAIT_CTX")

# bio.h
patch_both("bio.h",
"typedef struct bio_addrinfo_st BIO_ADDRINFO;",
"""/**
 * @brief Opaque linked address-info node returned by BIO_lookup() / BIO_lookup_ex().
 */
typedef struct bio_addrinfo_st BIO_ADDRINFO;""",
"BIO_ADDRINFO")

patch_both("bio.h",
"typedef struct bio_method_st BIO_METHOD;",
"""/**
 * @brief Opaque BIO method table describing how a BIO type reads, writes, and controls I/O.
 */
typedef struct bio_method_st BIO_METHOD;""",
"BIO_METHOD")

patch_both("bio.h",
"""typedef void (*BIO_dgram_sctp_notification_handler_fn)(BIO *b,
    void *context,
    void *buf);""",
"""/**
 * @brief Callback invoked when an SCTP datagram BIO receives a notification message.
 * @param b Datagram BIO that received the notification.
 * @param context User pointer supplied when the handler was registered.
 * @param buf Notification payload buffer (SCTP notification structure).
 */
typedef void (*BIO_dgram_sctp_notification_handler_fn)(BIO *b,
    void *context,
    void *buf);""",
"BIO_dgram_sctp_notification_handler_fn")

patch_both("bio.h",
"""typedef struct bio_mmsg_cb_args_st {
    BIO_MSG *msg;
    size_t stride, num_msg;
    uint64_t flags;
    size_t *msgs_processed;
} BIO_MMSG_CB_ARGS;""",
"""typedef struct bio_mmsg_cb_args_st {
    BIO_MSG *msg;
    /** Byte stride between consecutive BIO_MSG elements in @c msg. */
    size_t stride;
    /** Number of BIO_MSG elements addressed by this multi-message operation. */
    size_t num_msg;
    uint64_t flags;
    size_t *msgs_processed;
} BIO_MMSG_CB_ARGS;""",
"BIO_MMSG_CB_ARGS stride/num_msg")

patch_both("bio.h",
"BIO *BIO_new_ex(OSSL_LIB_CTX *libctx, const BIO_METHOD *method);",
"""/**
 * @brief Allocate a new BIO for @p method using the given library context.
 * @param libctx Library context associated with the BIO, or NULL for the default.
 * @param method BIO method that defines the BIO's behaviour.
 * @return New BIO, or NULL on allocation failure.
 */
BIO *BIO_new_ex(OSSL_LIB_CTX *libctx, const BIO_METHOD *method);""",
"BIO_new_ex")

patch_both("bio.h",
"void BIO_set_data(BIO *a, void *ptr);",
"""/**
 * @brief Store an implementation-specific pointer on a BIO (used by custom BIO methods).
 * @param a BIO whose app-data pointer is set.
 * @param ptr Opaque pointer for the BIO method implementation.
 */
void BIO_set_data(BIO *a, void *ptr);""",
"BIO_set_data")

patch_both("bio.h",
"void BIO_set_shutdown(BIO *a, int shut);",
"""/**
 * @brief Set whether BIO_free() should close the underlying I/O resource.
 * @param a BIO to update.
 * @param shut Non-zero to close the underlying descriptor/handle on free; 0 to leave it open.
 */
void BIO_set_shutdown(BIO *a, int shut);""",
"BIO_set_shutdown")

patch_both("bio.h",
"int BIO_fd_should_retry(int i);",
"""/**
 * @brief Decide whether a file-descriptor BIO I/O result should be retried.
 * @param i Return value from a read/write-style call (negative on error).
 * @return Non-zero if the operation failed with a non-fatal condition and should be retried, or 0 otherwise.
 */
int BIO_fd_should_retry(int i);""",
"BIO_fd_should_retry")

patch_both("bio.h",
"int BIO_ADDRINFO_socktype(const BIO_ADDRINFO *bai);",
"""/**
 * @brief Return the socket type of a BIO_ADDRINFO node (for example SOCK_STREAM).
 * @param bai Address-info node to query.
 * @return Socket type constant suitable for socket().
 */
int BIO_ADDRINFO_socktype(const BIO_ADDRINFO *bai);""",
"BIO_ADDRINFO_socktype")

patch_both("bio.h",
"""enum BIO_lookup_type {
    BIO_LOOKUP_CLIENT,
    BIO_LOOKUP_SERVER
};""",
"""enum BIO_lookup_type {
    /** Resolve addresses suitable for an outgoing client connection. */
    BIO_LOOKUP_CLIENT,
    /** Resolve addresses suitable for an accepting server socket. */
    BIO_LOOKUP_SERVER
};""",
"BIO_lookup_type")

patch_both("bio.h",
"int BIO_socket_ioctl(int fd, long type, void *arg);",
"""/**
 * @brief Perform an ioctl on a socket descriptor with BIO error reporting.
 * @param fd Socket file descriptor.
 * @param type ioctl request code.
 * @param arg Request-specific argument pointer.
 * @return 0 on success, or -1 on error (OpenSSL error stack updated).
 */
int BIO_socket_ioctl(int fd, long type, void *arg);""",
"BIO_socket_ioctl")

patch_both("bio.h",
"int BIO_set_tcp_ndelay(int sock, int turn_on);",
"""/**
 * @brief Enable or disable TCP_NODELAY on a socket.
 * @param sock Socket file descriptor.
 * @param turn_on Non-zero to disable Nagle coalescing (TCP_NODELAY on), or 0 to clear it.
 * @return 0 on success, or -1 on error.
 */
int BIO_set_tcp_ndelay(int sock, int turn_on);""",
"BIO_set_tcp_ndelay")

patch_both("bio.h",
"""int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
    long (*callback_ctrl)(BIO *, int,
        BIO_info_cb *));""",
"""/**
 * @brief Install the callback-ctrl function on a custom BIO_METHOD.
 * @param biom Method object to update.
 * @param callback_ctrl Function invoked for BIO_callback_ctrl()-style commands.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_callback_ctrl(BIO_METHOD *biom,
    long (*callback_ctrl)(BIO *, int,
        BIO_info_cb *));""",
"BIO_meth_set_callback_ctrl")

# bn.h
patch_both("bn.h",
"int BN_GENCB_call(BN_GENCB *cb, int a, int b);",
"""/**
 * @brief Invoke a BN_GENCB progress callback with event codes @p a and @p b.
 * @param cb Callback object populated with BN_GENCB_set() or BN_GENCB_set_old(); NULL is ignored.
 * @param a Primary event / stage code passed to the callback.
 * @param b Secondary progress value passed to the callback.
 * @return 1 to continue, or 0 if the callback requested cancellation.
 */
int BN_GENCB_call(BN_GENCB *cb, int a, int b);""",
"BN_GENCB_call")

patch_both("bn.h",
"void BN_zero_ex(BIGNUM *a);",
"""/**
 * @brief Set a BIGNUM to zero without allocating or freeing limbs.
 * @param a Integer cleared in place; must already be a valid BIGNUM.
 */
void BN_zero_ex(BIGNUM *a);""",
"BN_zero_ex")

patch_both("bn.h",
"BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);",
"""/**
 * @brief Convert a little-endian unsigned byte array to a BIGNUM.
 * @param s Little-endian input octets (least significant byte first).
 * @param len Number of bytes at @p s.
 * @param ret Destination BIGNUM to reuse, or NULL to allocate a new one.
 * @return Result BIGNUM, or NULL on error.
 */
BIGNUM *BN_lebin2bn(const unsigned char *s, int len, BIGNUM *ret);""",
"BN_lebin2bn")

patch_both("bn.h",
"""BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
    const BIGNUM *mod, BN_CTX *ctx);""",
"""/**
 * @brief Lazily initialize a shared Montgomery context under a lock.
 * @param pmont Address of the Montgomery context pointer; allocated and set on first use.
 * @param lock Read/write lock serializing initialization of *@p pmont.
 * @param mod Modulus used to build the Montgomery context.
 * @param ctx BN_CTX scratch space for the initialization.
 * @return The initialized Montgomery context at *@p pmont, or NULL on error.
 */
BN_MONT_CTX *BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
    const BIGNUM *mod, BN_CTX *ctx);""",
"BN_MONT_CTX_set_locked")

patch_both("bn.h",
"""int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const int p[],
    BN_CTX *ctx);""",
"""/**
 * @brief Compute the inverse of @p b modulo an irreducible GF(2^m) polynomial given as an int array.
 * @param r Result BIGNUM receiving (1 / b) mod p(x).
 * @param b Value to invert (must be non-zero modulo @p p).
 * @param p Irreducible polynomial as a descending list of set-bit indices terminated by -1.
 * @param ctx BN_CTX scratch space.
 * @return 1 on success, or 0 on error.
 */
int BN_GF2m_mod_inv_arr(BIGNUM *r, const BIGNUM *b, const int p[],
    BN_CTX *ctx);""",
"BN_GF2m_mod_inv_arr")

# buffer.h
patch_both("buffer.h",
"    size_t length; /* current number of bytes */",
"    /** Current number of valid content bytes stored in @c data. */\n    size_t length;",
"BUF_MEM::length")

patch_both("buffer.h",
"BUF_MEM *BUF_MEM_new(void);",
"""/**
 * @brief Allocate an empty BUF_MEM with default (non-secure) allocation flags.
 * @return New zero-length BUF_MEM, or NULL on allocation failure.
 */
BUF_MEM *BUF_MEM_new(void);""",
"BUF_MEM_new")

patch_both("buffer.h",
"void BUF_MEM_free(BUF_MEM *a);",
"""/**
 * @brief Free a BUF_MEM and its data buffer.
 * @param a Buffer to free, or NULL.
 *
 * Clears @c data before release when the buffer was allocated with secure flags.
 */
void BUF_MEM_free(BUF_MEM *a);""",
"BUF_MEM_free")

# cms
patch_both("cms.h",
"""int CMS_set1_signers_certs(CMS_ContentInfo *cms, STACK_OF(X509) *certs,
    unsigned int flags);""",
"""/**
 * @brief Attach signer certificates from @p certs to matching CMS SignerInfos.
 * @param cms Signed CMS ContentInfo whose SignerInfos are updated.
 * @param certs Candidate signer certificates; matching ones are referenced by the CMS structure.
 * @param flags CMS_NOINTERN and related flags controlling where certificates are taken from.
 * @return Number of SignerInfos that received a certificate, or a negative value on error.
 */
int CMS_set1_signers_certs(CMS_ContentInfo *cms, STACK_OF(X509) *certs,
    unsigned int flags);""",
"CMS_set1_signers_certs")

# conf
patch_both("conf.h",
"int NCONF_load(CONF *conf, const char *file, long *eline);",
"""/**
 * @brief Load configuration values from a file into a CONF object.
 * @param conf Destination configuration object.
 * @param file Path of the configuration file to read.
 * @param eline Optional output set to the line number where a parse error occurred.
 * @return 1 on success, or 0 on error.
 */
int NCONF_load(CONF *conf, const char *file, long *eline);""",
"NCONF_load")

patch_both("conf_api.h",
"int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value);",
"""/**
 * @brief Insert a name/value pair into a CONF section (internal CONF helper).
 * @param conf Configuration object whose hash table is updated.
 * @param section Section CONF_VALUE that owns the entry.
 * @param value Name/value CONF_VALUE to add; ownership transfers on success.
 * @return 1 on success, or 0 on error.
 */
int _CONF_add_string(CONF *conf, CONF_VALUE *section, CONF_VALUE *value);""",
"_CONF_add_string")

patch_both("conf_api.h",
"int _CONF_new_data(CONF *conf);",
"""/**
 * @brief Allocate the internal LHASH used to store CONF values (internal helper).
 * @param conf Configuration object whose data table is created when missing.
 * @return 1 on success, or 0 on allocation failure.
 */
int _CONF_new_data(CONF *conf);""",
"_CONF_new_data")

patch_both("conftypes.h",
"""    int (*init)(CONF *conf);
    int (*destroy)(CONF *conf);
    int (*destroy_data)(CONF *conf);""",
"""    int (*init)(CONF *conf);
    /** Tear down a CONF object created by @c create (method-specific cleanup). */
    int (*destroy)(CONF *conf);
    int (*destroy_data)(CONF *conf);""",
"conf_method_st::destroy")

# core.h
patch_both("core.h",
"typedef struct ossl_core_handle_st OSSL_CORE_HANDLE;",
"""/**
 * @brief Opaque core handle passed to a provider's OSSL_provider_init() for upcalls.
 */
typedef struct ossl_core_handle_st OSSL_CORE_HANDLE;""",
"OSSL_CORE_HANDLE")

patch_both("core.h",
"OPENSSL_EXPORT OSSL_provider_init_fn OSSL_provider_init;",
"""/**
 * @brief Exported provider entry point; each provider module must define this symbol.
 *
 * OpenSSL loads the provider by resolving this function and calling it with the
 * core dispatch tables described by OSSL_provider_init_fn.
 */
OPENSSL_EXPORT OSSL_provider_init_fn OSSL_provider_init;""",
"OSSL_provider_init")

# crypto.h
patch_both("crypto.h",
"""typedef struct crypto_threadid_st {
    int dummy;
} CRYPTO_THREADID;""",
"""/**
 * @brief Legacy thread-id placeholder retained for API compatibility (no longer used).
 */
typedef struct crypto_threadid_st {
    int dummy;
} CRYPTO_THREADID;""",
"CRYPTO_THREADID")

patch_both("crypto.h",
"OSSL_CRYPTO_ALLOC void *CRYPTO_zalloc(size_t num, const char *file, int line);",
"""/**
 * @brief Allocate @p num bytes of zero-initialized memory (file/line for debugging).
 * @param num Number of bytes to allocate.
 * @param file Source file name recorded with the allocation (usually __FILE__).
 * @param line Source line recorded with the allocation (usually __LINE__).
 * @return Pointer to zeroed memory, or NULL on failure.
 */
OSSL_CRYPTO_ALLOC void *CRYPTO_zalloc(size_t num, const char *file, int line);""",
"CRYPTO_zalloc")

patch_both("crypto.h",
"char *CRYPTO_strdup(const char *str, const char *file, int line);",
"""/**
 * @brief Duplicate a NUL-terminated string using the OpenSSL allocator.
 * @param str String to copy.
 * @param file Source file name recorded with the allocation (usually __FILE__).
 * @param line Source line recorded with the allocation (usually __LINE__).
 * @return Newly allocated copy, or NULL on failure.
 */
char *CRYPTO_strdup(const char *str, const char *file, int line);""",
"CRYPTO_strdup")

patch_both("crypto.h",
"""void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num,
    const char *file, int line);""",
"""/**
 * @brief Reallocate a buffer, securely clearing any released trailing bytes.
 * @param addr Existing allocation, or NULL to allocate anew.
 * @param old_num Previous size in bytes (used when clearing shrunk regions).
 * @param num New size in bytes.
 * @param file Source file name recorded with the allocation (usually __FILE__).
 * @param line Source line recorded with the allocation (usually __LINE__).
 * @return Reallocated pointer, or NULL on failure (original block left allocated on failure).
 */
void *CRYPTO_clear_realloc(void *addr, size_t old_num, size_t num,
    const char *file, int line);""",
"CRYPTO_clear_realloc")

patch_both("crypto.h",
"int OPENSSL_atexit(void (*handler)(void));",
"""/**
 * @brief Register a handler to run during OPENSSL_cleanup().
 * @param handler Function invoked once when OpenSSL is deinitialized.
 * @return 1 on success, or 0 on failure.
 */
int OPENSSL_atexit(void (*handler)(void));""",
"OPENSSL_atexit")

patch_both("cryptoerr_legacy.h",
"OSSL_DEPRECATEDIN_3_0 int ERR_load_KDF_strings(void);",
"""/**
 * @brief Load KDF library error strings (no-op in OpenSSL 3; deprecated).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_KDF_strings(void);""",
"ERR_load_KDF_strings")

# dh.h
patch_both("dh.h",
"OSSL_DEPRECATEDIN_3_0 int DH_security_bits(const DH *dh);",
"""/**
 * @brief Estimate the security strength in bits of a DH key's parameters (deprecated).
 * @param dh DH object whose prime size is assessed.
 * @return Approximate security strength in bits, or 0 on error.
 */
OSSL_DEPRECATEDIN_3_0 int DH_security_bits(const DH *dh);""",
"DH_security_bits")

patch_both("dh.h",
"OSSL_DEPRECATEDIN_3_0 void *DH_get_ex_data(const DH *d, int idx);",
"""/**
 * @brief Return application data previously stored on a DH object (deprecated).
 * @param d DH object to query.
 * @param idx Index obtained from DH_get_ex_new_index().
 * @return Stored pointer, or NULL if unset.
 */
OSSL_DEPRECATEDIN_3_0 void *DH_get_ex_data(const DH *d, int idx);""",
"DH_get_ex_data")

patch_both("dh.h",
"OSSL_DEPRECATEDIN_3_0 DH *DH_get_2048_224(void);",
"""/**
 * @brief Allocate a DH object with the RFC 5114 2048-bit MODP group using a 224-bit subgroup (deprecated).
 * @return New DH with p, q, and g set, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 DH *DH_get_2048_224(void);""",
"DH_get_2048_224")

patch_both("dh.h",
"OSSL_DEPRECATEDIN_3_0 int DH_meth_get_flags(const DH_METHOD *dhm);",
"""/**
 * @brief Return the flag mask stored on a DH_METHOD (deprecated).
 * @param dhm Method object to query.
 * @return Flags previously set with DH_meth_set_flags().
 */
OSSL_DEPRECATEDIN_3_0 int DH_meth_get_flags(const DH_METHOD *dhm);""",
"DH_meth_get_flags")

# dsa.h
patch_both("dsa.h",
"typedef struct DSA_SIG_st DSA_SIG;",
"""/**
 * @brief Opaque DSA signature value holding the ASN.1 integers r and s.
 */
typedef struct DSA_SIG_st DSA_SIG;""",
"DSA_SIG")

patch_both("dsa.h",
"OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_priv_key(const DSA *d);",
"""/**
 * @brief Return the private key component of a DSA object without duplicating it (deprecated).
 * @param d DSA key to query.
 * @return Internal BIGNUM pointer for the private key, or NULL if unset; do not free.
 */
OSSL_DEPRECATEDIN_3_0 const BIGNUM *DSA_get0_priv_key(const DSA *d);""",
"DSA_get0_priv_key")

patch_both("dsa.h",
"OSSL_DEPRECATEDIN_3_0 int DSA_meth_get_flags(const DSA_METHOD *dsam);",
"""/**
 * @brief Return the flag mask stored on a DSA_METHOD (deprecated).
 * @param dsam Method object to query.
 * @return Flags previously set with DSA_meth_set_flags().
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_get_flags(const DSA_METHOD *dsam);""",
"DSA_meth_get_flags")

patch_both("dsa.h",
"OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_flags(DSA_METHOD *dsam, int flags);",
"""/**
 * @brief Set the flag mask on a DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param flags New flag bits for the method.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_flags(DSA_METHOD *dsam, int flags);""",
"DSA_meth_set_flags")

print(f"done ok={len(ok)} miss={len(missing)}")
if missing:
    print("MISSING:", *missing, sep="\n  ")
