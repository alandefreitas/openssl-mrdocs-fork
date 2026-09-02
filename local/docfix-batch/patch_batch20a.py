#!/usr/bin/env python3
"""Documentation repair batch 20a: asn1, bio."""
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


print("=== batch 20a: asn1/bio ===")

# ----- asn1.h / asn1.h.in -----

patch_both(
    "asn1.h",
    """ASN1_PCTX *ASN1_PCTX_new(void);
void ASN1_PCTX_free(ASN1_PCTX *p);
""",
    """ASN1_PCTX *ASN1_PCTX_new(void);
/**
 * @brief Free an ASN1_PCTX allocated by ASN1_PCTX_new().
 * @param p Print context to free, or NULL (no-op).
 */
void ASN1_PCTX_free(ASN1_PCTX *p);
""",
    "ASN1_PCTX_free",
)

# ----- bio.h / bio.h.in -----

patch_both(
    "bio.h",
    """const char *BIO_method_name(const BIO *b);
int BIO_method_type(const BIO *b);
""",
    """const char *BIO_method_name(const BIO *b);
/**
 * @brief Return the BIO type code of the method used by @p b (BIO_TYPE_*).
 * @param b BIO whose method type is queried.
 * @return Type identifier such as BIO_TYPE_MEM or BIO_TYPE_SOCKET.
 */
int BIO_method_type(const BIO *b);
""",
    "BIO_method_type",
)

patch_both(
    "bio.h",
    """size_t BIO_ctrl_pending(BIO *b);
""",
    """/**
 * @brief Return the number of bytes buffered for reading in a BIO (ctrl pending read count).
 * @param b BIO to query.
 * @return Pending readable byte count.
 */
size_t BIO_ctrl_pending(BIO *b);
""",
    "BIO_ctrl_pending",
)

patch_both(
    "bio.h",
    """int BIO_set_ex_data(BIO *bio, int idx, void *data);
void *BIO_get_ex_data(const BIO *bio, int idx);
""",
    """int BIO_set_ex_data(BIO *bio, int idx, void *data);
/**
 * @brief Retrieve application data previously stored on a BIO with BIO_set_ex_data().
 * @param bio BIO to query.
 * @param idx Ex-data index from BIO_get_ex_new_index() or a class-specific allocator.
 * @return Stored pointer, or NULL if unset.
 */
void *BIO_get_ex_data(const BIO *bio, int idx);
""",
    "BIO_get_ex_data",
)

patch_both(
    "bio.h",
    """BIO *BIO_new_ex(OSSL_LIB_CTX *libctx, const BIO_METHOD *method);
BIO *BIO_new(const BIO_METHOD *type);
""",
    """BIO *BIO_new_ex(OSSL_LIB_CTX *libctx, const BIO_METHOD *method);
/**
 * @brief Allocate a new BIO using @p type and the default library context.
 * @param type BIO_METHOD such as BIO_s_mem() or BIO_s_file().
 * @return New BIO, or NULL on failure; free with BIO_free() / BIO_free_all().
 */
BIO *BIO_new(const BIO_METHOD *type);
""",
    "BIO_new",
)

patch_both(
    "bio.h",
    """long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);
void *BIO_ptr_ctrl(BIO *bp, int cmd, long larg);
""",
    """long BIO_callback_ctrl(BIO *b, int cmd, BIO_info_cb *fp);
/**
 * @brief Invoke a BIO ctrl that returns a pointer result.
 * @param bp BIO to control.
 * @param cmd Control command that yields a pointer (for example BIO_C_GET_BUF_MEM).
 * @param larg Long argument passed through to BIO_ctrl().
 * @return Pointer returned by the ctrl implementation, or NULL.
 */
void *BIO_ptr_ctrl(BIO *bp, int cmd, long larg);
""",
    "BIO_ptr_ctrl",
)

patch_both(
    "bio.h",
    """int BIO_nread0(BIO *bio, char **buf);
""",
    """/**
 * @brief Peek at readable bytes in a memory BIO without consuming them.
 * @param bio Memory BIO to inspect.
 * @param buf Receives a pointer into the BIO's internal buffer (valid until the next modify).
 * @return Number of bytes available at *@p buf, or a negative value on error.
 */
int BIO_nread0(BIO *bio, char **buf);
""",
    "BIO_nread0",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_f_prefix(void);
const BIO_METHOD *BIO_s_core(void);
""",
    """const BIO_METHOD *BIO_f_prefix(void);
/**
 * @brief Return the BIO_METHOD for a core BIO that reads/writes via an OSSL_CORE_BIO.
 * @return Pointer to the static core method for use with BIO_new() and BIO_set_data().
 */
const BIO_METHOD *BIO_s_core(void);
""",
    "BIO_s_core",
)

patch_both(
    "bio.h",
    """int BIO_sock_should_retry(int i);
int BIO_sock_non_fatal_error(int error);
""",
    """int BIO_sock_should_retry(int i);
/**
 * @brief Report whether a socket errno / WSA error is a non-fatal retryable condition.
 * @param error Platform socket error code (for example EAGAIN or WSAEWOULDBLOCK).
 * @return 1 if BIO socket I/O should retry, or 0 if the error is fatal.
 */
int BIO_sock_non_fatal_error(int error);
""",
    "BIO_sock_non_fatal_error",
)

patch_both(
    "bio.h",
    """int BIO_ADDR_rawmake(BIO_ADDR *ap, int family,
    const void *where, size_t wherelen, unsigned short port);
""",
    """/**
 * @brief Populate a BIO_ADDR from a raw address family, bytes, and port.
 * @param ap Destination address object (must already be allocated).
 * @param family Address family such as AF_INET or AF_INET6.
 * @param where Network-order address bytes (for example in_addr / in6_addr).
 * @param wherelen Length of @p where in bytes.
 * @param port Port number in host byte order.
 * @return 1 on success, or 0 on failure.
 */
int BIO_ADDR_rawmake(BIO_ADDR *ap, int family,
    const void *where, size_t wherelen, unsigned short port);
""",
    "BIO_ADDR_rawmake",
)

patch_both(
    "bio.h",
    """int BIO_socket_nbio(int fd, int mode);
int BIO_sock_init(void);
""",
    """int BIO_socket_nbio(int fd, int mode);
/**
 * @brief Initialize platform socket support used by BIO socket helpers (Winsock on Windows).
 * @return 1 on success, or 0 on failure.
 */
int BIO_sock_init(void);
""",
    "BIO_sock_init",
)

patch_both(
    "bio.h",
    """OSSL_DEPRECATEDIN_1_1_0 struct hostent *BIO_gethostbyname(const char *name);
""",
    """/**
 * @brief Resolve @p name with gethostbyname(3) (deprecated; prefer BIO_lookup_ex()).
 * @param name Host name to look up.
 * @return Pointer to a static hostent on success, or NULL on failure.
 */
OSSL_DEPRECATEDIN_1_1_0 struct hostent *BIO_gethostbyname(const char *name);
""",
    "BIO_gethostbyname",
)

patch_both(
    "bio.h",
    """union BIO_sock_info_u {
    /** Local or peer address when type is BIO_SOCK_INFO_ADDRESS. */
    BIO_ADDR *addr;
};
enum BIO_sock_info_type {
    BIO_SOCK_INFO_ADDRESS
};
""",
    """/**
 * @brief Output union for BIO_sock_info(); currently holds a BIO_ADDR pointer.
 */
union BIO_sock_info_u {
    /** Local or peer address when type is BIO_SOCK_INFO_ADDRESS. */
    BIO_ADDR *addr;
};
/**
 * @brief Kinds of socket metadata that BIO_sock_info() can retrieve.
 */
enum BIO_sock_info_type {
    /** Request the local or peer BIO_ADDR for the socket. */
    BIO_SOCK_INFO_ADDRESS
};
""",
    "BIO_sock_info_u/type",
)

patch_both(
    "bio.h",
    """int BIO_socket(int domain, int socktype, int protocol, int options);
""",
    """/**
 * @brief Create a socket with optional BIO_SOCK_* behaviour flags applied.
 * @param domain Address family (for example AF_INET).
 * @param socktype Socket type (for example SOCK_STREAM).
 * @param protocol Protocol number, or 0 for the default for @p socktype.
 * @param options Bitmask of BIO_SOCK_* flags (for example BIO_SOCK_NONBLOCK).
 * @return New socket file descriptor on success, or -1 on failure.
 */
int BIO_socket(int domain, int socktype, int protocol, int options);
""",
    "BIO_socket",
)

patch_both(
    "bio.h",
    """int BIO_vprintf(BIO *bio, const char *format, va_list args)
    ossl_bio__attr__((__format__(ossl_bio__printf__, 2, 0)));
""",
    """/**
 * @brief printf-style formatted write to a BIO using a va_list.
 * @param bio Destination BIO.
 * @param format printf-style format string.
 * @param args Variable-argument list matching @p format.
 * @return Number of bytes written, or a negative value on error.
 */
int BIO_vprintf(BIO *bio, const char *format, va_list args)
    ossl_bio__attr__((__format__(ossl_bio__printf__, 2, 0)));
""",
    "BIO_vprintf",
)

patch_both(
    "bio.h",
    """BIO_METHOD *BIO_meth_new(int type, const char *name);
void BIO_meth_free(BIO_METHOD *biom);
""",
    """BIO_METHOD *BIO_meth_new(int type, const char *name);
/**
 * @brief Free a BIO_METHOD allocated with BIO_meth_new().
 * @param biom Method table to free, or NULL (no-op).
 */
void BIO_meth_free(BIO_METHOD *biom);
""",
    "BIO_meth_free",
)

patch_both(
    "bio.h",
    """int BIO_meth_set_write_ex(BIO_METHOD *biom,
    int (*bwrite)(BIO *, const char *, size_t, size_t *));
""",
    """/**
 * @brief Install the size_t-based write callback on a BIO_METHOD.
 * @param biom Method table to update.
 * @param bwrite Callback implementing BIO_write_ex()-style output; may be NULL.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_write_ex(BIO_METHOD *biom,
    int (*bwrite)(BIO *, const char *, size_t, size_t *));
""",
    "BIO_meth_set_write_ex",
)

patch_both(
    "bio.h",
    """int (*BIO_meth_get_puts(const BIO_METHOD *biom))(BIO *, const char *);
""",
    """/**
 * @brief Return the puts callback installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Puts callback, or NULL if unset.
 */
int (*BIO_meth_get_puts(const BIO_METHOD *biom))(BIO *, const char *);
""",
    "BIO_meth_get_puts",
)

patch_both(
    "bio.h",
    """long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))(BIO *, int, BIO_info_cb *);
""",
    """/**
 * @brief Return the callback-ctrl function installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Callback-ctrl function, or NULL if unset.
 */
long (*BIO_meth_get_callback_ctrl(const BIO_METHOD *biom))(BIO *, int, BIO_info_cb *);
""",
    "BIO_meth_get_callback_ctrl",
)

print(f"\nOK {len(ok)}, MISS {len(missing)}")
for m in missing:
    print(" ", m)
