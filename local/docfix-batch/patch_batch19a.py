#!/usr/bin/env python3
"""Documentation repair batch 19a: asn1.h ASN1_item_d2i + bio.h BIO_* symbols."""
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


print("=== batch 19a: asn1 + bio ===")

# ----- asn1.h -----

patch_both(
    "asn1.h",
    """ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in,
    long len, const ASN1_ITEM *it);
""",
    """/**
 * @brief Decode a DER-encoded ASN.1 value using an item descriptor (default library context).
 * @param val Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @param it ASN.1 item descriptor for the type to decode.
 * @return Decoded ASN1_VALUE, or NULL on error.
 *
 * Equivalent to ASN1_item_d2i_ex() with a NULL library context and property query.
 */
ASN1_VALUE *ASN1_item_d2i(ASN1_VALUE **val, const unsigned char **in,
    long len, const ASN1_ITEM *it);
""",
    "ASN1_item_d2i",
)

# ----- bio.h -----

patch_both(
    "bio.h",
    """int BIO_free(BIO *a);
""",
    """/**
 * @brief Free a single BIO (does not free BIOs linked after it in a chain).
 * @param a BIO to free; NULL is ignored.
 * @return 1 on success, or 0 on failure.
 *
 * To free an entire chain, use BIO_free_all() / BIO_vfree().
 */
int BIO_free(BIO *a);
""",
    "BIO_free",
)

patch_both(
    "bio.h",
    """int BIO_get_shutdown(BIO *a);
""",
    """/**
 * @brief Return whether BIO_free() will close the underlying I/O resource.
 * @param a BIO to query.
 * @return Non-zero if the underlying descriptor/handle is closed on free; 0 otherwise.
 */
int BIO_get_shutdown(BIO *a);
""",
    "BIO_get_shutdown",
)

patch_both(
    "bio.h",
    """__owur int BIO_sendmmsg(BIO *b, BIO_MSG *msg,
    size_t stride, size_t num_msg, uint64_t flags,
    size_t *msgs_processed);
""",
    """/**
 * @brief Send multiple messages through a BIO (sendmmsg-style interface).
 * @param b Destination BIO supporting multi-message send.
 * @param msg Array (or strided sequence) of BIO_MSG descriptors to send.
 * @param stride Byte stride between consecutive BIO_MSG elements (usually sizeof(BIO_MSG)).
 * @param num_msg Number of messages in the @p msg sequence.
 * @param flags Operation flags passed to the BIO method implementation.
 * @param msgs_processed Receives how many messages were successfully processed, or NULL.
 * @return 1 on success, or 0 on failure (see BIO_should_retry).
 */
__owur int BIO_sendmmsg(BIO *b, BIO_MSG *msg,
    size_t stride, size_t num_msg, uint64_t flags,
    size_t *msgs_processed);
""",
    "BIO_sendmmsg",
)

patch_both(
    "bio.h",
    """void BIO_set_retry_reason(BIO *bio, int reason);
""",
    """/**
 * @brief Store a BIO_RR_* retry reason on a BIO (used by BIO methods after special I/O).
 * @param bio BIO that requested a special retry condition.
 * @param reason Retry reason code (for example BIO_RR_CONNECT).
 */
void BIO_set_retry_reason(BIO *bio, int reason);
""",
    "BIO_set_retry_reason",
)

patch_both(
    "bio.h",
    """int BIO_nwrite0(BIO *bio, char **buf);
""",
    """/**
 * @brief Obtain a writable buffer from a memory BIO without advancing the write pointer.
 * @param bio Memory BIO to write into.
 * @param buf Receives a pointer into the BIO's internal buffer (valid until the next modify).
 * @return Number of bytes available at *@p buf, or a negative value on error.
 *
 * Call BIO_nwrite() afterward to commit written bytes, or use BIO_nwrite() directly.
 */
int BIO_nwrite0(BIO *bio, char **buf);
""",
    "BIO_nwrite0",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_mem(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a memory (RAM buffer) source/sink BIO.
 * @return Pointer to the static memory BIO method for use with BIO_new().
 */
const BIO_METHOD *BIO_s_mem(void);
""",
    "BIO_s_mem",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_socket(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a socket source/sink BIO.
 * @return Pointer to the static socket BIO method for use with BIO_new().
 */
const BIO_METHOD *BIO_s_socket(void);
""",
    "BIO_s_socket",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_fd(void);
const BIO_METHOD *BIO_s_log(void);
const BIO_METHOD *BIO_s_bio(void);
const BIO_METHOD *BIO_s_null(void);
const BIO_METHOD *BIO_f_null(void);
const BIO_METHOD *BIO_f_buffer(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a file-descriptor source/sink BIO.
 * @return Pointer to the static fd BIO method for use with BIO_new().
 */
const BIO_METHOD *BIO_s_fd(void);
/**
 * @brief Return the BIO_METHOD for a logging sink BIO (writes to the system log).
 * @return Pointer to the static log BIO method for use with BIO_new().
 */
const BIO_METHOD *BIO_s_log(void);
/**
 * @brief Return the BIO_METHOD for a BIO-pair endpoint (in-memory pipe half).
 * @return Pointer to the static bio-pair method for use with BIO_new() / BIO_new_bio_pair().
 */
const BIO_METHOD *BIO_s_bio(void);
/**
 * @brief Return the BIO_METHOD for a null source/sink that discards writes and returns EOF on reads.
 * @return Pointer to the static null BIO method for use with BIO_new().
 */
const BIO_METHOD *BIO_s_null(void);
const BIO_METHOD *BIO_f_null(void);
/**
 * @brief Return the BIO filter method that buffers reads and writes to the next BIO.
 * @return Pointer to the buffer filter method used with BIO_new().
 */
const BIO_METHOD *BIO_f_buffer(void);
""",
    "BIO_s_fd/log/bio/null+BIO_f_buffer",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_f_nbio_test(void);
const BIO_METHOD *BIO_f_prefix(void);
""",
    """/**
 * @brief Return the BIO filter method that randomly injects non-blocking retry conditions (test aid).
 * @return Pointer to the nbio-test filter method used with BIO_new().
 */
const BIO_METHOD *BIO_f_nbio_test(void);
/**
 * @brief Return the BIO filter method that prefixes each output line with a configurable string.
 * @return Pointer to the prefix filter method used with BIO_new().
 */
const BIO_METHOD *BIO_f_prefix(void);
""",
    "BIO_f_nbio_test+BIO_f_prefix",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_s_dgram_pair(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a datagram BIO-pair endpoint (in-memory UDP-style pipe half).
 * @return Pointer to the static dgram-pair method for use with BIO_new() / BIO_new_bio_dgram_pair().
 */
const BIO_METHOD *BIO_s_dgram_pair(void);
""",
    "BIO_s_dgram_pair",
)

patch_both(
    "bio.h",
    """int BIO_fd_non_fatal_error(int error);
""",
    """/**
 * @brief Report whether a file-descriptor errno is a non-fatal retryable I/O condition.
 * @param error Error code such as a value from errno.
 * @return 1 if the error is considered non-fatal for fd BIO I/O, or 0 otherwise.
 */
int BIO_fd_non_fatal_error(int error);
""",
    "BIO_fd_non_fatal_error",
)

patch_both(
    "bio.h",
    """int BIO_dump_cb(int (*cb)(const void *data, size_t len, void *u),
    void *u, const void *s, int len);
int BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
    void *u, const void *s, int len, int indent);
""",
    """/**
 * @brief Hex-dump @p len bytes at @p s by invoking @p cb for each formatted chunk.
 * @param cb Callback receiving dump text; return <=0 to abort.
 * @param u Opaque user pointer forwarded to @p cb.
 * @param s Bytes to dump.
 * @param len Number of bytes at @p s.
 * @return 1 on success, or 0 on error / callback abort.
 */
int BIO_dump_cb(int (*cb)(const void *data, size_t len, void *u),
    void *u, const void *s, int len);
/**
 * @brief Hex-dump @p len bytes at @p s with leading indent, via callback output.
 * @param cb Callback receiving dump text; return <=0 to abort.
 * @param u Opaque user pointer forwarded to @p cb.
 * @param s Bytes to dump.
 * @param len Number of bytes at @p s.
 * @param indent Number of spaces to prefix each dump line.
 * @return 1 on success, or 0 on error / callback abort.
 */
int BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
    void *u, const void *s, int len, int indent);
""",
    "BIO_dump_cb+BIO_dump_indent_cb",
)

patch_both(
    "bio.h",
    """int BIO_dump_indent(BIO *b, const void *bytes, int len, int indent);
""",
    """/**
 * @brief Hex-dump @p len bytes at @p bytes to a BIO with leading indent.
 * @param b Destination BIO.
 * @param bytes Bytes to dump.
 * @param len Number of bytes at @p bytes.
 * @param indent Number of spaces to prefix each dump line.
 * @return 1 on success, or 0 on error.
 */
int BIO_dump_indent(BIO *b, const void *bytes, int len, int indent);
""",
    "BIO_dump_indent",
)

patch_both(
    "bio.h",
    """int BIO_dump_indent_fp(FILE *fp, const void *s, int len, int indent);
""",
    """/**
 * @brief Hex-dump @p len bytes at @p s to a stdio FILE with leading indent.
 * @param fp Output FILE.
 * @param s Bytes to dump.
 * @param len Number of bytes at @p s.
 * @param indent Number of spaces to prefix each dump line.
 * @return 1 on success, or 0 on error.
 */
int BIO_dump_indent_fp(FILE *fp, const void *s, int len, int indent);
""",
    "BIO_dump_indent_fp",
)

patch_both(
    "bio.h",
    """int BIO_hex_string(BIO *out, int indent, int width, const void *data,
    int datalen);
""",
    """/**
 * @brief Write @p datalen bytes from @p data as a colon-separated hex string to a BIO.
 * @param out Destination BIO.
 * @param indent Number of spaces to prefix the first line (and continuation lines as needed).
 * @param width Maximum number of hex octets per line before wrapping (0 for no wrap).
 * @param data Bytes to format.
 * @param datalen Number of bytes at @p data.
 * @return 1 on success, or 0 on error.
 */
int BIO_hex_string(BIO *out, int indent, int width, const void *data,
    int datalen);
""",
    "BIO_hex_string",
)

patch_both(
    "bio.h",
    """int BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src);
""",
    """/**
 * @brief Copy a BIO_ADDR value from @p src into @p dst.
 * @param dst Destination address object (must already be allocated).
 * @param src Source address to copy.
 * @return 1 on success, or 0 on failure.
 */
int BIO_ADDR_copy(BIO_ADDR *dst, const BIO_ADDR *src);
""",
    "BIO_ADDR_copy",
)

patch_both(
    "bio.h",
    """int BIO_ADDR_family(const BIO_ADDR *ap);
int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l);
unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap);
""",
    """/**
 * @brief Return the address family stored in a BIO_ADDR (for example AF_INET).
 * @param ap Address object to query.
 * @return Address family constant, or AF_UNSPEC if unset.
 */
int BIO_ADDR_family(const BIO_ADDR *ap);
/**
 * @brief Extract the raw network address bytes from a BIO_ADDR.
 * @param ap Address object to query.
 * @param p Destination buffer for the raw address, or NULL to query length only.
 * @param l On input, capacity of @p p when non-NULL; on output, required/written length.
 * @return 1 on success, or 0 on failure.
 */
int BIO_ADDR_rawaddress(const BIO_ADDR *ap, void *p, size_t *l);
/**
 * @brief Return the port number from a BIO_ADDR in host byte order.
 * @param ap Address object to query.
 * @return Port number, or 0 if unset / not applicable (for example AF_UNIX).
 */
unsigned short BIO_ADDR_rawport(const BIO_ADDR *ap);
""",
    "BIO_ADDR_family/rawaddress/rawport",
)

patch_both(
    "bio.h",
    """char *BIO_ADDR_path_string(const BIO_ADDR *ap);
""",
    """/**
 * @brief Return a newly allocated string for the filesystem path in a Unix-domain BIO_ADDR.
 * @param ap Address object to query (typically AF_UNIX).
 * @return Heap-allocated path string to free with OPENSSL_free(), or NULL on error / if unset.
 */
char *BIO_ADDR_path_string(const BIO_ADDR *ap);
""",
    "BIO_ADDR_path_string",
)

patch_both(
    "bio.h",
    """const BIO_ADDRINFO *BIO_ADDRINFO_next(const BIO_ADDRINFO *bai);
""",
    """/**
 * @brief Advance to the next node in a BIO_ADDRINFO linked list.
 * @param bai Current address-info node.
 * @return Next node, or NULL at the end of the list.
 */
const BIO_ADDRINFO *BIO_ADDRINFO_next(const BIO_ADDRINFO *bai);
""",
    "BIO_ADDRINFO_next",
)

patch_both(
    "bio.h",
    """const BIO_ADDR *BIO_ADDRINFO_address(const BIO_ADDRINFO *bai);
void BIO_ADDRINFO_free(BIO_ADDRINFO *bai);
""",
    """/**
 * @brief Return the BIO_ADDR carried by an address-info list node.
 * @param bai Address-info node from BIO_lookup() / BIO_lookup_ex().
 * @return Pointer to the embedded address (owned by @p bai; do not free separately).
 */
const BIO_ADDR *BIO_ADDRINFO_address(const BIO_ADDRINFO *bai);
/**
 * @brief Free a BIO_ADDRINFO list allocated by BIO_lookup() / BIO_lookup_ex().
 * @param bai Head of the list to free, or NULL (no-op).
 */
void BIO_ADDRINFO_free(BIO_ADDRINFO *bai);
""",
    "BIO_ADDRINFO_address+free",
)

patch_both(
    "bio.h",
    """enum BIO_hostserv_priorities {
    BIO_PARSE_PRIO_HOST,
    BIO_PARSE_PRIO_SERV
};
""",
    """/**
 * @brief How BIO_parse_hostserv() disambiguates host vs service in a combined string.
 */
enum BIO_hostserv_priorities {
    /** Prefer interpreting an ambiguous token as a hostname. */
    BIO_PARSE_PRIO_HOST,
    /** Prefer interpreting an ambiguous token as a service/port. */
    BIO_PARSE_PRIO_SERV
};
""",
    "BIO_hostserv_priorities",
)

patch_both(
    "bio.h",
    """int BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type,
    int family, int socktype, BIO_ADDRINFO **res);
""",
    """/**
 * @brief Resolve @p host / @p service into a BIO_ADDRINFO list.
 * @param host Hostname or address string to look up, or NULL for wildcard.
 * @param service Service name or port string, or NULL.
 * @param lookup_type BIO_LOOKUP_CLIENT or BIO_LOOKUP_SERVER.
 * @param family Address family (for example AF_INET, AF_INET6, or AF_UNSPEC).
 * @param socktype Socket type (for example SOCK_STREAM or SOCK_DGRAM).
 * @param res Receives the head of the allocated BIO_ADDRINFO list; free with BIO_ADDRINFO_free().
 * @return 1 on success, or 0 on failure.
 *
 * Prefer BIO_lookup_ex() when a specific protocol number is required.
 */
int BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type,
    int family, int socktype, BIO_ADDRINFO **res);
""",
    "BIO_lookup",
)

patch_both(
    "bio.h",
    """union BIO_sock_info_u {
    BIO_ADDR *addr;
};
""",
    """union BIO_sock_info_u {
    /** Local or peer address when type is BIO_SOCK_INFO_ADDRESS. */
    BIO_ADDR *addr;
};
""",
    "BIO_sock_info_u.addr",
)

patch_both(
    "bio.h",
    """int BIO_connect(int sock, const BIO_ADDR *addr, int options);
int BIO_bind(int sock, const BIO_ADDR *addr, int options);
""",
    """/**
 * @brief Connect socket @p sock to @p addr, applying BIO_SOCK_* @p options.
 * @param sock Socket file descriptor.
 * @param addr Destination address.
 * @param options Bitmask of BIO_SOCK_* flags (for example BIO_SOCK_NONBLOCK).
 * @return 1 on success, or 0 on failure.
 */
int BIO_connect(int sock, const BIO_ADDR *addr, int options);
/**
 * @brief Bind socket @p sock to @p addr, applying BIO_SOCK_* @p options.
 * @param sock Socket file descriptor.
 * @param addr Local address to bind.
 * @param options Bitmask of BIO_SOCK_* flags (for example BIO_SOCK_REUSEADDR).
 * @return 1 on success, or 0 on failure.
 */
int BIO_bind(int sock, const BIO_ADDR *addr, int options);
""",
    "BIO_connect+BIO_bind",
)

patch_both(
    "bio.h",
    """int BIO_closesocket(int sock);
""",
    """/**
 * @brief Close a socket descriptor with OpenSSL error reporting.
 * @param sock Socket file descriptor to close.
 * @return 1 on success, or 0 on failure.
 */
int BIO_closesocket(int sock);
""",
    "BIO_closesocket",
)

patch_both(
    "bio.h",
    """BIO *BIO_new_connect(const char *host_port);
""",
    """/**
 * @brief Create a BIO_s_connect() BIO configured for @p host_port.
 * @param host_port Host:port string describing the peer to connect to.
 * @return New connect BIO, or NULL on error; free with BIO_free().
 */
BIO *BIO_new_connect(const char *host_port);
""",
    "BIO_new_connect",
)

patch_both(
    "bio.h",
    """int BIO_snprintf(char *buf, size_t n, const char *format, ...)
    ossl_bio__attr__((__format__(ossl_bio__printf__, 3, 4)));
""",
    """/**
 * @brief Bounded snprintf-style formatting into @p buf (NUL-terminated when @p n > 0).
 * @param buf Destination buffer.
 * @param n Capacity of @p buf in bytes.
 * @param format printf-style format string.
 * @return Number of characters that would have been written (excluding NUL), or a negative value on error.
 */
int BIO_snprintf(char *buf, size_t n, const char *format, ...)
    ossl_bio__attr__((__format__(ossl_bio__printf__, 3, 4)));
""",
    "BIO_snprintf",
)

patch_both(
    "bio.h",
    """BIO_METHOD *BIO_meth_new(int type, const char *name);
""",
    """/**
 * @brief Allocate a new custom BIO_METHOD with the given type index and name.
 * @param type BIO type index (often from BIO_get_new_index(), combined with BIO_TYPE_* flags).
 * @param name Human-readable method name stored on the BIO_METHOD.
 * @return New method table, or NULL on allocation failure; free with BIO_meth_free().
 */
BIO_METHOD *BIO_meth_new(int type, const char *name);
""",
    "BIO_meth_new",
)

patch_both(
    "bio.h",
    """int (*BIO_meth_get_write(const BIO_METHOD *biom))(BIO *, const char *, int);
""",
    """/**
 * @brief Return the legacy write function installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Write callback, or NULL if unset.
 */
int (*BIO_meth_get_write(const BIO_METHOD *biom))(BIO *, const char *, int);
""",
    "BIO_meth_get_write",
)

patch_both(
    "bio.h",
    """int BIO_meth_set_write(BIO_METHOD *biom,
    int (*write)(BIO *, const char *, int));
""",
    """/**
 * @brief Install the legacy write callback on a BIO_METHOD.
 * @param biom Method table to update.
 * @param write Callback implementing BIO_write()-style output.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_write(BIO_METHOD *biom,
    int (*write)(BIO *, const char *, int));
""",
    "BIO_meth_set_write",
)

patch_both(
    "bio.h",
    """int (*BIO_meth_get_sendmmsg(const BIO_METHOD *biom))(BIO *, BIO_MSG *,
    size_t, size_t,
    uint64_t, size_t *);
""",
    """/**
 * @brief Return the multi-message send callback installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return sendmmsg-style callback, or NULL if unset.
 */
int (*BIO_meth_get_sendmmsg(const BIO_METHOD *biom))(BIO *, BIO_MSG *,
    size_t, size_t,
    uint64_t, size_t *);
""",
    "BIO_meth_get_sendmmsg",
)

patch_both(
    "bio.h",
    """int (*BIO_meth_get_read(const BIO_METHOD *biom))(BIO *, char *, int);
int (*BIO_meth_get_read_ex(const BIO_METHOD *biom))(BIO *, char *, size_t, size_t *);
int BIO_meth_set_read(BIO_METHOD *biom,
    int (*read)(BIO *, char *, int));
int BIO_meth_set_read_ex(BIO_METHOD *biom,
    int (*bread)(BIO *, char *, size_t, size_t *));
""",
    """/**
 * @brief Return the legacy read function installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Read callback, or NULL if unset.
 */
int (*BIO_meth_get_read(const BIO_METHOD *biom))(BIO *, char *, int);
/**
 * @brief Return the extended read function installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Read-ex callback, or NULL if unset.
 */
int (*BIO_meth_get_read_ex(const BIO_METHOD *biom))(BIO *, char *, size_t, size_t *);
/**
 * @brief Install the legacy read callback on a BIO_METHOD.
 * @param biom Method table to update.
 * @param read Callback implementing BIO_read()-style input.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_read(BIO_METHOD *biom,
    int (*read)(BIO *, char *, int));
/**
 * @brief Install the extended read callback on a BIO_METHOD.
 * @param biom Method table to update.
 * @param bread Callback implementing BIO_read_ex()-style input.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_read_ex(BIO_METHOD *biom,
    int (*bread)(BIO *, char *, size_t, size_t *));
""",
    "BIO_meth_get/set_read(+_ex)",
)

patch_both(
    "bio.h",
    """int (*BIO_meth_get_recvmmsg(const BIO_METHOD *biom))(BIO *, BIO_MSG *,
    size_t, size_t,
    uint64_t, size_t *);
""",
    """/**
 * @brief Return the multi-message receive callback installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return recvmmsg-style callback, or NULL if unset.
 */
int (*BIO_meth_get_recvmmsg(const BIO_METHOD *biom))(BIO *, BIO_MSG *,
    size_t, size_t,
    uint64_t, size_t *);
""",
    "BIO_meth_get_recvmmsg",
)

patch_both(
    "bio.h",
    """int BIO_meth_set_puts(BIO_METHOD *biom,
    int (*puts)(BIO *, const char *));
int (*BIO_meth_get_gets(const BIO_METHOD *biom))(BIO *, char *, int);
int BIO_meth_set_gets(BIO_METHOD *biom,
    int (*ossl_gets)(BIO *, char *, int));
""",
    """/**
 * @brief Install the puts callback on a BIO_METHOD.
 * @param biom Method table to update.
 * @param puts Callback implementing BIO_puts()-style string output.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_puts(BIO_METHOD *biom,
    int (*puts)(BIO *, const char *));
/**
 * @brief Return the gets function installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Gets callback, or NULL if unset.
 */
int (*BIO_meth_get_gets(const BIO_METHOD *biom))(BIO *, char *, int);
/**
 * @brief Install the gets callback on a BIO_METHOD.
 * @param biom Method table to update.
 * @param ossl_gets Callback implementing BIO_gets()-style line input.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_gets(BIO_METHOD *biom,
    int (*ossl_gets)(BIO *, char *, int));
""",
    "BIO_meth_set_puts+get/set_gets",
)

patch_both(
    "bio.h",
    """int BIO_meth_set_ctrl(BIO_METHOD *biom,
    long (*ctrl)(BIO *, int, long, void *));
""",
    """/**
 * @brief Install the ctrl callback on a BIO_METHOD.
 * @param biom Method table to update.
 * @param ctrl Callback implementing BIO_ctrl()-style commands.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_ctrl(BIO_METHOD *biom,
    long (*ctrl)(BIO *, int, long, void *));
""",
    "BIO_meth_set_ctrl",
)

patch_both(
    "bio.h",
    """int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *));
int (*BIO_meth_get_destroy(const BIO_METHOD *biom))(BIO *);
""",
    """/**
 * @brief Install the create callback invoked when a BIO of this method is allocated.
 * @param biom Method being configured.
 * @param create Callback that initializes method-specific state for a BIO; may be NULL.
 * @return 1 on success, or 0 on failure.
 */
int BIO_meth_set_create(BIO_METHOD *biom, int (*create)(BIO *));
/**
 * @brief Return the destroy callback installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Destroy callback, or NULL if unset.
 */
int (*BIO_meth_get_destroy(const BIO_METHOD *biom))(BIO *);
""",
    "BIO_meth_set_create+get_destroy",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
