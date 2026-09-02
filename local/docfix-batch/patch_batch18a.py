#!/usr/bin/env python3
"""Documentation repair batch 18a: asn1.h + bio.h."""
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


print("=== batch 18a: asn1 + bio ===")

# ----- asn1.h -----

patch_both(
    "asn1.h",
    """struct asn1_string_table_st {
    int nid;
    long minsize;
""",
    """struct asn1_string_table_st {
    /** Numeric identifier (NID_*) this table entry constrains. */
    int nid;
    /** Minimum allowed string size in characters for this NID (-1 = no minimum). */
    long minsize;
""",
    "asn1_string_table_st nid/minsize",
)

patch_both(
    "asn1.h",
    """struct asn1_type_st {
    int type;
""",
    """struct asn1_type_st {
    /** Active ASN.1 type tag (V_ASN1_*) selecting which union arm is valid. */
    int type;
""",
    "asn1_type_st.type",
)

patch_both(
    "asn1.h",
    """        ASN1_IA5STRING *ia5string;
        ASN1_GENERALSTRING *generalstring;
""",
    """        ASN1_IA5STRING *ia5string;
        /** GeneralString value when type is V_ASN1_GENERALSTRING. */
        ASN1_GENERALSTRING *generalstring;
""",
    "generalstring",
)

patch_both(
    "asn1.h",
    """int ASN1_TYPE_get(const ASN1_TYPE *a);
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
""",
    """int ASN1_TYPE_get(const ASN1_TYPE *a);
/**
 * @brief Set an ASN1_TYPE to @p type, taking ownership of @p value (no copy).
 * @param a Destination ANY/CHOICE container to update.
 * @param type ASN.1 type tag (V_ASN1_*); for V_ASN1_BOOLEAN, @p value may be NULL to mean FALSE.
 * @param value Pointer to the typed value transferred into @p a, or NULL where the type allows it.
 */
void ASN1_TYPE_set(ASN1_TYPE *a, int type, void *value);
""",
    "ASN1_TYPE_set",
)

patch_both(
    "asn1.h",
    """int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b);

ASN1_TYPE *ASN1_TYPE_pack_sequence(const ASN1_ITEM *it, void *s, ASN1_TYPE **t);
""",
    """int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b);

/**
 * @brief Encode a typed structure as a SEQUENCE and store it in an ASN1_TYPE.
 * @param it ASN.1 item describing the SEQUENCE type of @p s.
 * @param s Structure instance to encode (type implied by @p it).
 * @param t Optional destination ASN1_TYPE pointer; when non-NULL, *@p t is reused or allocated.
 * @return ASN1_TYPE holding the packed SEQUENCE, or NULL on error.
 */
ASN1_TYPE *ASN1_TYPE_pack_sequence(const ASN1_ITEM *it, void *s, ASN1_TYPE **t);
""",
    "ASN1_TYPE_pack_sequence",
)

patch_both(
    "asn1.h",
    """ASN1_STRING *ASN1_STRING_type_new(int type);
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);
""",
    """ASN1_STRING *ASN1_STRING_type_new(int type);
/**
 * @brief Compare two ASN1_STRING values by type and content octets.
 * @param a First string.
 * @param b Second string.
 * @return Negative, zero, or positive like memcmp(), considering type then data.
 */
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);
""",
    "ASN1_STRING_cmp",
)

patch_both(
    "asn1.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(ASN1_UTF8STRING, ASN1_UTF8STRING, ASN1_UTF8STRING)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ASN1_UTF8STRING) container type.
 */
struct stack_st_ASN1_UTF8STRING;
SKM_DEFINE_STACK_OF_INTERNAL(ASN1_UTF8STRING, ASN1_UTF8STRING, ASN1_UTF8STRING)
""",
    "stack_st_ASN1_UTF8STRING",
)

patch_both(
    "asn1.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(ASN1_GENERALSTRING, ASN1_GENERALSTRING, ASN1_GENERALSTRING)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ASN1_GENERALSTRING) container type.
 */
struct stack_st_ASN1_GENERALSTRING;
SKM_DEFINE_STACK_OF_INTERNAL(ASN1_GENERALSTRING, ASN1_GENERALSTRING, ASN1_GENERALSTRING)
""",
    "stack_st_ASN1_GENERALSTRING",
)

patch_both(
    "asn1.h",
    """ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t);
""",
    """/**
 * @brief Set an ASN.1 Time to the given POSIX time (UTCTime or GeneralizedTime).
 * @param s Existing ASN1_TIME to reuse, or NULL to allocate.
 * @param t POSIX time to store.
 * @return The updated or newly allocated ASN1_TIME, or NULL on error.
 */
ASN1_TIME *ASN1_TIME_set(ASN1_TIME *s, time_t t);
""",
    "ASN1_TIME_set",
)

patch_both(
    "asn1.h",
    """int i2t_ASN1_OBJECT(char *buf, int buf_len, const ASN1_OBJECT *a);
""",
    """/**
 * @brief Format an ASN.1 OBJECT IDENTIFIER into a textual OID name or dotted decimal form.
 * @param buf Destination buffer for the NUL-terminated text, or NULL to measure length only.
 * @param buf_len Capacity of @p buf in bytes when @p buf is non-NULL.
 * @param a Object identifier to format.
 * @return Number of characters written (excluding NUL), or the required length when @p buf is NULL.
 */
int i2t_ASN1_OBJECT(char *buf, int buf_len, const ASN1_OBJECT *a);
""",
    "i2t_ASN1_OBJECT",
)

patch_both(
    "asn1.h",
    """int ASN1_check_infinite_end(unsigned char **p, long len);
""",
    """/**
 * @brief Check for an indefinite-length end-of-contents (EOC) marker without consuming it.
 * @param p Address of the input cursor pointing at candidate EOC octets.
 * @param len Remaining bytes available at *@p p.
 * @return Non-zero if an EOC is present (or @p len indicates end), or 0 otherwise.
 */
int ASN1_check_infinite_end(unsigned char **p, long len);
""",
    "ASN1_check_infinite_end",
)

patch_both(
    "asn1.h",
    """int ASN1_object_size(int constructed, int length, int tag);
""",
    """/**
 * @brief Compute the total DER size of a tagged ASN.1 value given its content length.
 * @param constructed Non-zero if the encoding uses a constructed form.
 * @param length Number of content octets (or -1 for indefinite length).
 * @param tag Tag number to encode (universal/application/context-specific as used by callers).
 * @return Total number of octets for tag, length, and content, or a negative value on error.
 */
int ASN1_object_size(int constructed, int length, int tag);
""",
    "ASN1_object_size",
)

patch_both(
    "asn1.h",
    """int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, const void *x);
""",
    """/**
 * @brief Encode an ASN.1 item to DER and write the encoding to a FILE stream.
 * @param it ASN.1 item descriptor for the type of @p x.
 * @param out Output stream that receives the DER encoding.
 * @param x Value to encode (type implied by @p it).
 * @return 1 on success, or 0 on failure.
 */
int ASN1_item_i2d_fp(const ASN1_ITEM *it, FILE *out, const void *x);
""",
    "ASN1_item_i2d_fp",
)

patch_both(
    "asn1.h",
    """int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a);
""",
    """/**
 * @brief Print an ASN.1 GeneralizedTime to a BIO in a human-readable form.
 * @param fp BIO that receives the formatted timestamp text.
 * @param a GeneralizedTime value to print.
 * @return 1 on success, or 0 on error.
 */
int ASN1_GENERALIZEDTIME_print(BIO *fp, const ASN1_GENERALIZEDTIME *a);
""",
    "ASN1_GENERALIZEDTIME_print",
)

patch_both(
    "asn1.h",
    """unsigned long ASN1_PCTX_get_flags(const ASN1_PCTX *p);
""",
    """/**
 * @brief Return the general ASN1_PCTX_FLAGS_* print-control flags from a print context.
 * @param p Print context to query.
 * @return Current flag mask.
 */
unsigned long ASN1_PCTX_get_flags(const ASN1_PCTX *p);
""",
    "ASN1_PCTX_get_flags",
)

patch_both(
    "asn1.h",
    """unsigned long ASN1_PCTX_get_nm_flags(const ASN1_PCTX *p);
""",
    """/**
 * @brief Return the name-printing flags from an ASN.1 print context.
 * @param p Print context to query.
 * @return XN_FLAG_* / ASN1_STRFLGS_* mask controlling how names are rendered.
 */
unsigned long ASN1_PCTX_get_nm_flags(const ASN1_PCTX *p);
""",
    "ASN1_PCTX_get_nm_flags",
)

patch_both(
    "asn1.h",
    """unsigned long ASN1_PCTX_get_str_flags(const ASN1_PCTX *p);
""",
    """/**
 * @brief Return the ASN1_STRFLGS_* flags controlling how string fields are printed.
 * @param p Print context to query.
 * @return String print flags (same family as ASN1_STRING_print_ex).
 */
unsigned long ASN1_PCTX_get_str_flags(const ASN1_PCTX *p);
""",
    "ASN1_PCTX_get_str_flags",
)

# ----- bio.h -----

patch_both(
    "bio.h",
    """int BIO_get_new_index(void);
""",
    """/**
 * @brief Allocate a new unique BIO type index for a custom BIO_METHOD.
 * @return New type index in the BIO_TYPE_START range, or a negative value on failure.
 */
int BIO_get_new_index(void);
""",
    "BIO_get_new_index",
)

patch_both(
    "bio.h",
    """int BIO_set_ex_data(BIO *bio, int idx, void *data);
void *BIO_get_ex_data(const BIO *bio, int idx);
""",
    """/**
 * @brief Store application-specific data on a BIO at the given ex_data index.
 * @param bio BIO that owns the ex_data table.
 * @param idx Index obtained from BIO_get_ex_new_index() (or 0 for app data).
 * @param data Pointer to store; ownership and lifetime are caller-defined.
 * @return 1 on success, or 0 on failure.
 */
int BIO_set_ex_data(BIO *bio, int idx, void *data);
void *BIO_get_ex_data(const BIO *bio, int idx);
""",
    "BIO_set_ex_data",
)

patch_both(
    "bio.h",
    """BIO *BIO_find_type(BIO *b, int bio_type);
BIO *BIO_next(BIO *b);
""",
    """BIO *BIO_find_type(BIO *b, int bio_type);
/**
 * @brief Return the next BIO in a filter chain after @p b.
 * @param b BIO whose successor is requested.
 * @return Next BIO in the chain, or NULL if @p b is the last / has no next.
 */
BIO *BIO_next(BIO *b);
""",
    "BIO_next",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_f_linebuffer(void);
""",
    """/**
 * @brief Return the BIO_METHOD for a line-buffering filter BIO.
 * @return Pointer to the static linebuffer filter method.
 */
const BIO_METHOD *BIO_f_linebuffer(void);
""",
    "BIO_f_linebuffer",
)

patch_both(
    "bio.h",
    """BIO *BIO_new_dgram(int fd, int close_flag);
""",
    """/**
 * @brief Create a datagram (UDP-style) BIO wrapping an existing socket descriptor.
 * @param fd Socket file descriptor to wrap.
 * @param close_flag BIO_CLOSE to close @p fd on BIO_free(), or BIO_NOCLOSE.
 * @return Newly allocated datagram BIO, or NULL on failure.
 */
BIO *BIO_new_dgram(int fd, int close_flag);
""",
    "BIO_new_dgram",
)

patch_both(
    "bio.h",
    """int BIO_wait(BIO *bio, time_t max_time, unsigned int nap_milliseconds);
""",
    """/**
 * @brief Wait until a BIO is ready for I/O or until @p max_time elapses.
 * @param bio BIO to poll (typically a socket or non-blocking I/O BIO).
 * @param max_time Absolute deadline as a time_t (0 means wait indefinitely where supported).
 * @param nap_milliseconds Sleep quantum between polls when the BIO has no native wait.
 * @return 1 when ready, 0 on timeout, or a negative value on error.
 */
int BIO_wait(BIO *bio, time_t max_time, unsigned int nap_milliseconds);
""",
    "BIO_wait",
)

patch_both(
    "bio.h",
    """int BIO_lookup_ex(const char *host, const char *service,
    int lookup_type, int family, int socktype, int protocol,
    BIO_ADDRINFO **res);
int BIO_sock_error(int sock);
""",
    """/**
 * @brief Resolve @p host / @p service into a BIO_ADDRINFO list with protocol selection.
 * @param host Hostname or address string to look up, or NULL for wildcard.
 * @param service Service name or port string, or NULL.
 * @param lookup_type BIO_LOOKUP_CLIENT or BIO_LOOKUP_SERVER.
 * @param family Address family (for example AF_INET, AF_INET6, or AF_UNSPEC).
 * @param socktype Socket type (for example SOCK_STREAM or SOCK_DGRAM).
 * @param protocol Protocol number (for example IPPROTO_TCP), or 0 for default.
 * @param res Receives the head of the allocated BIO_ADDRINFO list; free with BIO_ADDRINFO_free().
 * @return 1 on success, or 0 on failure.
 */
int BIO_lookup_ex(const char *host, const char *service,
    int lookup_type, int family, int socktype, int protocol,
    BIO_ADDRINFO **res);
/**
 * @brief Return the pending socket error for @p sock (clears SO_ERROR).
 * @param sock Socket file descriptor.
 * @return Pending errno-style error code, or 0 if none.
 */
int BIO_sock_error(int sock);
""",
    "BIO_lookup_ex+BIO_sock_error",
)

patch_both(
    "bio.h",
    """BIO *BIO_new_fd(int fd, int close_flag);
""",
    """/**
 * @brief Create a file-descriptor BIO wrapping an existing OS descriptor.
 * @param fd File descriptor to wrap.
 * @param close_flag BIO_CLOSE to close @p fd on BIO_free(), or BIO_NOCLOSE.
 * @return Newly allocated fd BIO, or NULL on failure.
 */
BIO *BIO_new_fd(int fd, int close_flag);
""",
    "BIO_new_fd",
)

patch_both(
    "bio.h",
    """int BIO_printf(BIO *bio, const char *format, ...)
    ossl_bio__attr__((__format__(ossl_bio__printf__, 2, 3)));
""",
    """/**
 * @brief Formatted print to a BIO, analogous to fprintf().
 * @param bio Destination BIO.
 * @param format printf-style format string.
 * @return Number of bytes written, or a negative value on error.
 */
int BIO_printf(BIO *bio, const char *format, ...)
    ossl_bio__attr__((__format__(ossl_bio__printf__, 2, 3)));
""",
    "BIO_printf",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
