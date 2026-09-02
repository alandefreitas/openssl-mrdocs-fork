#!/usr/bin/env python3
"""Documentation repair batch 17a: asn1, async, bio."""
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


print("=== batch 17a: asn1, async, bio ===")

# ----- asn1.h / asn1.h.in -----

patch_both(
    "asn1.h",
    """        ASN1_ENUMERATED *enumerated;
        ASN1_BIT_STRING *bit_string;
        /** OCTET STRING value when type is V_ASN1_OCTET_STRING. */
""",
    """        ASN1_ENUMERATED *enumerated;
        /** BIT STRING value when type is V_ASN1_BIT_STRING. */
        ASN1_BIT_STRING *bit_string;
        /** OCTET STRING value when type is V_ASN1_OCTET_STRING. */
""",
    "bit_string",
)

patch_both(
    "asn1.h",
    """        ASN1_OCTET_STRING *octet_string;
        ASN1_PRINTABLESTRING *printablestring;
        /** TeletexString / T61String value when type is V_ASN1_T61STRING. */
""",
    """        ASN1_OCTET_STRING *octet_string;
        /** PrintableString value when type is V_ASN1_PRINTABLESTRING. */
        ASN1_PRINTABLESTRING *printablestring;
        /** TeletexString / T61String value when type is V_ASN1_T61STRING. */
""",
    "printablestring",
)

patch_both(
    "asn1.h",
    """int ASN1_TYPE_get(const ASN1_TYPE *a);
""",
    """/**
 * @brief Return the type tag stored in an ASN1_TYPE, or 0 if unset or empty.
 * @param a ANY value to query.
 * @return V_ASN1_* type constant, or 0 when no value is present.
 */
int ASN1_TYPE_get(const ASN1_TYPE *a);
""",
    "ASN1_TYPE_get",
)

patch_both(
    "asn1.h",
    """ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
    time_t t);
""",
    """/**
 * @brief Set an ASN1_GENERALIZEDTIME to the calendar time @p t (allocating when @p s is NULL).
 * @param s Existing GeneralizedTime to reuse, or NULL to allocate a new one.
 * @param t POSIX time (seconds since the Epoch).
 * @return The GeneralizedTime on success (possibly newly allocated), or NULL on error.
 */
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
    time_t t);
""",
    "ASN1_GENERALIZEDTIME_set",
)

patch_both(
    "asn1.h",
    """int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);
""",
    """/**
 * @brief Set an ASN1_GENERALIZEDTIME from an ASN.1 GeneralizedTime string (or only validate when @p s is NULL).
 * @param s Destination GeneralizedTime, or NULL to format-check @p str only.
 * @param str NUL-terminated GeneralizedTime string such as YYYYMMDDHHMMSSZ.
 * @return 1 on success, or 0 if the string is not a valid GeneralizedTime.
 */
int ASN1_GENERALIZEDTIME_set_string(ASN1_GENERALIZEDTIME *s, const char *str);
""",
    "ASN1_GENERALIZEDTIME_set_string",
)

patch_both(
    "asn1.h",
    """int a2i_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *bs, char *buf, int size);
""",
    """/**
 * @brief Read a colon-separated hex ENUMERATED from @p bp into @p bs (PEM helper).
 * @param bp Input BIO supplying ASCII hex digits (and optional colon separators).
 * @param bs Destination ENUMERATED updated with the parsed value.
 * @param buf Scratch buffer of length @p size used while reading lines.
 * @param size Capacity of @p buf in bytes.
 * @return 1 on success, or 0 on parse/I/O error.
 */
int a2i_ASN1_ENUMERATED(BIO *bp, ASN1_ENUMERATED *bs, char *buf, int size);
""",
    "a2i_ASN1_ENUMERATED",
)

patch_both(
    "asn1.h",
    """int a2i_ASN1_STRING(BIO *bp, ASN1_STRING *bs, char *buf, int size);
""",
    """/**
 * @brief Read a colon-separated hex ASN.1 string from @p bp into @p bs (PEM helper).
 * @param bp Input BIO supplying ASCII hex digits (and optional colon separators).
 * @param bs Destination ASN1_STRING updated with the parsed octets.
 * @param buf Scratch buffer of length @p size used while reading lines.
 * @param size Capacity of @p buf in bytes.
 * @return 1 on success, or 0 on parse/I/O error.
 */
int a2i_ASN1_STRING(BIO *bp, ASN1_STRING *bs, char *buf, int size);
""",
    "a2i_ASN1_STRING",
)

patch_both(
    "asn1.h",
    """ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data, int len,
    const char *sn, const char *ln);
""",
    """/**
 * @brief Allocate a dynamically owned ASN1_OBJECT from DER content and optional names.
 * @param nid NID to assign (or NID_undef for an unnamed object).
 * @param data DER OID content octets (ownership transferred to the object on success).
 * @param len Length of @p data in bytes.
 * @param sn Optional short name string (ownership transferred), or NULL.
 * @param ln Optional long name string (ownership transferred), or NULL.
 * @return New ASN1_OBJECT, or NULL on error.
 */
ASN1_OBJECT *ASN1_OBJECT_create(int nid, unsigned char *data, int len,
    const char *sn, const char *ln);
""",
    "ASN1_OBJECT_create",
)

patch_both(
    "asn1.h",
    """const ASN1_TEMPLATE *ASN1_SCTX_get_template(ASN1_SCTX *p);
""",
    """/**
 * @brief Return the ASN1_TEMPLATE currently being scanned by an ASN.1 scan context.
 * @param p Scan context created for a custom ASN.1 item scan/callback.
 * @return Template associated with @p p, or NULL if none is set.
 */
const ASN1_TEMPLATE *ASN1_SCTX_get_template(ASN1_SCTX *p);
""",
    "ASN1_SCTX_get_template",
)

patch_both(
    "asn1.h",
    """unsigned long ASN1_SCTX_get_flags(ASN1_SCTX *p);
""",
    """/**
 * @brief Return scan flags for the current field in an ASN.1 scan context.
 * @param p Scan context to query.
 * @return Flag word stored on @p p (ASN1_SCAN_* and related bits).
 */
unsigned long ASN1_SCTX_get_flags(ASN1_SCTX *p);
""",
    "ASN1_SCTX_get_flags",
)

# ----- async.h -----

patch_one(
    "async.h",
    """int ASYNC_WAIT_CTX_get_changed_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *addfd,
    size_t *numaddfds, OSSL_ASYNC_FD *delfd,
    size_t *numdelfds);
""",
    """/**
 * @brief Retrieve file descriptors added to or removed from a wait context since the last poll.
 * @param ctx Wait context to query.
 * @param addfd Array that receives fds to add to the poll set (may be NULL to skip copying).
 * @param numaddfds On entry, capacity of @p addfd; on exit, number of fds to add.
 * @param delfd Array that receives fds to remove from the poll set (may be NULL to skip copying).
 * @param numdelfds On entry, capacity of @p delfd; on exit, number of fds to remove.
 * @return 1 on success.
 */
int ASYNC_WAIT_CTX_get_changed_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *addfd,
    size_t *numaddfds, OSSL_ASYNC_FD *delfd,
    size_t *numdelfds);
""",
    "ASYNC_WAIT_CTX_get_changed_fds",
)

# ----- bio.h / bio.h.in -----

patch_both(
    "bio.h",
    """typedef union bio_addr_st BIO_ADDR;
""",
    """/**
 * @brief Opaque socket address union used by BIO socket and datagram APIs.
 */
typedef union bio_addr_st BIO_ADDR;
""",
    "BIO_ADDR",
)

patch_both(
    "bio.h",
    """void BIO_clear_flags(BIO *b, int flags);
""",
    """/**
 * @brief Clear the given BIO_FLAGS_* bits from a BIO.
 * @param b BIO whose flags are updated.
 * @param flags Bitmask of BIO_FLAGS_* values to clear.
 */
void BIO_clear_flags(BIO *b, int flags);
""",
    "BIO_clear_flags",
)

patch_both(
    "bio.h",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
typedef long (*BIO_callback_fn)(BIO *b, int oper, const char *argp, int argi,
    long argl, long ret);
""",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Legacy BIO callback invoked immediately before and after I/O operations (deprecated).
 * @param b BIO performing the operation.
 * @param oper BIO_CB_* operation code OR'd with BIO_CB_RETURN after the call.
 * @param argp Pointer argument (buffer or ctrl pointer), or NULL.
 * @param argi Integer argument for ctrl-style operations.
 * @param argl Long argument for ctrl-style operations.
 * @param ret Return value from the underlying operation (post-call only).
 * @return Post-call return value (usually @p ret unchanged).
 */
typedef long (*BIO_callback_fn)(BIO *b, int oper, const char *argp, int argi,
    long argl, long ret);
""",
    "BIO_callback_fn",
)

patch_both(
    "bio.h",
    """OSSL_DEPRECATEDIN_3_0 long BIO_debug_callback(BIO *bio, int cmd,
    const char *argp, int argi,
    long argl, long ret);
""",
    """/**
 * @brief Default legacy BIO debug logger writing to the BIO's callback-argument BIO (deprecated).
 * @param bio BIO whose operation is being reported.
 * @param cmd BIO_CB_* operation code (read, write, ctrl, …).
 * @param argp Pointer argument for the operation (buffer or ctrl pointer), or NULL.
 * @param argi Integer argument for ctrl-style operations.
 * @param argl Long argument for ctrl-style operations.
 * @param ret Return value being reported for the operation.
 * @return @p ret unchanged (pass-through debug callback).
 */
OSSL_DEPRECATEDIN_3_0 long BIO_debug_callback(BIO *bio, int cmd,
    const char *argp, int argi,
    long argl, long ret);
""",
    "BIO_debug_callback",
)

patch_both(
    "bio.h",
    """typedef long (*BIO_callback_fn_ex)(BIO *b, int oper, const char *argp,
    size_t len, int argi,
    long argl, int ret, size_t *processed);
""",
    """/**
 * @brief Extended BIO callback invoked immediately before and after I/O operations.
 * @param b BIO performing the operation.
 * @param oper BIO_CB_* operation code OR'd with BIO_CB_RETURN after the call.
 * @param argp Pointer argument (buffer or ctrl pointer), or NULL.
 * @param len Byte count associated with the operation when applicable.
 * @param argi Integer argument for ctrl-style operations.
 * @param argl Long argument for ctrl-style operations.
 * @param ret Return value from the underlying operation (post-call only).
 * @param processed Optional in/out processed-byte count for read/write/mmsg operations.
 * @return Post-call return value (usually @p ret unchanged).
 */
typedef long (*BIO_callback_fn_ex)(BIO *b, int oper, const char *argp,
    size_t len, int argi,
    long argl, int ret, size_t *processed);
""",
    "BIO_callback_fn_ex",
)

patch_both(
    "bio.h",
    """void BIO_set_callback_ex(BIO *b, BIO_callback_fn_ex callback);
""",
    """/**
 * @brief Install an extended pre/post I/O callback on a BIO.
 * @param b BIO whose callback is replaced.
 * @param callback Extended callback function, or NULL to clear.
 */
void BIO_set_callback_ex(BIO *b, BIO_callback_fn_ex callback);
""",
    "BIO_set_callback_ex",
)

patch_both(
    "bio.h",
    """void BIO_set_callback_arg(BIO *b, char *arg);
""",
    """/**
 * @brief Store an opaque pointer passed to BIO callbacks as the callback argument.
 * @param b BIO whose callback argument is set.
 * @param arg Opaque pointer (often a BIO* used for debug logging), or NULL.
 */
void BIO_set_callback_arg(BIO *b, char *arg);
""",
    "BIO_set_callback_arg",
)

patch_both(
    "bio.h",
    """typedef int BIO_info_cb(BIO *, int, int);
typedef BIO_info_cb bio_info_cb; /* backward compatibility */
""",
    """/**
 * @brief Ctrl-style info callback type used with BIO_callback_ctrl() / BIO_set_info_callback().
 * @param b BIO being controlled.
 * @param cmd BIO control command.
 * @param arg Integer argument for the control operation.
 * @return Command-specific result (usually 1 on success).
 */
typedef int BIO_info_cb(BIO *, int, int);
/** @brief Backward-compatible alias for BIO_info_cb. */
typedef BIO_info_cb bio_info_cb; /* backward compatibility */
""",
    "BIO_info_cb+bio_info_cb",
)

patch_both(
    "bio.h",
    """typedef struct bio_msg_st {
    void *data;
    size_t data_len;
    /** Peer socket address associated with this message, or NULL if unused. */
    BIO_ADDR *peer;
    /** Local socket address associated with this message, or NULL if unused. */
    BIO_ADDR *local;
    uint64_t flags;
} BIO_MSG;
""",
    """/**
 * @brief Single message descriptor for BIO_sendmmsg() / BIO_recvmmsg().
 */
typedef struct bio_msg_st {
    /** Message payload buffer for send or receive. */
    void *data;
    /** Length of @c data in bytes (send length or receive buffer capacity). */
    size_t data_len;
    /** Peer socket address associated with this message, or NULL if unused. */
    BIO_ADDR *peer;
    /** Local socket address associated with this message, or NULL if unused. */
    BIO_ADDR *local;
    /** Operation-specific flags (for example BIO_MSG_FLAG_*). */
    uint64_t flags;
} BIO_MSG;
""",
    "bio_msg_st",
)

patch_both(
    "bio.h",
    """typedef struct bio_mmsg_cb_args_st {
    BIO_MSG *msg;
    /** Byte stride between consecutive BIO_MSG elements in @c msg. */
    size_t stride;
    /** Number of BIO_MSG elements addressed by this multi-message operation. */
    size_t num_msg;
    uint64_t flags;
    size_t *msgs_processed;
} BIO_MMSG_CB_ARGS;
""",
    """/**
 * @brief Argument bundle passed to multi-message BIO callbacks (sendmmsg/recvmmsg).
 */
typedef struct bio_mmsg_cb_args_st {
    /** Array of @c num_msg message descriptors spaced @c stride bytes apart. */
    BIO_MSG *msg;
    /** Byte stride between consecutive BIO_MSG elements in @c msg. */
    size_t stride;
    /** Number of BIO_MSG elements addressed by this multi-message operation. */
    size_t num_msg;
    /** Operation-specific flags mirrored from the BIO_sendmmsg()/BIO_recvmmsg() call. */
    uint64_t flags;
    /** Optional in/out count of messages processed by the operation. */
    size_t *msgs_processed;
} BIO_MMSG_CB_ARGS;
""",
    "bio_mmsg_cb_args_st",
)

patch_both(
    "bio.h",
    """size_t BIO_ctrl_wpending(BIO *b);
""",
    """/**
 * @brief Return the number of bytes buffered for writing in a BIO (ctrl pending write count).
 * @param b BIO to query.
 * @return Pending write byte count.
 */
size_t BIO_ctrl_wpending(BIO *b);
""",
    "BIO_ctrl_wpending",
)

patch_both(
    "bio.h",
    """uint64_t BIO_number_read(BIO *bio);
""",
    """/**
 * @brief Return the cumulative number of bytes successfully read through a BIO.
 * @param bio BIO whose read counter is queried.
 * @return Total bytes read since the BIO was created.
 */
uint64_t BIO_number_read(BIO *bio);
""",
    "BIO_number_read",
)

patch_both(
    "bio.h",
    """int BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix,
    asn1_ps_func *prefix_free);
""",
    """/**
 * @brief Install prefix encode/free callbacks on a BIO_f_asn1() filter BIO.
 * @param b ASN.1 filter BIO to configure.
 * @param prefix Callback that writes prefix octets before each ASN.1 item, or NULL.
 * @param prefix_free Optional cleanup for prefix state, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int BIO_asn1_set_prefix(BIO *b, asn1_ps_func *prefix,
    asn1_ps_func *prefix_free);
""",
    "BIO_asn1_set_prefix",
)

patch_both(
    "bio.h",
    """int BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix,
    asn1_ps_func *suffix_free);
""",
    """/**
 * @brief Install suffix encode/free callbacks on a BIO_f_asn1() filter BIO.
 * @param b ASN.1 filter BIO to configure.
 * @param suffix Callback that writes suffix octets after each ASN.1 item, or NULL.
 * @param suffix_free Optional cleanup for suffix state, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int BIO_asn1_set_suffix(BIO *b, asn1_ps_func *suffix,
    asn1_ps_func *suffix_free);
""",
    "BIO_asn1_set_suffix",
)

patch_both(
    "bio.h",
    """BIO *BIO_new_file(const char *filename, const char *mode);
BIO *BIO_new_from_core_bio(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *corebio);
#ifndef OPENSSL_NO_STDIO
BIO *BIO_new_fp(FILE *stream, int close_flag);
#endif
""",
    """/**
 * @brief Open @p filename and wrap it in a BIO_s_file() BIO.
 * @param filename Path to open.
 * @param mode stdio-style mode string (for example "r" or "w").
 * @return New file BIO, or NULL on error.
 */
BIO *BIO_new_file(const char *filename, const char *mode);
/**
 * @brief Wrap a provider OSSL_CORE_BIO in a library BIO_s_core() BIO.
 * @param libctx Library context for the new BIO, or NULL for the default.
 * @param corebio Provider core BIO to wrap (ownership rules follow the provider API).
 * @return New core BIO, or NULL on error.
 */
BIO *BIO_new_from_core_bio(OSSL_LIB_CTX *libctx, OSSL_CORE_BIO *corebio);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Wrap a stdio FILE* in a BIO_s_file() BIO.
 * @param stream FILE handle to associate with the BIO.
 * @param close_flag BIO_CLOSE to fclose @p stream when the BIO is freed, or BIO_NOCLOSE.
 * @return New file BIO, or NULL on error.
 */
BIO *BIO_new_fp(FILE *stream, int close_flag);
#endif
""",
    "BIO_new_file+new_from_core_bio+new_fp",
)

patch_both(
    "bio.h",
    """void *BIO_get_data(BIO *a);
void BIO_set_init(BIO *a, int init);
int BIO_get_init(BIO *a);
""",
    """/**
 * @brief Return the implementation-specific pointer stored on a BIO.
 * @param a BIO to query.
 * @return Opaque pointer previously set with BIO_set_data(), or NULL.
 */
void *BIO_get_data(BIO *a);
/**
 * @brief Mark whether a custom BIO method has completed its create() initialization.
 * @param a BIO whose init flag is updated.
 * @param init Non-zero after BIO_meth create() succeeds; 0 before initialization.
 */
void BIO_set_init(BIO *a, int init);
/**
 * @brief Test whether a custom BIO has been initialized by its create() callback.
 * @param a BIO to query.
 * @return Non-zero if initialized, or 0 otherwise.
 */
int BIO_get_init(BIO *a);
""",
    "BIO_get_data+set_init+get_init",
)

patch_both(
    "bio.h",
    """void BIO_vfree(BIO *a);
int BIO_up_ref(BIO *a);
""",
    """/**
 * @brief Free a BIO and every BIO linked after it in the chain.
 * @param a First BIO in the chain to free; NULL is ignored.
 */
void BIO_vfree(BIO *a);
/**
 * @brief Increment the reference count of a BIO.
 * @param a BIO to reference.
 * @return 1 on success, or 0 if reference counting is unavailable.
 */
int BIO_up_ref(BIO *a);
""",
    "BIO_vfree+BIO_up_ref",
)

patch_both(
    "bio.h",
    """int BIO_gets(BIO *bp, char *buf, int size);
int BIO_get_line(BIO *bio, char *buf, int size);
int BIO_write(BIO *b, const void *data, int dlen);
int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);
""",
    """/**
 * @brief Read a line from a BIO into @p buf (NUL-terminated; strips trailing newline when present).
 * @param bp Source BIO.
 * @param buf Destination buffer.
 * @param size Capacity of @p buf in bytes.
 * @return Number of bytes read (excluding NUL), 0 on EOF, or a negative value on error.
 */
int BIO_gets(BIO *bp, char *buf, int size);
/**
 * @brief Read bytes until a newline or EOF, without requiring a trailing NUL in the source.
 * @param bio Source BIO.
 * @param buf Destination buffer.
 * @param size Capacity of @p buf in bytes.
 * @return Number of bytes stored, 0 on EOF with no data, or a negative value on error.
 */
int BIO_get_line(BIO *bio, char *buf, int size);
/**
 * @brief Write @p dlen bytes from @p data to a BIO.
 * @param b Destination BIO.
 * @param data Bytes to write.
 * @param dlen Number of bytes to write (must fit in int).
 * @return Number of bytes written, or a negative value on error (see BIO_should_retry).
 */
int BIO_write(BIO *b, const void *data, int dlen);
/**
 * @brief Write up to @p dlen bytes from @p data to a BIO.
 * @param b Destination BIO.
 * @param data Bytes to write.
 * @param dlen Number of bytes to write.
 * @param written On success, receives the number of bytes actually written.
 * @return 1 if any data was written, or 0 otherwise.
 */
int BIO_write_ex(BIO *b, const void *data, size_t dlen, size_t *written);
""",
    "BIO_gets+get_line+write+write_ex",
)

patch_both(
    "bio.h",
    """__owur int BIO_get_rpoll_descriptor(BIO *b, BIO_POLL_DESCRIPTOR *desc);
__owur int BIO_get_wpoll_descriptor(BIO *b, BIO_POLL_DESCRIPTOR *desc);
""",
    """/**
 * @brief Fill @p desc with the pollable read-side target for a BIO (if any).
 * @param b BIO to query.
 * @param desc Receives type/discriminator and fd/ssl/custom value for polling.
 * @return 1 if a descriptor was returned, or 0 if none / unsupported.
 */
__owur int BIO_get_rpoll_descriptor(BIO *b, BIO_POLL_DESCRIPTOR *desc);
/**
 * @brief Fill @p desc with the pollable write-side target for a BIO (if any).
 * @param b BIO to query.
 * @param desc Receives type/discriminator and fd/ssl/custom value for polling.
 * @return 1 if a descriptor was returned, or 0 if none / unsupported.
 */
__owur int BIO_get_wpoll_descriptor(BIO *b, BIO_POLL_DESCRIPTOR *desc);
""",
    "BIO_get_rpoll_descriptor+get_wpoll_descriptor",
)

patch_both(
    "bio.h",
    """long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);
BIO *BIO_push(BIO *b, BIO *append);
BIO *BIO_pop(BIO *b);
void BIO_free_all(BIO *a);
""",
    """/**
 * @brief Invoke a BIO ctrl that takes an integer argument in the low word.
 * @param bp BIO to control.
 * @param cmd Control command.
 * @param larg Long argument for the control operation.
 * @param iarg Integer argument packed into the ctrl call.
 * @return Command-specific long result, or <=0 on error depending on @p cmd.
 */
long BIO_int_ctrl(BIO *bp, int cmd, long larg, int iarg);
/**
 * @brief Append @p append to the filter chain rooted at @p b and return the new head.
 * @param b Head of the existing BIO chain.
 * @param append BIO to link after the tail of @p b's chain.
 * @return @p b (unchanged head pointer).
 */
BIO *BIO_push(BIO *b, BIO *append);
/**
 * @brief Remove the first BIO from a chain and return the new head.
 * @param b BIO at the head of a chain (may be the only BIO).
 * @return The next BIO in the chain, or NULL if @p b was the last BIO.
 */
BIO *BIO_pop(BIO *b);
/**
 * @brief Free @p a and every BIO linked after it in the chain (alias for BIO_vfree()).
 * @param a First BIO in the chain to free; NULL is ignored.
 */
void BIO_free_all(BIO *a);
""",
    "BIO_int_ctrl+pop+free_all",
)

patch_both(
    "bio.h",
    """BIO *BIO_get_retry_BIO(BIO *bio, int *reason);
int BIO_get_retry_reason(BIO *bio);
""",
    """/**
 * @brief Walk a BIO chain after BIO_should_io_special() and locate the BIO requesting a retry.
 * @param bio Starting BIO (usually the application-facing filter).
 * @param reason Receives a BIO_RR_* reason code when non-NULL.
 * @return The BIO in the chain that set the special condition, or NULL if none.
 */
BIO *BIO_get_retry_BIO(BIO *bio, int *reason);
/**
 * @brief Return the BIO_RR_* retry reason stored on a BIO.
 * @param bio BIO previously returned by BIO_get_retry_BIO().
 * @return Retry reason code (for example BIO_RR_CONNECT).
 */
int BIO_get_retry_reason(BIO *bio);
""",
    "BIO_get_retry_BIO+get_retry_reason",
)

patch_both(
    "bio.h",
    """int BIO_nwrite(BIO *bio, char **buf, int num);
""",
    """/**
 * @brief Obtain a writable buffer from a memory BIO and advance its write pointer.
 * @param bio Memory BIO to write into.
 * @param buf Receives a pointer into the BIO's internal buffer.
 * @param num Maximum number of bytes to reserve.
 * @return Number of bytes made available at *@p buf, or a negative value on error.
 */
int BIO_nwrite(BIO *bio, char **buf, int num);
""",
    "BIO_nwrite",
)

patch_both(
    "bio.h",
    """const BIO_METHOD *BIO_f_readbuffer(void);
""",
    """/**
 * @brief Return the BIO filter method that read-ahead buffers data from the next BIO.
 * @return Pointer to the read-buffer filter method used with BIO_new().
 */
const BIO_METHOD *BIO_f_readbuffer(void);
""",
    "BIO_f_readbuffer",
)

patch_both(
    "bio.h",
    """void BIO_ADDR_clear(BIO_ADDR *ap);
""",
    """/**
 * @brief Reset a BIO_ADDR to an empty/uninitialized state.
 * @param ap Address object to clear.
 */
void BIO_ADDR_clear(BIO_ADDR *ap);
""",
    "BIO_ADDR_clear",
)

patch_both(
    "bio.h",
    """int BIO_socket_nbio(int fd, int mode);
""",
    """/**
 * @brief Set or clear non-blocking mode on a socket file descriptor.
 * @param fd Socket descriptor to configure.
 * @param mode Non-zero to enable non-blocking I/O; 0 to disable.
 * @return 1 on success, or 0 on error.
 */
int BIO_socket_nbio(int fd, int mode);
""",
    "BIO_socket_nbio",
)

patch_both(
    "bio.h",
    """OSSL_DEPRECATEDIN_1_1_0 int BIO_get_port(const char *str, unsigned short *port_ptr);
OSSL_DEPRECATEDIN_1_1_0 int BIO_get_host_ip(const char *str, unsigned char *ip);
""",
    """/**
 * @brief Parse a service name or numeric port string (deprecated; prefer modern address APIs).
 * @param str Port string such as "443" or a service name.
 * @param port_ptr Receives the network-byte-order port number on success.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_1_1_0 int BIO_get_port(const char *str, unsigned short *port_ptr);
/**
 * @brief Resolve a hostname to four IPv4 octets (deprecated; prefer BIO_lookup()).
 * @param str Hostname to resolve.
 * @param ip Receives four bytes of IPv4 address on success.
 * @return 1 on success, or 0 on error.
 */
OSSL_DEPRECATEDIN_1_1_0 int BIO_get_host_ip(const char *str, unsigned char *ip);
""",
    "BIO_get_port+BIO_get_host_ip",
)

patch_both(
    "bio.h",
    """int BIO_sock_info(int sock,
    enum BIO_sock_info_type type, union BIO_sock_info_u *info);
""",
    """/**
 * @brief Query socket metadata into a BIO_sock_info_u union.
 * @param sock Connected or bound socket descriptor.
 * @param type Information type to retrieve (for example BIO_SOCK_INFO_ADDRESS).
 * @param info Output union; for BIO_SOCK_INFO_ADDRESS, @c info->addr receives a BIO_ADDR*.
 * @return 1 on success, or 0 on error.
 */
int BIO_sock_info(int sock,
    enum BIO_sock_info_type type, union BIO_sock_info_u *info);
""",
    "BIO_sock_info",
)

patch_both(
    "bio.h",
    """BIO *BIO_new_socket(int sock, int close_flag);
""",
    """/**
 * @brief Wrap an existing socket descriptor in a BIO_s_socket() BIO.
 * @param sock Socket file descriptor.
 * @param close_flag BIO_CLOSE to close @p sock when the BIO is freed, or BIO_NOCLOSE.
 * @return New socket BIO, or NULL on error.
 */
BIO *BIO_new_socket(int sock, int close_flag);
""",
    "BIO_new_socket",
)

patch_both(
    "bio.h",
    """int BIO_new_bio_pair(BIO **bio1, size_t writebuf1,
    BIO **bio2, size_t writebuf2);
""",
    """/**
 * @brief Create two connected memory BIOs that form a reliable in-memory byte pipe.
 * @param bio1 Receives the first endpoint BIO.
 * @param writebuf1 Write buffer size for @p *bio1 (0 for default).
 * @param bio2 Receives the second endpoint BIO.
 * @param writebuf2 Write buffer size for @p *bio2 (0 for default).
 * @return 1 on success, or 0 on error.
 */
int BIO_new_bio_pair(BIO **bio1, size_t writebuf1,
    BIO **bio2, size_t writebuf2);
""",
    "BIO_new_bio_pair",
)

patch_both(
    "bio.h",
    """int (*BIO_meth_get_write_ex(const BIO_METHOD *biom))(BIO *, const char *, size_t,
    size_t *);
""",
    """/**
 * @brief Return the extended write function installed on a BIO_METHOD.
 * @param biom Method to query.
 * @return Write-ex callback, or NULL if unset.
 */
int (*BIO_meth_get_write_ex(const BIO_METHOD *biom))(BIO *, const char *, size_t,
    size_t *);
""",
    "BIO_meth_get_write_ex",
)

patch_both(
    "bio.h",
    """int (*BIO_meth_get_create(const BIO_METHOD *bion))(BIO *);
""",
    """/**
 * @brief Return the create callback installed on a BIO_METHOD.
 * @param bion Method to query.
 * @return Create callback invoked when a BIO of this method is allocated, or NULL if unset.
 */
int (*BIO_meth_get_create(const BIO_METHOD *bion))(BIO *);
""",
    "BIO_meth_get_create",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  {m}")
