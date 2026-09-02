#!/usr/bin/env python3
"""Documentation repair batch 22a: bio through self_test headers."""
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


print("=== batch 22a ===")

# ----- bio.h -----

patch_both(
    "bio.h",
    """BIO *BIO_find_type(BIO *b, int bio_type);
""",
    """/**
 * @brief Walk a BIO chain and return the first BIO whose method type matches @p bio_type.
 * @param b Starting BIO in the chain (may be a filter or source/sink).
 * @param bio_type BIO_TYPE_* mask or exact type to match.
 * @return Matching BIO in the chain, or NULL if none matches.
 */
BIO *BIO_find_type(BIO *b, int bio_type);
""",
    "BIO_find_type",
)

# ----- blowfish.h -----

patch_one(
    "blowfish.h",
    """OSSL_DEPRECATEDIN_3_0 void BF_decrypt(BF_LONG *data, const BF_KEY *key);
""",
    """/**
 * @brief Decrypt one Blowfish block in place (deprecated low-level primitive).
 * @param data Two BF_LONG words holding the 64-bit block (host endianness).
 * @param key Expanded Blowfish key schedule from BF_set_key().
 */
OSSL_DEPRECATEDIN_3_0 void BF_decrypt(BF_LONG *data, const BF_KEY *key);
""",
    "BF_decrypt",
)

# ----- bn.h -----

patch_one(
    "bn.h",
    """int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
""",
    """/**
 * @brief Compute @p r = (@p a - @p b) mod @p m.
 * @param r Destination BIGNUM.
 * @param a Minuend.
 * @param b Subtrahend.
 * @param m Modulus (must be positive).
 * @param ctx Optional BN_CTX for temporaries, or NULL.
 * @return 1 on success, or 0 on error.
 */
int BN_mod_sub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, const BIGNUM *m,
    BN_CTX *ctx);
""",
    "BN_mod_sub",
)

# ----- camellia.h -----

patch_one(
    "camellia.h",
    """OSSL_DEPRECATEDIN_3_0 void Camellia_cbc_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    const int enc);
""",
    """/**
 * @brief Encrypt or decrypt data with Camellia in CBC mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process (need not be block-aligned).
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte IV; updated to the last ciphertext block on return.
 * @param enc Non-zero to encrypt, zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_cbc_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    const int enc);
""",
    "Camellia_cbc_encrypt",
)

patch_one(
    "camellia.h",
    """OSSL_DEPRECATEDIN_3_0 void Camellia_cfb1_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    int *num,
    const int enc);
""",
    """/**
 * @brief Encrypt or decrypt data with Camellia in 1-bit CFB mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte IV; updated with running feedback state on return.
 * @param num Bit offset into the feedback buffer (0–7); updated on return.
 * @param enc Non-zero to encrypt, zero to decrypt.
 */
OSSL_DEPRECATEDIN_3_0 void Camellia_cfb1_encrypt(const unsigned char *in,
    unsigned char *out,
    size_t length,
    const CAMELLIA_KEY *key,
    unsigned char *ivec,
    int *num,
    const int enc);
""",
    "Camellia_cfb1_encrypt",
)

patch_one(
    "camellia.h",
    """OSSL_DEPRECATEDIN_3_0
void Camellia_ctr128_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const CAMELLIA_KEY *key,
    unsigned char ivec[CAMELLIA_BLOCK_SIZE],
    unsigned char ecount_buf[CAMELLIA_BLOCK_SIZE],
    unsigned int *num);
""",
    """/**
 * @brief Encrypt or decrypt data with Camellia in 128-bit CTR mode (deprecated).
 * @param in Input buffer of @p length bytes.
 * @param out Output buffer of at least @p length bytes (may equal @p in).
 * @param length Number of bytes to process.
 * @param key Expanded Camellia key from Camellia_set_key().
 * @param ivec 16-byte counter block; low bytes are incremented on return.
 * @param ecount_buf Encrypted counter block cache updated by the routine.
 * @param num Byte offset into @p ecount_buf for the next keystream byte; updated on return.
 */
OSSL_DEPRECATEDIN_3_0
void Camellia_ctr128_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const CAMELLIA_KEY *key,
    unsigned char ivec[CAMELLIA_BLOCK_SIZE],
    unsigned char ecount_buf[CAMELLIA_BLOCK_SIZE],
    unsigned int *num);
""",
    "Camellia_ctr128_encrypt",
)

# ----- cmp_util.h -----

patch_one(
    "cmp_util.h",
    """int OSSL_CMP_log_open(void);
""",
    """/**
 * @brief Open the default CMP logging channel (stderr) if not already open.
 * @return 1 on success, or 0 on error.
 */
int OSSL_CMP_log_open(void);
""",
    "OSSL_CMP_log_open",
)

# ----- core.h -----

patch_one(
    "core.h",
    """    const OSSL_DISPATCH *implementation;
    /** Optional human-readable description of the algorithm implementation. */
""",
    """    /** Provider dispatch table implementing the algorithm named by @c algorithm_names. */
    const OSSL_DISPATCH *implementation;
    /** Optional human-readable description of the algorithm implementation. */
""",
    "implementation",
)

# ----- crypto.h -----

patch_both(
    "crypto.h",
    """unsigned char *OPENSSL_hexstr2buf(const char *str, long *buflen);
""",
    """/**
 * @brief Decode a hexadecimal string into a newly allocated byte buffer.
 * @param str NUL-terminated hex text (optional ':' separators between octets).
 * @param buflen Receives the number of decoded bytes, or may be NULL.
 * @return Allocated buffer with decoded bytes, or NULL on error; free with OPENSSL_free().
 */
unsigned char *OPENSSL_hexstr2buf(const char *str, long *buflen);
""",
    "OPENSSL_hexstr2buf",
)

# ----- cryptoerr_legacy.h -----

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_PKCS7_strings(void);
""",
    """/**
 * @brief Load PKCS#7 library error strings into the error queue (deprecated no-op in OpenSSL 3+).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_PKCS7_strings(void);
""",
    "ERR_load_PKCS7_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_OSSL_STORE_strings(void);
""",
    """/**
 * @brief Load OSSL_STORE library error strings into the error queue (deprecated no-op in OpenSSL 3+).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_OSSL_STORE_strings(void);
""",
    "ERR_load_OSSL_STORE_strings",
)

# ----- decoder.h -----

patch_one(
    "decoder.h",
    """OSSL_DECODER *OSSL_DECODER_fetch(OSSL_LIB_CTX *libctx, const char *name,
    const char *properties);
""",
    """/**
 * @brief Fetch a decoder implementation from providers by algorithm name.
 * @param libctx Library context, or NULL for the default.
 * @param name Decoder algorithm name (for example "DER").
 * @param properties Optional property query string, or NULL.
 * @return Fetched OSSL_DECODER, or NULL on error; release with OSSL_DECODER_free().
 */
OSSL_DECODER *OSSL_DECODER_fetch(OSSL_LIB_CTX *libctx, const char *name,
    const char *properties);
""",
    "OSSL_DECODER_fetch",
)

patch_one(
    "decoder.h",
    """const char *OSSL_DECODER_get0_properties(const OSSL_DECODER *encoder);
""",
    """/**
 * @brief Return the property definition string of a fetched decoder.
 * @param encoder Decoder to query.
 * @return Property definition string, or NULL if unavailable.
 */
const char *OSSL_DECODER_get0_properties(const OSSL_DECODER *encoder);
""",
    "OSSL_DECODER_get0_properties",
)

patch_one(
    "decoder.h",
    """const char *OSSL_DECODER_get0_description(const OSSL_DECODER *decoder);
""",
    """/**
 * @brief Return a human-readable description of a fetched decoder.
 * @param decoder Decoder to query.
 * @return Description string, or NULL if unavailable.
 */
const char *OSSL_DECODER_get0_description(const OSSL_DECODER *decoder);
""",
    "OSSL_DECODER_get0_description",
)

patch_one(
    "decoder.h",
    """void OSSL_DECODER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(OSSL_DECODER *encoder, void *arg),
    void *arg);
""",
    """/**
 * @brief Invoke a callback for every decoder provided by activated providers.
 * @param libctx Library context, or NULL for the default.
 * @param fn Callback invoked once per decoder.
 * @param arg Opaque argument passed to @p fn.
 */
void OSSL_DECODER_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(OSSL_DECODER *encoder, void *arg),
    void *arg);
""",
    "OSSL_DECODER_do_all_provided",
)

patch_one(
    "decoder.h",
    """int OSSL_DECODER_CTX_set_passphrase_ui(OSSL_DECODER_CTX *ctx,
    const UI_METHOD *ui_method,
    void *ui_data);
""",
    """/**
 * @brief Set a UI method for passphrase prompting on a decoder context.
 * @param ctx Decoder context to configure.
 * @param ui_method UI_METHOD used to read passphrases, or NULL for the default.
 * @param ui_data Application data passed to the UI method.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_passphrase_ui(OSSL_DECODER_CTX *ctx,
    const UI_METHOD *ui_method,
    void *ui_data);
""",
    "OSSL_DECODER_CTX_set_passphrase_ui",
)

patch_one(
    "decoder.h",
    """int OSSL_DECODER_CTX_set_selection(OSSL_DECODER_CTX *ctx, int selection);
""",
    """/**
 * @brief Set the key/component selection mask for decoding (OSSL_KEYMGMT_SELECT_*).
 * @param ctx Decoder context to configure.
 * @param selection Bit mask of components to decode.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_selection(OSSL_DECODER_CTX *ctx, int selection);
""",
    "OSSL_DECODER_CTX_set_selection",
)

patch_one(
    "decoder.h",
    """int OSSL_DECODER_CTX_set_input_structure(OSSL_DECODER_CTX *ctx,
    const char *input_structure);
""",
    """/**
 * @brief Set the expected ASN.1 structure name for the encoded input.
 * @param ctx Decoder context to configure.
 * @param input_structure Structure name (for example "EncryptedPrivateKeyInfo"), or NULL.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_input_structure(OSSL_DECODER_CTX *ctx,
    const char *input_structure);
""",
    "OSSL_DECODER_CTX_set_input_structure",
)

patch_one(
    "decoder.h",
    """void *
OSSL_DECODER_INSTANCE_get_decoder_ctx(OSSL_DECODER_INSTANCE *decoder_inst);
""",
    """/**
 * @brief Return the provider decoder context for a decoder instance.
 * @param decoder_inst Active decoder instance from a decode run.
 * @return Opaque provider decoder context, or NULL if unavailable.
 */
void *
OSSL_DECODER_INSTANCE_get_decoder_ctx(OSSL_DECODER_INSTANCE *decoder_inst);
""",
    "OSSL_DECODER_INSTANCE_get_decoder_ctx",
)

patch_one(
    "decoder.h",
    """const char *
OSSL_DECODER_INSTANCE_get_input_structure(OSSL_DECODER_INSTANCE *decoder_inst,
    int *was_set);
""",
    """/**
 * @brief Return the input-structure name configured for a decoder instance.
 * @param decoder_inst Active decoder instance from a decode run.
 * @param was_set Optional output set to 1 if an input structure was explicitly configured.
 * @return Input-structure name string, or NULL if unset.
 */
const char *
OSSL_DECODER_INSTANCE_get_input_structure(OSSL_DECODER_INSTANCE *decoder_inst,
    int *was_set);
""",
    "OSSL_DECODER_INSTANCE_get_input_structure",
)

patch_one(
    "decoder.h",
    """int OSSL_DECODER_CTX_set_construct(OSSL_DECODER_CTX *ctx,
    OSSL_DECODER_CONSTRUCT *construct);
""",
    """/**
 * @brief Register a callback invoked when a decoded object is constructed.
 * @param ctx Decoder context to configure.
 * @param construct Callback receiving params for each constructed object, or NULL to clear.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_CTX_set_construct(OSSL_DECODER_CTX *ctx,
    OSSL_DECODER_CONSTRUCT *construct);
""",
    "OSSL_DECODER_CTX_set_construct",
)

patch_one(
    "decoder.h",
    """int OSSL_DECODER_export(OSSL_DECODER_INSTANCE *decoder_inst,
    void *reference, size_t reference_sz,
    OSSL_CALLBACK *export_cb, void *export_cbarg);
""",
    """/**
 * @brief Export a reference from a decoder instance via a provider export callback.
 * @param decoder_inst Decoder instance that produced @p reference.
 * @param reference Reference bytes to export.
 * @param reference_sz Size of @p reference in bytes.
 * @param export_cb Provider export callback.
 * @param export_cbarg Opaque argument passed to @p export_cb.
 * @return 1 on success, or 0 on error.
 */
int OSSL_DECODER_export(OSSL_DECODER_INSTANCE *decoder_inst,
    void *reference, size_t reference_sz,
    OSSL_CALLBACK *export_cb, void *export_cbarg);
""",
    "OSSL_DECODER_export",
)

patch_one(
    "decoder.h",
    """OSSL_DECODER_CTX *
OSSL_DECODER_CTX_new_for_pkey(EVP_PKEY **pkey,
    const char *input_type,
    const char *input_struct,
    const char *keytype, int selection,
    OSSL_LIB_CTX *libctx, const char *propquery);
""",
    """/**
 * @brief Create a decoder context preconfigured to decode an EVP_PKEY.
 * @param pkey Address of a pointer set to the decoded key on success.
 * @param input_type Expected encoding type (for example "DER"), or NULL.
 * @param input_struct Expected ASN.1 structure name, or NULL.
 * @param keytype Target key type name (for example "RSA"), or NULL.
 * @param selection OSSL_KEYMGMT_SELECT_* mask for components to decode.
 * @param libctx Library context, or NULL for the default.
 * @param propquery Optional property query for decoder fetching, or NULL.
 * @return New decoder context, or NULL on error; free with OSSL_DECODER_CTX_free().
 */
OSSL_DECODER_CTX *
OSSL_DECODER_CTX_new_for_pkey(EVP_PKEY **pkey,
    const char *input_type,
    const char *input_struct,
    const char *keytype, int selection,
    OSSL_LIB_CTX *libctx, const char *propquery);
""",
    "OSSL_DECODER_CTX_new_for_pkey",
)

# ----- e_os2.h -----

patch_one(
    "e_os2.h",
    """#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && defined(INTMAX_MAX) && defined(UINTMAX_MAX)
typedef intmax_t ossl_intmax_t;
typedef uintmax_t ossl_uintmax_t;
#else
""",
    """#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L && defined(INTMAX_MAX) && defined(UINTMAX_MAX)
/** @brief Widest signed integer type available from stdint.h on this platform. */
typedef intmax_t ossl_intmax_t;
/** @brief Widest unsigned integer type available from stdint.h on this platform. */
typedef uintmax_t ossl_uintmax_t;
#else
""",
    "ossl_intmax_t_intmax",
)

patch_one(
    "e_os2.h",
    """/* Fall back to the largest we know we require and can handle */
typedef int64_t ossl_intmax_t;
typedef uint64_t ossl_uintmax_t;
#endif
""",
    """/* Fall back to the largest we know we require and can handle */
/** @brief Signed 64-bit fallback when stdint.h max-width types are unavailable. */
typedef int64_t ossl_intmax_t;
/** @brief Unsigned 64-bit fallback when stdint.h max-width types are unavailable. */
typedef uint64_t ossl_uintmax_t;
#endif
""",
    "ossl_intmax_t_int64",
)

# ----- evp.h -----

patch_one(
    "evp.h",
    """const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void);
""",
    """/**
 * @brief Return the EVP_CIPHER for AES-128-CBC with HMAC-SHA1 (TLS AEAD).
 * @return Pointer to the cipher method, or NULL if unavailable in this build.
 */
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha1(void);
""",
    "EVP_aes_128_cbc_hmac_sha1",
)

# ----- lhash.h -----

patch_one(
    "lhash.h",
    """typedef int (*OPENSSL_LH_COMPFUNCTHUNK)(const void *, const void *, OPENSSL_LH_COMPFUNC cfn);
""",
    """/**
 * @brief Adapter that invokes a typed OPENSSL_LH_COMPFUNC on two void* elements.
 * @param a First element pointer passed to the comparison function.
 * @param b Second element pointer passed to the comparison function.
 * @param cfn Underlying comparison function to invoke on @p a and @p b.
 */
typedef int (*OPENSSL_LH_COMPFUNCTHUNK)(const void *a, const void *b, OPENSSL_LH_COMPFUNC cfn);
""",
    "OPENSSL_LH_COMPFUNCTHUNK",
)

# ----- md5.h -----

patch_one(
    "md5.h",
    """OSSL_DEPRECATEDIN_3_0 int MD5_Final(unsigned char *md, MD5_CTX *c);
""",
    """/**
 * @brief Finish an MD5 message digest and write the 16-byte result (deprecated).
 * @param md Output buffer for the digest (must hold at least 16 bytes).
 * @param c MD5 context initialized with MD5_Init() and updated with MD5_Update().
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int MD5_Final(unsigned char *md, MD5_CTX *c);
""",
    "MD5_Final",
)

# ----- param_build.h -----

patch_one(
    "param_build.h",
    """OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void);
""",
    """/**
 * @brief Allocate an empty OSSL_PARAM builder.
 * @return New builder, or NULL on allocation failure; free with OSSL_PARAM_BLD_free().
 */
OSSL_PARAM_BLD *OSSL_PARAM_BLD_new(void);
""",
    "OSSL_PARAM_BLD_new",
)

patch_one(
    "param_build.h",
    """int OSSL_PARAM_BLD_push_ulong(OSSL_PARAM_BLD *bld, const char *key,
    unsigned long int val);
""",
    """/**
 * @brief Append an unsigned long parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_ulong(OSSL_PARAM_BLD *bld, const char *key,
    unsigned long int val);
""",
    "OSSL_PARAM_BLD_push_ulong",
)

patch_one(
    "param_build.h",
    """int OSSL_PARAM_BLD_push_int32(OSSL_PARAM_BLD *bld, const char *key,
    int32_t val);
""",
    """/**
 * @brief Append a signed 32-bit integer parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_int32(OSSL_PARAM_BLD *bld, const char *key,
    int32_t val);
""",
    "OSSL_PARAM_BLD_push_int32",
)

patch_one(
    "param_build.h",
    """int OSSL_PARAM_BLD_push_double(OSSL_PARAM_BLD *bld, const char *key,
    double val);
""",
    """/**
 * @brief Append a double-precision floating-point parameter to a builder.
 * @param bld Parameter builder.
 * @param key Parameter name string.
 * @param val Value to store.
 * @return 1 on success, or 0 on error.
 */
int OSSL_PARAM_BLD_push_double(OSSL_PARAM_BLD *bld, const char *key,
    double val);
""",
    "OSSL_PARAM_BLD_push_double",
)

# ----- stack.h -----

patch_one(
    "stack.h",
    """int OPENSSL_sk_num(const OPENSSL_STACK *);
""",
    """/**
 * @brief Return the number of elements in a stack.
 * @param st Stack to query.
 * @return Element count, or 0 if @p st is NULL.
 */
int OPENSSL_sk_num(const OPENSSL_STACK *st);
""",
    "OPENSSL_sk_num",
)

patch_one(
    "stack.h",
    """void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc);
""",
    """/**
 * @brief Remove and return the element at index @p loc from a stack.
 * @param st Stack to modify.
 * @param loc Zero-based index of the element to remove.
 * @return Removed element pointer, or NULL if @p loc is out of range.
 */
void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc);
""",
    "OPENSSL_sk_delete",
)

# ----- thread.h -----

patch_one(
    "thread.h",
    """uint32_t OSSL_get_thread_support_flags(void);
""",
    """/**
 * @brief Return bitmask of thread features supported by this OpenSSL build.
 * @return OSSL_THREAD_SUPPORT_FLAG_* bits indicating thread-pool and default-spawn support.
 */
uint32_t OSSL_get_thread_support_flags(void);
""",
    "OSSL_get_thread_support_flags",
)

# ----- trace.h -----

patch_one(
    "trace.h",
    """void OSSL_trace_end(int category, BIO *channel);
""",
    """/**
 * @brief End a locked trace output group and release the trace BIO channel.
 * @param category OSSL_TRACE_CATEGORY_* value passed to OSSL_trace_begin().
 * @param channel BIO returned by OSSL_trace_begin() for the same @p category.
 */
void OSSL_trace_end(int category, BIO *channel);
""",
    "OSSL_trace_end",
)

# ----- txt_db.h -----

patch_one(
    "txt_db.h",
    """typedef struct txt_db_st {
    int num_fields;
    STACK_OF(OPENSSL_PSTRING) *data;
    LHASH_OF(OPENSSL_STRING) **index;
    int (**qual)(OPENSSL_STRING *);
    long error;
    long arg1;
    long arg2;
    OPENSSL_STRING *arg_row;
} TXT_DB;
""",
    """/**
 * @brief In-memory text database parsed from newline-separated, comma-separated rows.
 */
typedef struct txt_db_st {
    int num_fields;
    STACK_OF(OPENSSL_PSTRING) *data;
    LHASH_OF(OPENSSL_STRING) **index;
    int (**qual)(OPENSSL_STRING *);
    long error;
    /** Auxiliary numeric value set by some TXT_DB operations on error (meaning depends on @c error). */
    long arg1;
    long arg2;
    OPENSSL_STRING *arg_row;
} TXT_DB;
""",
    "TXT_DB",
)

patch_one(
    "txt_db.h",
    """TXT_DB *TXT_DB_read(BIO *in, int num);
""",
    """/**
 * @brief Read a text database from a BIO into memory.
 * @param in BIO supplying newline-terminated rows of comma-separated fields.
 * @param num Expected number of fields per row.
 * @return Parsed TXT_DB, or NULL on error (see @c error on partial objects).
 */
TXT_DB *TXT_DB_read(BIO *in, int num);
""",
    "TXT_DB_read",
)

patch_one(
    "txt_db.h",
    """long TXT_DB_write(BIO *out, TXT_DB *db);
""",
    """/**
 * @brief Write a text database to a BIO in comma-separated row format.
 * @param out Destination BIO.
 * @param db Database to serialize.
 * @return Number of bytes written, or -1 on error.
 */
long TXT_DB_write(BIO *out, TXT_DB *db);
""",
    "TXT_DB_write",
)

patch_one(
    "txt_db.h",
    """void TXT_DB_free(TXT_DB *db);
""",
    """/**
 * @brief Free a text database and all stored rows.
 * @param db Database to free, or NULL.
 */
void TXT_DB_free(TXT_DB *db);
""",
    "TXT_DB_free",
)

# ----- types.h -----

patch_one(
    "types.h",
    """typedef struct buf_mem_st BUF_MEM;
""",
    """/**
 * @brief Growable memory buffer used by BIO memory BIOs and similar helpers.
 */
typedef struct buf_mem_st BUF_MEM;
""",
    "BUF_MEM",
)

patch_one(
    "types.h",
    """typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;
""",
    """/**
 * @brief Opaque PKCS#8 PrivateKeyInfo structure (RFC 5208).
 */
typedef struct pkcs8_priv_key_info_st PKCS8_PRIV_KEY_INFO;
""",
    "pkcs8_priv_key_info_st",
)

patch_one(
    "types.h",
    """typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;
""",
    """/**
 * @brief Opaque OpenSSL library initialization settings passed to OPENSSL_init_crypto().
 */
typedef struct ossl_init_settings_st OPENSSL_INIT_SETTINGS;
""",
    "ossl_init_settings_st",
)

# ----- x509.h -----

patch_both(
    "x509.h",
    """int X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *x,
    int crit, int lastpos);
""",
    """/**
 * @brief Find the next X509 extension with a given critical flag in a stack.
 * @param x Stack of extensions to search.
 * @param crit Non-zero to match critical extensions, zero for non-critical.
 * @param lastpos Index to search after, or -1 to start from the beginning.
 * @return Index of the matching extension, or -1 if not found.
 */
int X509v3_get_ext_by_critical(const STACK_OF(X509_EXTENSION) *x,
    int crit, int lastpos);
""",
    "X509v3_get_ext_by_critical",
)

# ----- self_test.h -----

patch_one(
    "self_test.h",
    """void OSSL_SELF_TEST_set_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK *cb,
    void *cbarg);
""",
    """/**
 * @brief Register a callback invoked during provider self-test operations.
 * @param libctx Library context, or NULL for the default.
 * @param cb Self-test event callback, or NULL to clear.
 * @param cbarg Opaque argument passed to @p cb.
 */
void OSSL_SELF_TEST_set_callback(OSSL_LIB_CTX *libctx, OSSL_CALLBACK *cb,
    void *cbarg);
""",
    "OSSL_SELF_TEST_set_callback",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
