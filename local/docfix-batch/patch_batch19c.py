#!/usr/bin/env python3
"""Documentation repair batch 19c: crypto, dsa, ec, engine, err."""
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


print("=== batch 19c: crypto/dsa/ec/engine/err ===")

# ----- crypto.h -----

patch_both(
    "crypto.h",
    """/*
 * Old type for allocating dynamic locks. No longer used. Use the new thread
 * API instead.
 */
typedef struct {
    int dummy;
} CRYPTO_dynlock;
""",
    """/**
 * @brief Legacy placeholder type once used for dynamic lock callbacks (deprecated).
 *
 * No longer used; prefer CRYPTO_THREAD_* / CRYPTO_RWLOCK instead.
 */
typedef struct {
    /** Unused padding member retained for ABI compatibility of the empty struct. */
    int dummy;
} CRYPTO_dynlock;
""",
    "CRYPTO_dynlock",
)

patch_both(
    "crypto.h",
    """typedef void CRYPTO_RWLOCK;
""",
    """/**
 * @brief Opaque read/write lock used by CRYPTO_THREAD_* and CRYPTO_atomic_* helpers.
 */
typedef void CRYPTO_RWLOCK;
""",
    "CRYPTO_RWLOCK",
)

patch_both(
    "crypto.h",
    """__owur int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock);
""",
    """/**
 * @brief Acquire a shared (read) lock on a CRYPTO_RWLOCK.
 * @param lock Lock allocated by CRYPTO_THREAD_lock_new().
 * @return 1 on success, or 0 on failure.
 */
__owur int CRYPTO_THREAD_read_lock(CRYPTO_RWLOCK *lock);
""",
    "CRYPTO_THREAD_read_lock",
)

patch_both(
    "crypto.h",
    """int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock);
""",
    """/**
 * @brief Atomically add @p amount to *@p val, optionally under @p lock.
 * @param val Integer to modify in place.
 * @param amount Value added to *@p val.
 * @param ret Receives the post-add value of *@p val; must not be NULL.
 * @param lock Optional CRYPTO_RWLOCK used when hardware atomics are unavailable, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_atomic_add(int *val, int amount, int *ret, CRYPTO_RWLOCK *lock);
""",
    "CRYPTO_atomic_add",
)

patch_both(
    "crypto.h",
    """int CRYPTO_atomic_or(uint64_t *val, uint64_t op, uint64_t *ret,
    CRYPTO_RWLOCK *lock);
""",
    """/**
 * @brief Atomically bitwise-OR @p op into *@p val, optionally under @p lock.
 * @param val 64-bit integer to modify in place.
 * @param op Bits ORed into *@p val.
 * @param ret Receives the post-OR value of *@p val; must not be NULL.
 * @param lock Optional CRYPTO_RWLOCK used when hardware atomics are unavailable, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_atomic_or(uint64_t *val, uint64_t op, uint64_t *ret,
    CRYPTO_RWLOCK *lock);
""",
    "CRYPTO_atomic_or",
)

patch_both(
    "crypto.h",
    """int CRYPTO_atomic_load(uint64_t *val, uint64_t *ret, CRYPTO_RWLOCK *lock);
""",
    """/**
 * @brief Atomically load a 64-bit value, optionally under @p lock.
 * @param val Address of the value to read.
 * @param ret Receives a snapshot of *@p val; must not be NULL.
 * @param lock Optional CRYPTO_RWLOCK used when hardware atomics are unavailable, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_atomic_load(uint64_t *val, uint64_t *ret, CRYPTO_RWLOCK *lock);
""",
    "CRYPTO_atomic_load",
)

patch_both(
    "crypto.h",
    """int CRYPTO_atomic_load_int(int *val, int *ret, CRYPTO_RWLOCK *lock);
""",
    """/**
 * @brief Atomically load an int value, optionally under @p lock.
 * @param val Address of the integer to read.
 * @param ret Receives a snapshot of *@p val; must not be NULL.
 * @param lock Optional CRYPTO_RWLOCK used when hardware atomics are unavailable, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_atomic_load_int(int *val, int *ret, CRYPTO_RWLOCK *lock);
""",
    "CRYPTO_atomic_load_int",
)

patch_both(
    "crypto.h",
    """size_t OPENSSL_strnlen(const char *str, size_t maxlen);
""",
    """/**
 * @brief Return the length of @p str, limited to at most @p maxlen bytes.
 * @param str Possibly non-NUL-terminated buffer to measure.
 * @param maxlen Maximum number of bytes to examine.
 * @return Number of non-NUL bytes before the first NUL, or @p maxlen if none is found.
 */
size_t OPENSSL_strnlen(const char *str, size_t maxlen);
""",
    "OPENSSL_strnlen",
)

patch_both(
    "crypto.h",
    """int OPENSSL_hexstr2buf_ex(unsigned char *buf, size_t buf_n, size_t *buflen,
    const char *str, const char sep);
""",
    """/**
 * @brief Decode a hex string into @p buf, optionally ignoring separator @p sep.
 * @param buf Destination byte buffer, or NULL to only compute the required length.
 * @param buf_n Capacity of @p buf in bytes (ignored when @p buf is NULL).
 * @param buflen Receives the number of decoded bytes, or may be NULL.
 * @param str NUL-terminated hex text (may contain @p sep between octets).
 * @param sep Optional separator character to skip (for example ':'), or '\\0' for none.
 * @return 1 on success, or 0 on failure (invalid input or insufficient @p buf_n).
 */
int OPENSSL_hexstr2buf_ex(unsigned char *buf, size_t buf_n, size_t *buflen,
    const char *str, const char sep);
""",
    "OPENSSL_hexstr2buf_ex",
)

patch_both(
    "crypto.h",
    """unsigned int OPENSSL_version_minor(void);
""",
    """/**
 * @brief Return the OpenSSL library minor version (OPENSSL_VERSION_MINOR).
 * @return Minor version number from the build-time OPENSSL_VERSION_* macros.
 */
unsigned int OPENSSL_version_minor(void);
""",
    "OPENSSL_version_minor",
)

patch_both(
    "crypto.h",
    """const char *OPENSSL_version_pre_release(void);
""",
    """/**
 * @brief Return the OpenSSL pre-release label (OPENSSL_VERSION_PRE_RELEASE).
 * @return Constant string such as "-dev" or "" when this is not a pre-release; do not free.
 */
const char *OPENSSL_version_pre_release(void);
""",
    "OPENSSL_version_pre_release",
)

patch_both(
    "crypto.h",
    """const char *OPENSSL_version_build_metadata(void);
""",
    """/**
 * @brief Return OpenSSL build metadata (OPENSSL_VERSION_BUILD_METADATA).
 * @return Constant metadata string (may be empty); do not free.
 */
const char *OPENSSL_version_build_metadata(void);
""",
    "OPENSSL_version_build_metadata",
)

patch_both(
    "crypto.h",
    """unsigned long OpenSSL_version_num(void);
""",
    """/**
 * @brief Return the packed OpenSSL version number (OPENSSL_VERSION_NUMBER).
 * @return Library version encoded as 0xMNN00PP0L (major/minor/patch nibbles).
 */
unsigned long OpenSSL_version_num(void);
""",
    "OpenSSL_version_num",
)

patch_both(
    "crypto.h",
    """int CRYPTO_set_mem_functions(CRYPTO_malloc_fn malloc_fn,
    CRYPTO_realloc_fn realloc_fn,
    CRYPTO_free_fn free_fn);
""",
    """/**
 * @brief Install process-wide CRYPTO memory allocator callbacks (before first allocation).
 * @param malloc_fn Replacement malloc, or NULL to leave the current malloc unchanged.
 * @param realloc_fn Replacement realloc, or NULL to leave the current realloc unchanged.
 * @param free_fn Replacement free, or NULL to leave the current free unchanged.
 * @return 1 on success, or 0 if allocators cannot be changed (already in use).
 */
int CRYPTO_set_mem_functions(CRYPTO_malloc_fn malloc_fn,
    CRYPTO_realloc_fn realloc_fn,
    CRYPTO_free_fn free_fn);
""",
    "CRYPTO_set_mem_functions",
)

patch_both(
    "crypto.h",
    """char *CRYPTO_strndup(const char *str, size_t s, const char *file, int line);
""",
    """/**
 * @brief Duplicate at most @p s characters of @p str using the OpenSSL allocator.
 * @param str Source bytes (NUL-terminated or truncated at @p s).
 * @param s Maximum number of characters to copy (excluding the added NUL).
 * @param file Source file name recorded with the allocation (usually __FILE__).
 * @param line Source line recorded with the allocation (usually __LINE__).
 * @return Newly allocated NUL-terminated copy, or NULL on failure.
 */
char *CRYPTO_strndup(const char *str, size_t s, const char *file, int line);
""",
    "CRYPTO_strndup",
)

patch_both(
    "crypto.h",
    """void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line);
""",
    """/**
 * @brief Securely clear @p num bytes at @p ptr and free the allocation.
 * @param ptr Memory to clear and free, or NULL.
 * @param num Number of bytes at @p ptr to zero before freeing.
 * @param file Source file name for tracking (usually __FILE__).
 * @param line Source line for tracking (usually __LINE__).
 */
void CRYPTO_clear_free(void *ptr, size_t num, const char *file, int line);
""",
    "CRYPTO_clear_free",
)

patch_both(
    "crypto.h",
    """void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line);
""",
    """/**
 * @brief Resize an OpenSSL allocation to @p num bytes (file/line for debugging).
 * @param addr Existing allocation, or NULL to allocate anew.
 * @param num New size in bytes (0 frees @p addr and returns NULL).
 * @param file Source file name recorded with the allocation (usually __FILE__).
 * @param line Source line recorded with the allocation (usually __LINE__).
 * @return Reallocated pointer, or NULL on failure (original block left allocated on failure).
 */
void *CRYPTO_realloc(void *addr, size_t num, const char *file, int line);
""",
    "CRYPTO_realloc",
)

patch_both(
    "crypto.h",
    """OSSL_DEPRECATEDIN_3_0 void OPENSSL_fork_prepare(void);
""",
    """/**
 * @brief Prepare OpenSSL internal state before a POSIX fork (deprecated).
 *
 * Call in the parent before fork(); pair with OPENSSL_fork_parent() / OPENSSL_fork_child().
 */
OSSL_DEPRECATEDIN_3_0 void OPENSSL_fork_prepare(void);
""",
    "OPENSSL_fork_prepare",
)

patch_both(
    "crypto.h",
    """void OPENSSL_cleanup(void);
""",
    """/**
 * @brief Deinitialize OpenSSL: run atexit handlers, free global crypto state, and stop threads.
 *
 * After this call, most OpenSSL APIs must not be used until the process re-initializes.
 */
void OPENSSL_cleanup(void);
""",
    "OPENSSL_cleanup",
)

patch_both(
    "crypto.h",
    """OSSL_LIB_CTX *OSSL_LIB_CTX_new_child(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in);
""",
    """/**
 * @brief Create a child library context mirroring providers from a provider's parent context.
 * @param handle Core handle identifying the provider whose parent libctx is mirrored.
 * @param in Provider-to-core OSSL_DISPATCH table (BIO and related upcalls).
 * @return New child OSSL_LIB_CTX, or NULL on failure; free with OSSL_LIB_CTX_free().
 */
OSSL_LIB_CTX *OSSL_LIB_CTX_new_child(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in);
""",
    "OSSL_LIB_CTX_new_child",
)

# ----- dsa.h -----

patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_paramgen(DSA_METHOD *dsam,
    int (*paramgen)(DSA *, int, const unsigned char *, int, int *,
        unsigned long *, BN_GENCB *));
""",
    """/**
 * @brief Set the parameter-generation callback on a custom DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param paramgen Callback that generates DSA domain parameters, or NULL to clear.
 * @return 1 on success.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set_paramgen(DSA_METHOD *dsam,
    int (*paramgen)(DSA *, int, const unsigned char *, int, int *,
        unsigned long *, BN_GENCB *));
""",
    "DSA_meth_set_paramgen",
)

# ----- ec.h -----

patch_one(
    "ec.h",
    """point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *);
""",
    """/**
 * @brief Return how EC points in this group are encoded by default.
 * @param group Curve group to query.
 * @return POINT_CONVERSION_COMPRESSED, POINT_CONVERSION_UNCOMPRESSED, or POINT_CONVERSION_HYBRID.
 */
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *group);
""",
    "EC_GROUP_get_point_conversion_form",
)

# ----- engine.h -----

patch_one(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_by_id(const char *id);
""",
    """/**
 * @brief Look up a registered ENGINE by its unique id string (deprecated).
 * @param id ENGINE identifier (for example "dynamic" or a built-in engine id).
 * @return Structural reference to the ENGINE, or NULL if not found; free with ENGINE_free().
 */
OSSL_DEPRECATEDIN_3_0 ENGINE *ENGINE_by_id(const char *id);
""",
    "ENGINE_by_id",
)

patch_one(
    "engine.h",
    """OSSL_DEPRECATEDIN_3_0
const EVP_CIPHER *ENGINE_get_cipher(ENGINE *e, int nid);
""",
    """/**
 * @brief Return the EVP_CIPHER that @p e provides for algorithm @p nid.
 * @param e ENGINE whose ciphers handler is queried.
 * @param nid NID of the cipher algorithm to look up.
 * @return Matching EVP_CIPHER, or NULL if @p e does not implement @p nid.
 */
OSSL_DEPRECATEDIN_3_0
const EVP_CIPHER *ENGINE_get_cipher(ENGINE *e, int nid);
""",
    "ENGINE_get_cipher",
)

# ----- err.h -----

patch_both(
    "err.h",
    """    char *err_data[ERR_NUM_ERRORS];
""",
    """    /** Optional auxiliary detail strings for each error slot (see ERR_TXT_*). */
    char *err_data[ERR_NUM_ERRORS];
""",
    "err_data",
)

patch_both(
    "err.h",
    """    char *err_file[ERR_NUM_ERRORS];
""",
    """    /** Source file name associated with each error slot (may be NULL). */
    char *err_file[ERR_NUM_ERRORS];
""",
    "err_file",
)

patch_both(
    "err.h",
    """static ossl_unused ossl_inline int ERR_GET_RFLAGS(unsigned long errcode)
{
    if (ERR_SYSTEM_ERROR(errcode))
        return 0;
    return errcode & (ERR_RFLAGS_MASK << ERR_RFLAGS_OFFSET);
}
""",
    """/**
 * @brief Extract reason-flag bits (ERR_RFLAG_*) from a packed OpenSSL error code.
 * @param errcode Error code as returned by ERR_get_error() or ERR_peek_error().
 * @return Flag bits shifted into place, or 0 for a recorded system error.
 */
static ossl_unused ossl_inline int ERR_GET_RFLAGS(unsigned long errcode)
{
    if (ERR_SYSTEM_ERROR(errcode))
        return 0;
    return errcode & (ERR_RFLAGS_MASK << ERR_RFLAGS_OFFSET);
}
""",
    "ERR_GET_RFLAGS",
)

patch_both(
    "err.h",
    """void ERR_new(void);
""",
    """/**
 * @brief Allocate a new empty slot on the current thread's OpenSSL error queue.
 *
 * Typically followed by ERR_set_debug() and ERR_set_error() (see ERR_raise()).
 */
void ERR_new(void);
""",
    "ERR_new",
)

patch_both(
    "err.h",
    """unsigned long ERR_peek_error_line(const char **file, int *line);
""",
    """/**
 * @brief Peek at the earliest error and optionally return its source file and line.
 * @param file Receives the source file name, or unchanged if NULL.
 * @param line Receives the source line number, or unchanged if NULL.
 * @return Earliest error code, or 0 if the queue is empty (queue unchanged).
 */
unsigned long ERR_peek_error_line(const char **file, int *line);
""",
    "ERR_peek_error_line",
)

patch_both(
    "err.h",
    """unsigned long ERR_peek_error_data(const char **data, int *flags);
""",
    """/**
 * @brief Peek at the earliest error and optionally return auxiliary data and flags.
 * @param data Receives optional auxiliary data, or unchanged if NULL.
 * @param flags Receives ERR_TXT_* flags for @p data, or unchanged if NULL.
 * @return Earliest error code, or 0 if the queue is empty (queue unchanged).
 */
unsigned long ERR_peek_error_data(const char **data, int *flags);
""",
    "ERR_peek_error_data",
)

patch_both(
    "err.h",
    """unsigned long ERR_peek_error_all(const char **file, int *line,
    const char **func,
    const char **data, int *flags);
""",
    """/**
 * @brief Peek at the earliest error and optionally return file, line, function, data, and flags.
 * @param file Receives the source file name, or unchanged if NULL.
 * @param line Receives the source line number, or unchanged if NULL.
 * @param func Receives the function name, or unchanged if NULL.
 * @param data Receives optional auxiliary data, or unchanged if NULL.
 * @param flags Receives ERR_TXT_* flags for @p data, or unchanged if NULL.
 * @return Earliest error code, or 0 if the queue is empty (queue unchanged).
 */
unsigned long ERR_peek_error_all(const char **file, int *line,
    const char **func,
    const char **data, int *flags);
""",
    "ERR_peek_error_all",
)

patch_both(
    "err.h",
    """unsigned long ERR_peek_last_error(void);
""",
    """/**
 * @brief Return the newest error code without removing it from the queue.
 * @return Packed error code, or 0 if the queue is empty.
 */
unsigned long ERR_peek_last_error(void);
""",
    "ERR_peek_last_error",
)

patch_both(
    "err.h",
    """void ERR_clear_error(void);
""",
    """/**
 * @brief Clear all errors from the current thread's OpenSSL error queue.
 */
void ERR_clear_error(void);
""",
    "ERR_clear_error",
)

print(f"\nOK={len(ok)} MISS={len(missing)}")
for m in missing:
    print("  missing:", m)
