#!/usr/bin/env python3
"""Documentation repair batch 20c: conf, core, crypto, misc headers."""
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


print("=== batch 20c: conf/core/crypto/misc ===")

# ----- conf -----
patch_both(
    "conf.h",
    """char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
    const char *name);
""",
    """/**
 * @brief Look up a string value in a legacy CONF LHASH.
 * @param conf Configuration hash from CONF_load*().
 * @param group Section name, or NULL for the default section.
 * @param name Key name within the section.
 * @return Internal value string (do not free), or NULL if not found.
 */
char *CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
    const char *name);
""",
    "CONF_get_string",
)

patch_both(
    "conf.h",
    """CONF *NCONF_new(CONF_METHOD *meth);
""",
    """/**
 * @brief Allocate a CONF object using configuration method @p meth.
 * @param meth Method such as NCONF_default(), or NULL for the default method.
 * @return New CONF, or NULL on failure; free with NCONF_free().
 */
CONF *NCONF_new(CONF_METHOD *meth);
""",
    "NCONF_new",
)

patch_both(
    "conf.h",
    """int CONF_modules_load_file_ex(OSSL_LIB_CTX *libctx, const char *filename,
    const char *appname, unsigned long flags);
int CONF_modules_load_file(const char *filename, const char *appname,
    unsigned long flags);
void CONF_modules_unload(int all);
void CONF_modules_finish(void);
""",
    """/**
 * @brief Load and initialize CONF modules from a file using library context @p libctx.
 * @param libctx Library context for module initialization, or NULL for the default.
 * @param filename Path to an OpenSSL configuration file, or NULL for the default path.
 * @param appname Application section name passed to modules, or NULL for the default.
 * @param flags Bitmask of CONF_MFLAGS_* controlling missing-file and errors.
 * @return 1 on success, or 0 on failure.
 */
int CONF_modules_load_file_ex(OSSL_LIB_CTX *libctx, const char *filename,
    const char *appname, unsigned long flags);
/**
 * @brief Load and initialize CONF modules from a file using the default library context.
 * @param filename Path to an OpenSSL configuration file, or NULL for the default path.
 * @param appname Application section name passed to modules, or NULL for the default.
 * @param flags Bitmask of CONF_MFLAGS_* controlling missing-file and errors.
 * @return 1 on success, or 0 on failure.
 */
int CONF_modules_load_file(const char *filename, const char *appname,
    unsigned long flags);
void CONF_modules_unload(int all);
/**
 * @brief Finish and tear down all currently loaded CONF modules.
 */
void CONF_modules_finish(void);
""",
    "CONF_modules_load*/finish",
)

patch_both(
    "conf.h",
    """const char *CONF_imodule_get_name(const CONF_IMODULE *md);
""",
    """/**
 * @brief Return the configured name of an initialized CONF module instance.
 * @param md Module instance from a conf_init_func callback.
 * @return Internal module name string; do not free.
 */
const char *CONF_imodule_get_name(const CONF_IMODULE *md);
""",
    "CONF_imodule_get_name",
)

patch_both(
    "conf.h",
    """void *CONF_imodule_get_usr_data(const CONF_IMODULE *md);
""",
    """/**
 * @brief Return the opaque application pointer stored on a CONF module instance.
 * @param md Module instance to query.
 * @return Pointer previously set with CONF_imodule_set_usr_data(), or NULL.
 */
void *CONF_imodule_get_usr_data(const CONF_IMODULE *md);
""",
    "CONF_imodule_get_usr_data",
)

patch_both(
    "conf.h",
    """char *CONF_get1_default_config_file(void);
""",
    """/**
 * @brief Return a newly allocated path to the default OpenSSL configuration file.
 * @return Heap string (free with OPENSSL_free()), or NULL on failure.
 */
char *CONF_get1_default_config_file(void);
""",
    "CONF_get1_default_config_file",
)

# ----- core.h -----
patch_one(
    "core.h",
    """struct ossl_dispatch_st {
    int function_id;
    /** Function pointer for this dispatch table entry (cast to the concrete OSSL_FUNC_* type). */
    void (*function)(void);
};
""",
    """struct ossl_dispatch_st {
    /** OSSL_FUNC_* identity selecting which provider API entry @c function implements. */
    int function_id;
    /** Function pointer for this dispatch table entry (cast to the concrete OSSL_FUNC_* type). */
    void (*function)(void);
};
""",
    "function_id",
)

# ----- crypto.h -----
patch_both(
    "crypto.h",
    """__owur int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock);
""",
    """/**
 * @brief Acquire a CRYPTO_RWLOCK for exclusive (write) access.
 * @param lock Lock to acquire.
 * @return 1 on success, or 0 on error.
 */
__owur int CRYPTO_THREAD_write_lock(CRYPTO_RWLOCK *lock);
""",
    "CRYPTO_THREAD_write_lock",
)

patch_both(
    "crypto.h",
    """void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock);
""",
    """/**
 * @brief Free a CRYPTO_RWLOCK allocated by CRYPTO_THREAD_lock_new().
 * @param lock Lock to free, or NULL (no-op).
 */
void CRYPTO_THREAD_lock_free(CRYPTO_RWLOCK *lock);
""",
    "CRYPTO_THREAD_lock_free",
)

patch_both(
    "crypto.h",
    """int OPENSSL_hexchar2int(unsigned char c);
""",
    """/**
 * @brief Convert a single hexadecimal digit character to its 0–15 value.
 * @param c ASCII hex digit ('0'–'9', 'a'–'f', or 'A'–'F').
 * @return Nibble value 0–15, or -1 if @p c is not a hex digit.
 */
int OPENSSL_hexchar2int(unsigned char c);
""",
    "OPENSSL_hexchar2int",
)

patch_both(
    "crypto.h",
    """const char *OPENSSL_info(int type);
""",
    """/**
 * @brief Return a static string describing a build or runtime configuration property.
 * @param type OPENSSL_INFO_* selector (for example OPENSSL_INFO_CONFIG_DIR).
 * @return Internal NUL-terminated string for @p type, or NULL if unknown.
 */
const char *OPENSSL_info(int type);
""",
    "OPENSSL_info",
)

patch_both(
    "crypto.h",
    """typedef void CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
    void **from_d, int idx, long argl, void *argp);
__owur int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
    CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func,
    CRYPTO_EX_free *free_func);
""",
    """/**
 * @brief Callback invoked when a new ex_data slot is first associated with an object.
 * @param parent Object that owns the CRYPTO_EX_DATA.
 * @param ptr Pointer value being stored (often NULL on allocation).
 * @param ad Ex-data bag for @p parent.
 * @param idx Ex-data index being initialized.
 * @param argl Long argument registered with CRYPTO_get_ex_new_index().
 * @param argp Pointer argument registered with CRYPTO_get_ex_new_index().
 */
typedef void CRYPTO_EX_new(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
typedef void CRYPTO_EX_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp);
/**
 * @brief Callback that duplicates one ex_data slot when an object is copied.
 * @param to Destination ex-data bag.
 * @param from Source ex-data bag.
 * @param from_d Address of the source slot pointer; may be updated to the duplicated value.
 * @param idx Ex-data index being duplicated.
 * @param argl Long argument registered with CRYPTO_get_ex_new_index().
 * @param argp Pointer argument registered with CRYPTO_get_ex_new_index().
 * @return 1 on success, or 0 on failure.
 */
typedef int CRYPTO_EX_dup(CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
    void **from_d, int idx, long argl, void *argp);
/**
 * @brief Allocate a new application-specific ex_data index for a CRYPTO_EX_INDEX_* class.
 * @param class_index CRYPTO_EX_INDEX_* identifying the object class.
 * @param argl Opaque long passed to the new/dup/free callbacks.
 * @param argp Opaque pointer passed to the new/dup/free callbacks.
 * @param new_func Optional constructor callback, or NULL.
 * @param dup_func Optional duplication callback, or NULL.
 * @param free_func Optional destructor callback, or NULL.
 * @return Non-negative index on success, or -1 on failure.
 */
__owur int CRYPTO_get_ex_new_index(int class_index, long argl, void *argp,
    CRYPTO_EX_new *new_func,
    CRYPTO_EX_dup *dup_func,
    CRYPTO_EX_free *free_func);
""",
    "CRYPTO_EX_*/get_ex_new_index",
)

patch_both(
    "crypto.h",
    """void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx);
""",
    """/**
 * @brief Retrieve the pointer stored at ex_data index @p idx.
 * @param ad Ex-data bag to query.
 * @param idx Index from CRYPTO_get_ex_new_index() (or a class helper).
 * @return Stored pointer, or NULL if unset / out of range.
 */
void *CRYPTO_get_ex_data(const CRYPTO_EX_DATA *ad, int idx);
""",
    "CRYPTO_get_ex_data",
)

patch_both(
    "crypto.h",
    """typedef void *(*CRYPTO_malloc_fn)(size_t num, const char *file, int line);
typedef void *(*CRYPTO_realloc_fn)(void *addr, size_t num, const char *file,
    int line);
typedef void (*CRYPTO_free_fn)(void *addr, const char *file, int line);
""",
    """/**
 * @brief Allocator callback type used by CRYPTO_set_mem_functions().
 * @param num Number of bytes to allocate.
 * @param file Source file recorded with the allocation.
 * @param line Source line recorded with the allocation.
 * @return Newly allocated memory, or NULL on failure.
 */
typedef void *(*CRYPTO_malloc_fn)(size_t num, const char *file, int line);
typedef void *(*CRYPTO_realloc_fn)(void *addr, size_t num, const char *file,
    int line);
/**
 * @brief Deallocator callback type used by CRYPTO_set_mem_functions().
 * @param addr Memory to free (may be NULL depending on implementation).
 * @param file Source file associated with the free site.
 * @param line Source line associated with the free site.
 */
typedef void (*CRYPTO_free_fn)(void *addr, const char *file, int line);
""",
    "CRYPTO_malloc/free_fn",
)

patch_both(
    "crypto.h",
    """void *CRYPTO_memdup(const void *str, size_t siz, const char *file, int line);
""",
    """/**
 * @brief Duplicate @p siz bytes from @p str using the OpenSSL allocator.
 * @param str Source memory to copy.
 * @param siz Number of bytes to duplicate.
 * @param file Source file name recorded with the allocation (usually __FILE__).
 * @param line Source line recorded with the allocation (usually __LINE__).
 * @return Newly allocated copy, or NULL on failure.
 */
void *CRYPTO_memdup(const void *str, size_t siz, const char *file, int line);
""",
    "CRYPTO_memdup",
)

patch_both(
    "crypto.h",
    """void CRYPTO_free(void *ptr, const char *file, int line);
""",
    """/**
 * @brief Free memory previously allocated by CRYPTO_malloc() / OPENSSL_malloc().
 * @param ptr Memory to free, or NULL (no-op).
 * @param file Source file name for tracking (usually __FILE__).
 * @param line Source line for tracking (usually __LINE__).
 */
void CRYPTO_free(void *ptr, const char *file, int line);
""",
    "CRYPTO_free",
)

patch_both(
    "crypto.h",
    """int CRYPTO_secure_malloc_done(void);
""",
    """/**
 * @brief Tear down the secure heap after CRYPTO_secure_malloc_init() (when unused).
 * @return 1 if the secure heap was released, or 0 if allocations remain / not initialised.
 */
int CRYPTO_secure_malloc_done(void);
""",
    "CRYPTO_secure_malloc_done",
)

patch_both(
    "crypto.h",
    """void CRYPTO_secure_clear_free(void *ptr, size_t num,
    const char *file, int line);
int CRYPTO_secure_allocated(const void *ptr);
""",
    """/**
 * @brief Clear @p num bytes at @p ptr then free a secure-heap allocation.
 * @param ptr Secure allocation to clear and free, or NULL.
 * @param num Number of bytes at @p ptr to zero before freeing.
 * @param file Source file name for tracking (usually __FILE__).
 * @param line Source line for tracking (usually __LINE__).
 */
void CRYPTO_secure_clear_free(void *ptr, size_t num,
    const char *file, int line);
/**
 * @brief Report whether @p ptr was allocated from the OpenSSL secure heap.
 * @param ptr Pointer to test.
 * @return 1 if @p ptr is a secure-heap allocation, or 0 otherwise.
 */
int CRYPTO_secure_allocated(const void *ptr);
""",
    "CRYPTO_secure_clear_free/allocated",
)

patch_both(
    "crypto.h",
    """size_t CRYPTO_secure_actual_size(void *ptr);
""",
    """/**
 * @brief Return the actual secure-heap block size reserved for @p ptr.
 * @param ptr Secure allocation from CRYPTO_secure_malloc().
 * @return Usable size of the secure block, or 0 if @p ptr is not secure-allocated.
 */
size_t CRYPTO_secure_actual_size(void *ptr);
""",
    "CRYPTO_secure_actual_size",
)

patch_both(
    "crypto.h",
    """void OPENSSL_init(void);
""",
    """/**
 * @brief Perform legacy low-level OpenSSL library initialization (prefer OPENSSL_init_crypto()).
 */
void OPENSSL_init(void);
""",
    "OPENSSL_init",
)

patch_both(
    "crypto.h",
    """OSSL_DEPRECATEDIN_3_0 void OPENSSL_fork_parent(void);
""",
    """/**
 * @brief Resume OpenSSL internal state in the parent after a POSIX fork (deprecated).
 */
OSSL_DEPRECATEDIN_3_0 void OPENSSL_fork_parent(void);
""",
    "OPENSSL_fork_parent",
)

patch_both(
    "crypto.h",
    """struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result);
int OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec);
""",
    """/**
 * @brief Convert a time_t to UTC broken-down time into caller-provided storage.
 * @param timer Instant to convert.
 * @param result Destination struct tm (thread-safe alternative to gmtime()).
 * @return @p result on success, or NULL on error.
 */
struct tm *OPENSSL_gmtime(const time_t *timer, struct tm *result);
/**
 * @brief Add a day/second offset to a UTC struct tm in place.
 * @param tm Time value to adjust (UTC).
 * @param offset_day Number of days to add (may be negative).
 * @param offset_sec Number of seconds to add (may be negative).
 * @return 1 on success, or 0 on error.
 */
int OPENSSL_gmtime_adj(struct tm *tm, int offset_day, long offset_sec);
""",
    "OPENSSL_gmtime*",
)

patch_both(
    "crypto.h",
    """int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
""",
    """/**
 * @brief Initialize libcrypto with option flags and optional settings.
 * @param opts Bitmask of OPENSSL_INIT_* options (for example OPENSSL_INIT_LOAD_CONFIG).
 * @param settings Optional settings from OPENSSL_INIT_new(), or NULL.
 * @return 1 on success, or 0 on failure.
 */
int OPENSSL_init_crypto(uint64_t opts, const OPENSSL_INIT_SETTINGS *settings);
""",
    "OPENSSL_init_crypto",
)

patch_both(
    "crypto.h",
    """OPENSSL_INIT_SETTINGS *OPENSSL_INIT_new(void);
#ifndef OPENSSL_NO_STDIO
int OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS *settings,
    const char *config_filename);
""",
    """/**
 * @brief Allocate an OPENSSL_INIT_SETTINGS object for OPENSSL_init_crypto().
 * @return New settings object, or NULL on failure; free with OPENSSL_INIT_free().
 */
OPENSSL_INIT_SETTINGS *OPENSSL_INIT_new(void);
#ifndef OPENSSL_NO_STDIO
/**
 * @brief Set the configuration file path used when OPENSSL_init_crypto() loads config.
 * @param settings Initialization settings object from OPENSSL_INIT_new().
 * @param config_filename Path to an openssl.cnf-style file.
 * @return 1 on success, or 0 on failure.
 */
int OPENSSL_INIT_set_config_filename(OPENSSL_INIT_SETTINGS *settings,
    const char *config_filename);
""",
    "OPENSSL_INIT_new/set_config_filename",
)

patch_both(
    "crypto.h",
    """int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *settings,
    const char *config_appname);
""",
    """/**
 * @brief Set the application section name used when OPENSSL_init_crypto() loads config.
 * @param settings Initialization settings object from OPENSSL_INIT_new().
 * @param config_appname Application name / section passed to CONF_modules_load_file().
 * @return 1 on success, or 0 on failure.
 */
int OPENSSL_INIT_set_config_appname(OPENSSL_INIT_SETTINGS *settings,
    const char *config_appname);
""",
    "OPENSSL_INIT_set_config_appname",
)

patch_both(
    "crypto.h",
    """int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));
""",
    """/**
 * @brief Run @p init exactly once across threads using a CRYPTO_ONCE control.
 * @param once Once-control variable (initialize with CRYPTO_ONCE_STATIC_INIT).
 * @param init Function invoked at most once process-wide for @p once.
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_THREAD_run_once(CRYPTO_ONCE *once, void (*init)(void));
""",
    "CRYPTO_THREAD_run_once",
)

patch_both(
    "crypto.h",
    """void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key);
""",
    """/**
 * @brief Return the calling thread's value for thread-local key @p key.
 * @param key Thread-local key from CRYPTO_THREAD_init_local().
 * @return Stored pointer for this thread, or NULL if unset.
 */
void *CRYPTO_THREAD_get_local(CRYPTO_THREAD_LOCAL *key);
""",
    "CRYPTO_THREAD_get_local",
)

patch_both(
    "crypto.h",
    """int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key);

CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void);
int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b);
""",
    """/**
 * @brief Destroy a thread-local key previously created with CRYPTO_THREAD_init_local().
 * @param key Key to clean up (invalid after success).
 * @return 1 on success, or 0 on failure.
 */
int CRYPTO_THREAD_cleanup_local(CRYPTO_THREAD_LOCAL *key);

/**
 * @brief Return an identifier for the calling thread.
 * @return Opaque CRYPTO_THREAD_ID for the current thread.
 */
CRYPTO_THREAD_ID CRYPTO_THREAD_get_current_id(void);
/**
 * @brief Compare two CRYPTO_THREAD_ID values for equality.
 * @param a First thread id.
 * @param b Second thread id.
 * @return 1 if @p a and @p b identify the same thread, or 0 otherwise.
 */
int CRYPTO_THREAD_compare_id(CRYPTO_THREAD_ID a, CRYPTO_THREAD_ID b);
""",
    "CRYPTO_THREAD_cleanup/id*",
)

patch_both(
    "crypto.h",
    """int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *ctx, const char *config_file);
""",
    """/**
 * @brief Load providers and configuration directives from @p config_file into @p ctx.
 * @param ctx Library context to configure.
 * @param config_file Path to an OpenSSL configuration file.
 * @return 1 on success, or 0 on failure.
 */
int OSSL_LIB_CTX_load_config(OSSL_LIB_CTX *ctx, const char *config_file);
""",
    "OSSL_LIB_CTX_load_config",
)

patch_both(
    "crypto.h",
    """OSSL_LIB_CTX *OSSL_LIB_CTX_get0_global_default(void);
""",
    """/**
 * @brief Return the process-wide global default OSSL_LIB_CTX (not thread-local).
 * @return Borrowed pointer to the global default context; do not free.
 */
OSSL_LIB_CTX *OSSL_LIB_CTX_get0_global_default(void);
""",
    "OSSL_LIB_CTX_get0_global_default",
)

# ----- cryptoerr_legacy -----
patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_BN_strings(void);
""",
    """/**
 * @brief Load BN library error strings (no-op in OpenSSL 3; deprecated).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_BN_strings(void);
""",
    "ERR_load_BN_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_EC_strings(void);
""",
    """/**
 * @brief Load EC library error strings (no-op in OpenSSL 3; deprecated).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_EC_strings(void);
""",
    "ERR_load_EC_strings",
)

patch_one(
    "cryptoerr_legacy.h",
    """OSSL_DEPRECATEDIN_3_0 int ERR_load_EVP_strings(void);
""",
    """/**
 * @brief Load EVP library error strings (no-op in OpenSSL 3; deprecated).
 * @return 1.
 */
OSSL_DEPRECATEDIN_3_0 int ERR_load_EVP_strings(void);
""",
    "ERR_load_EVP_strings",
)

# ----- dsa -----
patch_one(
    "dsa.h",
    """OSSL_DEPRECATEDIN_3_0 int DSA_meth_set1_name(DSA_METHOD *dsam,
    const char *name);
""",
    """/**
 * @brief Set the descriptive name of a DSA_METHOD (deprecated).
 * @param dsam Method object to update.
 * @param name NUL-terminated name copied into @p dsam.
 * @return 1 on success, or 0 on failure.
 */
OSSL_DEPRECATEDIN_3_0 int DSA_meth_set1_name(DSA_METHOD *dsam,
    const char *name);
""",
    "DSA_meth_set1_name",
)

# ----- err -----
patch_both(
    "err.h",
    """unsigned long ERR_peek_last_error_line(const char **file, int *line);
""",
    """/**
 * @brief Peek at the newest error code and optionally its source file/line.
 * @param file Receives the source file name associated with the error, or may be NULL.
 * @param line Receives the source line number associated with the error, or may be NULL.
 * @return Newest error code, or 0 if the queue is empty (queue unchanged).
 */
unsigned long ERR_peek_last_error_line(const char **file, int *line);
""",
    "ERR_peek_last_error_line",
)

patch_both(
    "err.h",
    """int ERR_clear_last_mark(void);
""",
    """/**
 * @brief Remove the most recently set error-stack mark without popping errors.
 * @return 1 if a mark was cleared, or 0 if no mark was active.
 */
int ERR_clear_last_mark(void);
""",
    "ERR_clear_last_mark",
)

# ----- evp -----
patch_one(
    "evp.h",
    """int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len);
""",
    """/**
 * @brief Assign the algorithm type of @p pkey from an algorithm name string.
 * @param pkey Key object to type.
 * @param str Algorithm name bytes (need not be NUL-terminated when @p len >= 0).
 * @param len Length of @p str, or -1 if @p str is NUL-terminated.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_set_type_str(EVP_PKEY *pkey, const char *str, int len);
""",
    "EVP_PKEY_set_type_str",
)

patch_one(
    "evp.h",
    """OSSL_DEPRECATEDIN_3_0
const struct ec_key_st *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);
""",
    """/**
 * @brief Return a borrowed pointer to the EC_KEY held by @p pkey (deprecated).
 * @param pkey Key that must hold an EC key.
 * @return Internal EC_KEY pointer (do not free), or NULL if not an EC key.
 */
OSSL_DEPRECATEDIN_3_0
const struct ec_key_st *EVP_PKEY_get0_EC_KEY(const EVP_PKEY *pkey);
""",
    "EVP_PKEY_get0_EC_KEY",
)

patch_one(
    "evp.h",
    """int EVP_SIGNATURE_up_ref(EVP_SIGNATURE *signature);
""",
    """/**
 * @brief Increment the reference count on a fetched EVP_SIGNATURE algorithm.
 * @param signature Signature algorithm from EVP_SIGNATURE_fetch().
 * @return 1 on success, or 0 on failure.
 */
int EVP_SIGNATURE_up_ref(EVP_SIGNATURE *signature);
""",
    "EVP_SIGNATURE_up_ref",
)

# ----- kdf -----
patch_one(
    "kdf.h",
    """int EVP_KDF_get_params(EVP_KDF *kdf, OSSL_PARAM params[]);
""",
    """/**
 * @brief Retrieve algorithm-level OSSL_PARAM values from a fetched EVP_KDF.
 * @param kdf Fetched KDF algorithm.
 * @param params NULL-terminated parameter array to fill.
 * @return 1 on success, or 0 on error.
 */
int EVP_KDF_get_params(EVP_KDF *kdf, OSSL_PARAM params[]);
""",
    "EVP_KDF_get_params",
)

patch_one(
    "kdf.h",
    """const OSSL_PARAM *EVP_KDF_gettable_ctx_params(const EVP_KDF *kdf);
""",
    """/**
 * @brief Return OSSL_PARAM descriptors that can be retrieved from an EVP_KDF_CTX.
 * @param kdf Fetched KDF algorithm whose context gettable params are queried.
 * @return Array of OSSL_PARAM descriptors terminated by an end sentinel, or NULL.
 */
const OSSL_PARAM *EVP_KDF_gettable_ctx_params(const EVP_KDF *kdf);
""",
    "EVP_KDF_gettable_ctx_params",
)

patch_one(
    "kdf.h",
    """void EVP_KDF_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KDF *kdf, void *arg),
    void *arg);
""",
    """/**
 * @brief Invoke @p fn for every KDF algorithm available from @p libctx providers.
 * @param libctx Library context to search, or NULL for the default.
 * @param fn Callback receiving each fetched EVP_KDF and @p arg.
 * @param arg Opaque pointer passed through to @p fn.
 */
void EVP_KDF_do_all_provided(OSSL_LIB_CTX *libctx,
    void (*fn)(EVP_KDF *kdf, void *arg),
    void *arg);
""",
    "EVP_KDF_do_all_provided",
)

patch_one(
    "kdf.h",
    """int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX *ctx, int mode);
""",
    """/**
 * @brief Select HKDF extract/expand mode on a key-derivation EVP_PKEY_CTX.
 * @param ctx HKDF derivation context.
 * @param mode EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND, EXTRACT_ONLY, or EXPAND_ONLY.
 * @return 1 on success, or 0 on error.
 */
int EVP_PKEY_CTX_set_hkdf_mode(EVP_PKEY_CTX *ctx, int mode);
""",
    "EVP_PKEY_CTX_set_hkdf_mode",
)

# ----- lhash -----
patch_both(
    "lhash.h",
    """typedef int (*OPENSSL_LH_COMPFUNC)(const void *, const void *);
""",
    """/**
 * @brief Comparison callback returning <0 / 0 / >0 for two LHASH element pointers.
 * @param a First element pointer.
 * @param b Second element pointer.
 * @return Negative, zero, or positive as in strcmp()-style ordering.
 */
typedef int (*OPENSSL_LH_COMPFUNC)(const void *a, const void *b);
""",
    "OPENSSL_LH_COMPFUNC",
)

patch_both(
    "lhash.h",
    """void *OPENSSL_LH_insert(OPENSSL_LHASH *lh, void *data);
""",
    """/**
 * @brief Insert @p data into an LHASH, replacing any equal existing element.
 * @param lh Hash table.
 * @param data Element to insert (ownership typically remains with the table).
 * @return Previously stored equal element, or NULL if none / on error (check ERR).
 */
void *OPENSSL_LH_insert(OPENSSL_LHASH *lh, void *data);
""",
    "OPENSSL_LH_insert",
)

patch_both(
    "lhash.h",
    """void OPENSSL_LH_doall_arg(OPENSSL_LHASH *lh,
    OPENSSL_LH_DOALL_FUNCARG func, void *arg);
""",
    """/**
 * @brief Invoke @p func for every element in an LHASH, passing caller argument @p arg.
 * @param lh Hash table to traverse.
 * @param func Callback receiving each element pointer and @p arg.
 * @param arg Opaque pointer forwarded to @p func.
 */
void OPENSSL_LH_doall_arg(OPENSSL_LHASH *lh,
    OPENSSL_LH_DOALL_FUNCARG func, void *arg);
""",
    "OPENSSL_LH_doall_arg",
)

patch_both(
    "lhash.h",
    """unsigned long OPENSSL_LH_get_down_load(const OPENSSL_LHASH *lh);
void OPENSSL_LH_set_down_load(OPENSSL_LHASH *lh, unsigned long down_load);
""",
    """/**
 * @brief Return the load factor threshold that triggers LHASH contraction.
 * @param lh Hash table to query.
 * @return Current down_load value (items-per-bucket style threshold).
 */
unsigned long OPENSSL_LH_get_down_load(const OPENSSL_LHASH *lh);
/**
 * @brief Set the load factor threshold that triggers LHASH contraction.
 * @param lh Hash table to update.
 * @param down_load New down_load threshold.
 */
void OPENSSL_LH_set_down_load(OPENSSL_LHASH *lh, unsigned long down_load);
""",
    "OPENSSL_LH_*_down_load",
)

patch_both(
    "lhash.h",
    """OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_stats(const OPENSSL_LHASH *lh, FILE *fp);
""",
    """/**
 * @brief Print summary statistics for an LHASH to @p fp (deprecated).
 * @param lh Hash table to describe.
 * @param fp Output stream.
 */
OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_stats(const OPENSSL_LHASH *lh, FILE *fp);
""",
    "OPENSSL_LH_stats",
)

patch_both(
    "lhash.h",
    """OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_node_usage_stats(const OPENSSL_LHASH *lh, FILE *fp);
""",
    """/**
 * @brief Print node-usage / collision statistics for an LHASH to @p fp (deprecated).
 * @param lh Hash table to describe.
 * @param fp Output stream.
 */
OSSL_DEPRECATEDIN_3_1 void OPENSSL_LH_node_usage_stats(const OPENSSL_LHASH *lh, FILE *fp);
""",
    "OPENSSL_LH_node_usage_stats",
)

# ----- params -----
patch_one(
    "params.h",
    """OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
    size_t bsize);
""",
    """/**
 * @brief Construct an OSSL_PARAM describing an arbitrary-precision integer in @p buf.
 * @param key Parameter name.
 * @param buf Buffer holding (or receiving) the BN in native unsigned big-endian form.
 * @param bsize Capacity of @p buf in bytes.
 * @return OSSL_PARAM suitable for inclusion in a parameter array.
 */
OSSL_PARAM OSSL_PARAM_construct_BN(const char *key, unsigned char *buf,
    size_t bsize);
""",
    "OSSL_PARAM_construct_BN",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val);
""",
    """/**
 * @brief Read an unsigned int parameter value from @p p into *@p val.
 * @param p Parameter locator describing an unsigned integer-typed value.
 * @param val Receives the converted unsigned int.
 * @return 1 on success, or 0 on type/range failure.
 */
int OSSL_PARAM_get_uint(const OSSL_PARAM *p, unsigned int *val);
""",
    "OSSL_PARAM_get_uint",
)

patch_one(
    "params.h",
    """int OSSL_PARAM_set_utf8_string(OSSL_PARAM *p, const char *val);
""",
    """/**
 * @brief Write a NUL-terminated UTF-8 string into an OSSL_PARAM destination.
 * @param p Parameter locating a writable UTF-8 string buffer.
 * @param val String to copy (may be truncated to the parameter's size).
 * @return 1 on success, or 0 on failure.
 */
int OSSL_PARAM_set_utf8_string(OSSL_PARAM *p, const char *val);
""",
    "OSSL_PARAM_set_utf8_string",
)

# ----- pem -----
patch_one(
    "pem.h",
    """int PEM_def_callback(char *buf, int num, int rwflag, void *userdata);
""",
    """/**
 * @brief Default pem_password_cb that prompts on the terminal (or copies @p userdata).
 * @param buf Destination buffer for the password bytes.
 * @param num Capacity of @p buf in bytes.
 * @param rwflag 0 when reading/decrypting, non-zero when writing/encrypting.
 * @param userdata Optional default password string, or NULL to prompt.
 * @return Password length written to @p buf, or 0 on failure / empty input.
 */
int PEM_def_callback(char *buf, int num, int rwflag, void *userdata);
""",
    "PEM_def_callback",
)

# ----- sha -----
patch_one(
    "sha.h",
    """OSSL_DEPRECATEDIN_3_0 void SHA256_Transform(SHA256_CTX *c,
    const unsigned char *data);
""",
    """/**
 * @brief Process one 64-byte SHA-256 block into digest state @p c (deprecated).
 * @param c SHA-256 context whose state words are updated.
 * @param data Pointer to a single 64-byte message block.
 */
OSSL_DEPRECATEDIN_3_0 void SHA256_Transform(SHA256_CTX *c,
    const unsigned char *data);
""",
    "SHA256_Transform",
)

# ----- stack -----
patch_one(
    "stack.h",
    """void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data);
""",
    """/**
 * @brief Replace the pointer at index @p i in a stack.
 * @param st Stack to update.
 * @param i Zero-based index of the slot to replace.
 * @param data New element pointer stored at @p i.
 * @return Previous pointer at @p i, or NULL if @p i is out of range.
 */
void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data);
""",
    "OPENSSL_sk_set",
)

patch_one(
    "stack.h",
    """OPENSSL_STACK *OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc c, int n);
""",
    """/**
 * @brief Allocate a stack with comparison function @p c and room for @p n elements.
 * @param c Comparison callback, or NULL for an unordered stack.
 * @param n Number of element slots to reserve up front.
 * @return New stack, or NULL on failure; free with OPENSSL_sk_free().
 */
OPENSSL_STACK *OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc c, int n);
""",
    "OPENSSL_sk_new_reserve",
)

patch_one(
    "stack.h",
    """OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK *sk,
    OPENSSL_sk_compfunc cmp);
OPENSSL_STACK *OPENSSL_sk_dup(const OPENSSL_STACK *st);
void OPENSSL_sk_sort(OPENSSL_STACK *st);
""",
    """/**
 * @brief Install a comparison function on a stack and mark it as unsorted.
 * @param sk Stack to update.
 * @param cmp New comparison callback, or NULL to clear ordering.
 * @return Previous comparison function, or NULL.
 */
OPENSSL_sk_compfunc OPENSSL_sk_set_cmp_func(OPENSSL_STACK *sk,
    OPENSSL_sk_compfunc cmp);
/**
 * @brief Shallow-copy a stack (element pointers are duplicated, not deep-copied).
 * @param st Source stack.
 * @return New stack with the same element pointers, or NULL on failure.
 */
OPENSSL_STACK *OPENSSL_sk_dup(const OPENSSL_STACK *st);
/**
 * @brief Sort a stack in place using its comparison function.
 * @param st Stack to sort; no-op if no comparison function is set.
 */
void OPENSSL_sk_sort(OPENSSL_STACK *st);
""",
    "OPENSSL_sk_set_cmp/dup/sort",
)

print(f"\nOK {len(ok)}, MISS {len(missing)}")
for m in missing:
    print(" ", m)
