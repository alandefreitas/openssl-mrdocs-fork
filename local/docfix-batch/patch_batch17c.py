#!/usr/bin/env python3
"""Documentation repair batch 17c: err.h err_state_st fields and ERR API."""
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


print("=== batch 17c: err.h ===")

# ----- err_state_st fields -----

patch_both(
    "err.h",
    """struct err_state_st {
    int err_flags[ERR_NUM_ERRORS];
""",
    """struct err_state_st {
    /** Per-slot internal flags (for example ERR_FLAG_MARK, ERR_FLAG_CLEAR). */
    int err_flags[ERR_NUM_ERRORS];
""",
    "err_state_st.err_flags",
)

patch_both(
    "err.h",
    """    int err_marks[ERR_NUM_ERRORS];
""",
    """    /** Mark nesting depth at each ring-buffer slot (used by ERR_set_mark()). */
    int err_marks[ERR_NUM_ERRORS];
""",
    "err_state_st.err_marks",
)

patch_both(
    "err.h",
    """    unsigned long err_buffer[ERR_NUM_ERRORS];
""",
    """    /** Packed error code stored in each slot (OpenSSL or system error). */
    unsigned long err_buffer[ERR_NUM_ERRORS];
""",
    "err_state_st.err_buffer",
)

patch_both(
    "err.h",
    """    int err_data_flags[ERR_NUM_ERRORS];
""",
    """    /** ERR_TXT_* flags describing how @c err_data[i] is owned and formatted. */
    int err_data_flags[ERR_NUM_ERRORS];
""",
    "err_state_st.err_data_flags",
)

patch_both(
    "err.h",
    """    int err_line[ERR_NUM_ERRORS];
""",
    """    /** Source line number for each error (-1 when unset). */
    int err_line[ERR_NUM_ERRORS];
""",
    "err_state_st.err_line",
)

patch_both(
    "err.h",
    """    char *err_func[ERR_NUM_ERRORS];
    int top, bottom;
""",
    """    char *err_func[ERR_NUM_ERRORS];
    /** Index of the newest error slot in the ring buffer. */
    int top;
    /** Index of the oldest error slot in the ring buffer. */
    int bottom;
""",
    "err_state_st.top/bottom",
)

# ----- inline helpers -----

patch_both(
    "err.h",
    """static ossl_unused ossl_inline int ERR_GET_LIB(unsigned long errcode)
""",
    """/**
 * @brief Extract the library number from a packed OpenSSL error code.
 * @param errcode Error code as returned by ERR_get_error() or ERR_peek_error().
 * @return ERR_LIB_* library number, or ERR_LIB_SYS for a recorded system error.
 */
static ossl_unused ossl_inline int ERR_GET_LIB(unsigned long errcode)
""",
    "ERR_GET_LIB",
)

patch_both(
    "err.h",
    """static ossl_unused ossl_inline int ERR_GET_REASON(unsigned long errcode)
""",
    """/**
 * @brief Extract the reason code from a packed OpenSSL or system error code.
 * @param errcode Error code as returned by ERR_get_error() or ERR_peek_error().
 * @return Reason code within the library, or the errno value for a system error.
 */
static ossl_unused ossl_inline int ERR_GET_REASON(unsigned long errcode)
""",
    "ERR_GET_REASON",
)

# ----- building blocks -----

patch_both(
    "err.h",
    """void ERR_set_debug(const char *file, int line, const char *func);
""",
    """/**
 * @brief Attach source location debug information to the current error-queue entry.
 * @param file Source file name pointer (must remain valid; not copied).
 * @param line Source line number.
 * @param func Function name pointer (must remain valid; not copied).
 */
void ERR_set_debug(const char *file, int line, const char *func);
""",
    "ERR_set_debug",
)

patch_both(
    "err.h",
    """void ERR_set_error(int lib, int reason, const char *fmt, ...);
""",
    """/**
 * @brief Set library, reason, and optional formatted auxiliary data on the current error entry.
 * @param lib ERR_LIB_* library number for the error.
 * @param reason Reason code within @p lib (or errno when @p lib is ERR_LIB_SYS).
 * @param fmt printf-style format for extra data, or NULL for none.
 * @param ... Arguments for @p fmt; stored in a newly allocated string when @p fmt is non-NULL.
 */
void ERR_set_error(int lib, int reason, const char *fmt, ...);
""",
    "ERR_set_error",
)

patch_both(
    "err.h",
    """void ERR_set_error_data(char *data, int flags);
""",
    """/**
 * @brief Replace auxiliary data on the most recent error, taking ownership when flagged.
 * @param data Auxiliary string or buffer; ownership transfers if @p flags includes ERR_TXT_MALLOCED.
 * @param flags ERR_TXT_MALLOCED and/or ERR_TXT_STRING describing @p data.
 */
void ERR_set_error_data(char *data, int flags);
""",
    "ERR_set_error_data",
)

# ----- error queue access -----

patch_both(
    "err.h",
    """unsigned long ERR_get_error_all(const char **file, int *line,
    const char **func,
    const char **data, int *flags);
""",
    """/**
 * @brief Pop the earliest error and optionally return file, line, function, data, and flags.
 * @param file Receives the source file name, or unchanged if NULL.
 * @param line Receives the source line number, or unchanged if NULL.
 * @param func Receives the function name, or unchanged if NULL.
 * @param data Receives optional auxiliary data, or unchanged if NULL.
 * @param flags Receives ERR_TXT_* flags for @p data, or unchanged if NULL.
 * @return Packed error code, or 0 if the queue is empty.
 */
unsigned long ERR_get_error_all(const char **file, int *line,
    const char **func,
    const char **data, int *flags);
""",
    "ERR_get_error_all",
)

patch_both(
    "err.h",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0
unsigned long ERR_get_error_line(const char **file, int *line);
""",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Pop the earliest error and optionally return file and line (deprecated).
 * @param file Receives the source file name, or unchanged if NULL.
 * @param line Receives the source line number, or unchanged if NULL.
 * @return Packed error code, or 0 if the queue is empty.
 */
OSSL_DEPRECATEDIN_3_0
unsigned long ERR_get_error_line(const char **file, int *line);
""",
    "ERR_get_error_line",
)

patch_both(
    "err.h",
    """OSSL_DEPRECATEDIN_3_0
unsigned long ERR_get_error_line_data(const char **file, int *line,
    const char **data, int *flags);
""",
    """/**
 * @brief Pop the earliest error with file, line, data, and flags (deprecated).
 * @param file Receives the source file name, or unchanged if NULL.
 * @param line Receives the source line number, or unchanged if NULL.
 * @param data Receives optional auxiliary data, or unchanged if NULL.
 * @param flags Receives ERR_TXT_* flags for @p data, or unchanged if NULL.
 * @return Packed error code, or 0 if the queue is empty.
 */
OSSL_DEPRECATEDIN_3_0
unsigned long ERR_get_error_line_data(const char **file, int *line,
    const char **data, int *flags);
""",
    "ERR_get_error_line_data",
)

patch_both(
    "err.h",
    """unsigned long ERR_peek_error(void);
""",
    """/**
 * @brief Return the earliest error code without removing it from the queue.
 * @return Packed error code, or 0 if the queue is empty.
 */
unsigned long ERR_peek_error(void);
""",
    "ERR_peek_error",
)

patch_both(
    "err.h",
    """unsigned long ERR_peek_error_func(const char **func);
""",
    """/**
 * @brief Peek at the earliest error and optionally return its function name.
 * @param func Receives the function name string, or unchanged if NULL.
 * @return Earliest error code, or 0 if the queue is empty (queue unchanged).
 */
unsigned long ERR_peek_error_func(const char **func);
""",
    "ERR_peek_error_func",
)

patch_both(
    "err.h",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0
unsigned long ERR_peek_error_line_data(const char **file, int *line,
    const char **data, int *flags);
""",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Peek at the earliest error with file, line, data, and flags (deprecated).
 * @param file Receives the source file name, or unchanged if NULL.
 * @param line Receives the source line number, or unchanged if NULL.
 * @param data Receives optional auxiliary data, or unchanged if NULL.
 * @param flags Receives ERR_TXT_* flags for @p data, or unchanged if NULL.
 * @return Earliest error code, or 0 if the queue is empty (queue unchanged).
 */
OSSL_DEPRECATEDIN_3_0
unsigned long ERR_peek_error_line_data(const char **file, int *line,
    const char **data, int *flags);
""",
    "ERR_peek_error_line_data",
)

patch_both(
    "err.h",
    """unsigned long ERR_peek_last_error_data(const char **data, int *flags);
""",
    """/**
 * @brief Peek at the newest error and optionally return auxiliary data and flags.
 * @param data Receives optional auxiliary data, or unchanged if NULL.
 * @param flags Receives ERR_TXT_* flags for @p data, or unchanged if NULL.
 * @return Newest error code, or 0 if the queue is empty (queue unchanged).
 */
unsigned long ERR_peek_last_error_data(const char **data, int *flags);
""",
    "ERR_peek_last_error_data",
)

patch_both(
    "err.h",
    """unsigned long ERR_peek_last_error_all(const char **file, int *line,
    const char **func,
    const char **data, int *flags);
""",
    """/**
 * @brief Peek at the newest error and optionally return file, line, function, data, and flags.
 * @param file Receives the source file name, or unchanged if NULL.
 * @param line Receives the source line number, or unchanged if NULL.
 * @param func Receives the function name, or unchanged if NULL.
 * @param data Receives optional auxiliary data, or unchanged if NULL.
 * @param flags Receives ERR_TXT_* flags for @p data, or unchanged if NULL.
 * @return Newest error code, or 0 if the queue is empty (queue unchanged).
 */
unsigned long ERR_peek_last_error_all(const char **file, int *line,
    const char **func,
    const char **data, int *flags);
""",
    "ERR_peek_last_error_all",
)

# ----- error strings -----

patch_both(
    "err.h",
    """char *ERR_error_string(unsigned long e, char *buf);
""",
    """/**
 * @brief Format a human-readable description of error code @p e into a buffer.
 * @param e Packed error code from ERR_get_error() or similar.
 * @param buf Destination buffer of at least 256 bytes, or NULL to use a static buffer (not thread-safe).
 * @return Pointer to @p buf, or to the static buffer when @p buf is NULL.
 */
char *ERR_error_string(unsigned long e, char *buf);
""",
    "ERR_error_string",
)

patch_both(
    "err.h",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0 const char *ERR_func_error_string(unsigned long e);
""",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the function name for a packed error code (deprecated; always returns NULL in 3.0).
 * @param e Packed error code (function field is ignored).
 * @return Always NULL in OpenSSL 3.0 and later.
 */
OSSL_DEPRECATEDIN_3_0 const char *ERR_func_error_string(unsigned long e);
""",
    "ERR_func_error_string",
)

patch_both(
    "err.h",
    """const char *ERR_reason_error_string(unsigned long e);
""",
    """/**
 * @brief Return the registered reason-string for a packed error code.
 * @param e Packed error code whose reason field is looked up.
 * @return Reason description string (do not free), or NULL if none is registered.
 */
const char *ERR_reason_error_string(unsigned long e);
""",
    "ERR_reason_error_string",
)

# ----- printing -----

patch_both(
    "err.h",
    """void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
    void *u);
""",
    """/**
 * @brief Print and clear all queued errors, invoking @p cb for each formatted line.
 * @param cb Callback receiving each error line and @p u; return value is ignored.
 * @param u Opaque argument passed to @p cb.
 */
void ERR_print_errors_cb(int (*cb)(const char *str, size_t len, void *u),
    void *u);
""",
    "ERR_print_errors_cb",
)

patch_both(
    "err.h",
    """#ifndef OPENSSL_NO_STDIO
void ERR_print_errors_fp(FILE *fp);
""",
    """#ifndef OPENSSL_NO_STDIO
/**
 * @brief Print and clear all queued OpenSSL errors to stdio stream @p fp.
 * @param fp Destination FILE (for example stderr).
 */
void ERR_print_errors_fp(FILE *fp);
""",
    "ERR_print_errors_fp",
)

# ----- add error data -----

patch_both(
    "err.h",
    """void ERR_add_error_data(int num, ...);
""",
    """/**
 * @brief Append concatenated C strings as auxiliary data to the most recent error.
 * @param num Number of following @c char * arguments to concatenate.
 * @param ... @p num NUL-terminated strings; total length per error is capped at 4096 bytes.
 */
void ERR_add_error_data(int num, ...);
""",
    "ERR_add_error_data",
)

patch_both(
    "err.h",
    """void ERR_add_error_txt(const char *sepr, const char *txt);
""",
    """/**
 * @brief Append text to the most recent error, optionally inserting a separator first.
 * @param sepr Separator inserted before @p txt when the top entry has no data yet, or NULL.
 * @param txt Additional text to append (may be split across new queue entries if too long).
 */
void ERR_add_error_txt(const char *sepr, const char *txt);
""",
    "ERR_add_error_txt",
)

patch_both(
    "err.h",
    """void ERR_add_error_mem_bio(const char *sep, BIO *bio);
""",
    """/**
 * @brief Append the contents of memory BIO @p bio as auxiliary data to the most recent error.
 * @param sep Optional separator inserted before the BIO contents when needed, or NULL.
 * @param bio Memory BIO whose contents are appended (a trailing NUL is added if missing).
 */
void ERR_add_error_mem_bio(const char *sep, BIO *bio);
""",
    "ERR_add_error_mem_bio",
)

# ----- string tables -----

patch_both(
    "err.h",
    """int ERR_load_strings(int lib, ERR_STRING_DATA *str);
""",
    """/**
 * @brief Register a mutable ERR_STRING_DATA table for library @p lib.
 * @param lib ERR_LIB_* library number the strings belong to.
 * @param str Array of {error, string} pairs terminated by {0, NULL}.
 * @return 1 on success, or 0 on failure.
 */
int ERR_load_strings(int lib, ERR_STRING_DATA *str);
""",
    "ERR_load_strings",
)

patch_both(
    "err.h",
    """int ERR_unload_strings(int lib, ERR_STRING_DATA *str);
""",
    """/**
 * @brief Remove previously registered error strings for library @p lib.
 * @param lib ERR_LIB_* library number passed to ERR_load_strings().
 * @param str Same table pointer used with ERR_load_strings() (entries must match).
 * @return 1 on success, or 0 on failure.
 */
int ERR_unload_strings(int lib, ERR_STRING_DATA *str);
""",
    "ERR_unload_strings",
)

# ----- thread state (deprecated) -----

patch_both(
    "err.h",
    """#ifndef OPENSSL_NO_DEPRECATED_1_1_0
OSSL_DEPRECATEDIN_1_1_0 void ERR_remove_thread_state(void *);
""",
    """#ifndef OPENSSL_NO_DEPRECATED_1_1_0
/**
 * @brief Free the error queue for a thread identifier (deprecated; automatic since 1.1.0).
 * @param tid Opaque thread identifier, or NULL for the current thread.
 */
OSSL_DEPRECATEDIN_1_1_0 void ERR_remove_thread_state(void *);
""",
    "ERR_remove_thread_state",
)

patch_both(
    "err.h",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
OSSL_DEPRECATEDIN_3_0 ERR_STATE *ERR_get_state(void);
""",
    """#ifndef OPENSSL_NO_DEPRECATED_3_0
/**
 * @brief Return the current thread's ERR_STATE (deprecated internal accessor).
 * @return Thread-local error state, or NULL on allocation failure.
 */
OSSL_DEPRECATEDIN_3_0 ERR_STATE *ERR_get_state(void);
""",
    "ERR_get_state",
)

# ----- marks and pop -----

patch_both(
    "err.h",
    """int ERR_set_mark(void);
""",
    """/**
 * @brief Place a mark on the current topmost error-queue entry.
 * @return 1 if a mark was placed, or 0 if the queue is empty.
 */
int ERR_set_mark(void);
""",
    "ERR_set_mark",
)

patch_both(
    "err.h",
    """int ERR_pop(void);
""",
    """/**
 * @brief Unconditionally remove the newest error from the queue.
 * @return 1 if an error was removed, or 0 if the queue was empty.
 */
int ERR_pop(void);
""",
    "ERR_pop",
)

# ----- saved error state -----

patch_both(
    "err.h",
    """ERR_STATE *OSSL_ERR_STATE_new(void);
""",
    """/**
 * @brief Allocate an empty saved error-state object.
 * @return New ERR_STATE for use with OSSL_ERR_STATE_save(), or NULL on failure.
 */
ERR_STATE *OSSL_ERR_STATE_new(void);
""",
    "OSSL_ERR_STATE_new",
)

patch_both(
    "err.h",
    """void OSSL_ERR_STATE_save_to_mark(ERR_STATE *es);
""",
    """/**
 * @brief Move errors above the most recent mark from the thread queue into @p es.
 * @param es Destination from OSSL_ERR_STATE_new(); prior contents are cleared first.
 */
void OSSL_ERR_STATE_save_to_mark(ERR_STATE *es);
""",
    "OSSL_ERR_STATE_save_to_mark",
)

patch_both(
    "err.h",
    """void OSSL_ERR_STATE_restore(const ERR_STATE *es);
""",
    """/**
 * @brief Append errors saved in @p es onto the current thread's error queue.
 * @param es Saved state from OSSL_ERR_STATE_save() or OSSL_ERR_STATE_save_to_mark().
 */
void OSSL_ERR_STATE_restore(const ERR_STATE *es);
""",
    "OSSL_ERR_STATE_restore",
)

patch_both(
    "err.h",
    """void OSSL_ERR_STATE_free(ERR_STATE *es);
""",
    """/**
 * @brief Free a saved error-state object and its duplicated auxiliary data.
 * @param es Object from OSSL_ERR_STATE_new(), or NULL (no-op).
 */
void OSSL_ERR_STATE_free(ERR_STATE *es);
""",
    "OSSL_ERR_STATE_free",
)

print(f"\nOK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  {m}")
