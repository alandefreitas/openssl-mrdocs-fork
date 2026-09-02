#!/usr/bin/env python3
"""Documentation repair batch 16: asn1.h / asn1.h.in."""
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


print("=== batch 16: asn1.h ===")

# ----- asn1_string_st fields: data, flags -----

patch_both(
    "asn1.h",
    """    int type;
    unsigned char *data;
    /*
     * The value of the following field depends on the type being held.  It
     * is mostly being used for BIT_STRING so if the input data has a
     * non-zero 'unused bits' value, it will be handled correctly
     */
    long flags;
""",
    """    int type;
    /** Content octets; length is given by @c length (may be NULL when empty). */
    unsigned char *data;
    /**
     * Type-dependent flags (ASN1_STRING_FLAG_*); for BIT STRING, unused-bits
     * and related encoding details are recorded here.
     */
    long flags;
""",
    "asn1_string_st::data+flags",
)

# ----- ASN1_ENCODING typedef -----

patch_both(
    "asn1.h",
    """/*
 * ASN1_ENCODING structure: this is used to save the received encoding of an
 * ASN1 type. This is useful to get round problems with invalid encodings
 * which can break signatures.
 */

typedef struct ASN1_ENCODING_st {
""",
    """/**
 * @brief Saved DER encoding of an ASN.1 value, used when re-emitting the
 * original bytes (for example so invalid encodings do not break signatures).
 */
typedef struct ASN1_ENCODING_st {
""",
    "ASN1_ENCODING",
)

# ----- asn1_string_table_st: maxsize, mask -----

patch_both(
    "asn1.h",
    """    int nid;
    long minsize;
    long maxsize;
    unsigned long mask;
    /** STABLE_FLAGS_* bits controlling how the table entry is applied. */
    unsigned long flags;
""",
    """    int nid;
    long minsize;
    /** Maximum allowed string size in characters for this NID (-1 = unlimited). */
    long maxsize;
    /** B_ASN1_* bitmask of permitted string types for this NID. */
    unsigned long mask;
    /** STABLE_FLAGS_* bits controlling how the table entry is applied. */
    unsigned long flags;
""",
    "asn1_string_table_st::maxsize+mask",
)

# ----- ASN1_TLC / ASN1_TLC_st -----

patch_both(
    "asn1.h",
    """typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
typedef struct ASN1_TLC_st ASN1_TLC;
""",
    """typedef struct ASN1_TEMPLATE_st ASN1_TEMPLATE;
/**
 * @brief Opaque ASN.1 tag/length cache (struct ASN1_TLC_st) used while
 * decoding constructed types; layout is private to the ASN.1 implementation.
 */
typedef struct ASN1_TLC_st ASN1_TLC;
""",
    "ASN1_TLC",
)

# ----- ASN1_TYPE union arms -----

patch_both(
    "asn1.h",
    """        /** INTEGER value when type is V_ASN1_INTEGER. */
        ASN1_INTEGER *integer;
        ASN1_ENUMERATED *enumerated;
""",
    """        /** INTEGER value when type is V_ASN1_INTEGER. */
        ASN1_INTEGER *integer;
        /** ENUMERATED value when type is V_ASN1_ENUMERATED. */
        ASN1_ENUMERATED *enumerated;
""",
    "enumerated",
)

patch_both(
    "asn1.h",
    """        ASN1_PRINTABLESTRING *printablestring;
        /** TeletexString / T61String value when type is V_ASN1_T61STRING. */
        ASN1_T61STRING *t61string;
        ASN1_IA5STRING *ia5string;
""",
    """        ASN1_PRINTABLESTRING *printablestring;
        /** TeletexString / T61String value when type is V_ASN1_T61STRING. */
        ASN1_T61STRING *t61string;
        /** IA5String value when type is V_ASN1_IA5STRING. */
        ASN1_IA5STRING *ia5string;
""",
    "ia5string",
)

patch_both(
    "asn1.h",
    """        /** Raw ASN.1 SEQUENCE contents when type is V_ASN1_SEQUENCE. */
        ASN1_STRING *sequence;
        ASN1_VALUE *asn1_value;
""",
    """        /** Raw ASN.1 SEQUENCE contents when type is V_ASN1_SEQUENCE. */
        ASN1_STRING *sequence;
        /** Generic ASN1_VALUE pointer for OTHER / opaque ANY payloads. */
        ASN1_VALUE *asn1_value;
""",
    "asn1_value",
)

# ----- stack_st_ASN1_TYPE -----

patch_one(
    "asn1.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(ASN1_TYPE, ASN1_TYPE, ASN1_TYPE)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ASN1_TYPE) container type.
 */
struct stack_st_ASN1_TYPE;
SKM_DEFINE_STACK_OF_INTERNAL(ASN1_TYPE, ASN1_TYPE, ASN1_TYPE)
""",
    "stack_st_ASN1_TYPE",
)

patch_one(
    "asn1.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("ASN1_TYPE");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ASN1_TYPE) container type.
 */
struct stack_st_ASN1_TYPE;
{-
    generate_stack_macros("ASN1_TYPE");
-}
""",
    "stack_st_ASN1_TYPE",
)

# ----- ASN1_SEQUENCE_ANY typedef -----

patch_both(
    "asn1.h",
    """typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;
""",
    """/**
 * @brief Stack of ASN1_TYPE values representing SEQUENCE OF ANY or SET OF ANY.
 */
typedef STACK_OF(ASN1_TYPE) ASN1_SEQUENCE_ANY;
""",
    "ASN1_SEQUENCE_ANY",
)

# ----- ASN1_TYPE_cmp -----

patch_both(
    "asn1.h",
    """int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b);
""",
    """int ASN1_TYPE_set1(ASN1_TYPE *a, int type, const void *value);
/**
 * @brief Compare two ASN1_TYPE values for identical type and content.
 * @param a First ANY value.
 * @param b Second ANY value.
 * @return 0 if @p a and @p b are identical, or nonzero otherwise.
 */
int ASN1_TYPE_cmp(const ASN1_TYPE *a, const ASN1_TYPE *b);
""",
    "ASN1_TYPE_cmp",
)

# ----- ASN1_STRING_new / clear_free / dup / type_new / set / length / type -----

patch_both(
    "asn1.h",
    """ASN1_STRING *ASN1_STRING_new(void);
/**
 * @brief Free an ASN.1 string and its contents.
 * @param a String to free, or NULL.
 */
void ASN1_STRING_free(ASN1_STRING *a);
void ASN1_STRING_clear_free(ASN1_STRING *a);
""",
    """/**
 * @brief Allocate an empty ASN1_STRING with default type V_ASN1_OCTET_STRING.
 * @return New ASN1_STRING, or NULL on allocation failure.
 */
ASN1_STRING *ASN1_STRING_new(void);
/**
 * @brief Free an ASN.1 string and its contents.
 * @param a String to free, or NULL.
 */
void ASN1_STRING_free(ASN1_STRING *a);
/**
 * @brief Zero the content octets then free an ASN.1 string.
 * @param a String to cleanse and free, or NULL.
 */
void ASN1_STRING_clear_free(ASN1_STRING *a);
""",
    "ASN1_STRING_new+clear_free",
)

patch_both(
    "asn1.h",
    """DECLARE_ASN1_DUP_FUNCTION(ASN1_STRING)
ASN1_STRING *ASN1_STRING_type_new(int type);
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);
/*
 * Since this is used to store all sorts of things, via macros, for now,
 * make its data void *
 */
int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
""",
    """/**
 * @brief Deep-copy an ASN.1 string (type, data, and flags).
 * @param a Source string to duplicate.
 * @return Newly allocated ASN1_STRING copy, or NULL on error; free with ASN1_STRING_free().
 */
ASN1_STRING *ASN1_STRING_dup(const ASN1_STRING *a);
/**
 * @brief Allocate an empty ASN1_STRING with the given ASN.1 string type.
 * @param type ASN.1 tag such as V_ASN1_UTF8STRING or V_ASN1_OCTET_STRING.
 * @return New ASN1_STRING, or NULL on allocation failure.
 */
ASN1_STRING *ASN1_STRING_type_new(int type);
int ASN1_STRING_cmp(const ASN1_STRING *a, const ASN1_STRING *b);
/*
 * Since this is used to store all sorts of things, via macros, for now,
 * make its data void *
 */
/**
 * @brief Copy @p data of length @p len into an ASN.1 string.
 * @param str String whose content is replaced with a copy of @p data.
 * @param data Bytes to copy; may be a C string when @p len is -1.
 * @param len Number of bytes at @p data, or -1 to use strlen(@p data).
 * @return 1 on success, or 0 on failure.
 */
int ASN1_STRING_set(ASN1_STRING *str, const void *data, int len);
""",
    "ASN1_STRING_dup+type_new+set",
)

patch_both(
    "asn1.h",
    """void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
int ASN1_STRING_length(const ASN1_STRING *x);
""",
    """void ASN1_STRING_set0(ASN1_STRING *str, void *data, int len);
/**
 * @brief Return the content length of an ASN.1 string in bytes.
 * @param x String to query.
 * @return Number of content octets in @p x.
 */
int ASN1_STRING_length(const ASN1_STRING *x);
""",
    "ASN1_STRING_length",
)

patch_both(
    "asn1.h",
    """OSSL_DEPRECATEDIN_3_0 void ASN1_STRING_length_set(ASN1_STRING *x, int n);
#endif
int ASN1_STRING_type(const ASN1_STRING *x);
""",
    """OSSL_DEPRECATEDIN_3_0 void ASN1_STRING_length_set(ASN1_STRING *x, int n);
#endif
/**
 * @brief Return the ASN.1 type tag stored in an ASN.1 string.
 * @param x String to query.
 * @return Type constant such as V_ASN1_OCTET_STRING.
 */
int ASN1_STRING_type(const ASN1_STRING *x);
""",
    "ASN1_STRING_type",
)

# ----- BIT_STRING get_bit / name_print -----

patch_both(
    "asn1.h",
    """int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
int ASN1_BIT_STRING_get_bit(const ASN1_BIT_STRING *a, int n);
""",
    """int ASN1_BIT_STRING_set_bit(ASN1_BIT_STRING *a, int n, int value);
/**
 * @brief Test whether bit @p n is set in an ASN.1 BIT STRING.
 * @param a Bit string to query; NULL or short strings are treated as clear.
 * @param n Zero-based bit index.
 * @return 1 if the bit is set, or 0 if clear / out of range / @p a is NULL.
 */
int ASN1_BIT_STRING_get_bit(const ASN1_BIT_STRING *a, int n);
""",
    "ASN1_BIT_STRING_get_bit",
)

patch_both(
    "asn1.h",
    """int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
    BIT_STRING_BITNAME *tbl, int indent);
""",
    """/**
 * @brief Print the long names of set bits from a BIT_STRING_BITNAME table.
 * @param out BIO that receives the indented comma-separated names and a newline.
 * @param bs Bit string whose set bits are looked up in @p tbl.
 * @param tbl NULL-terminated table of bit numbers and long names.
 * @param indent Number of spaces written before the first name.
 * @return 1 on success.
 */
int ASN1_BIT_STRING_name_print(BIO *out, ASN1_BIT_STRING *bs,
    BIT_STRING_BITNAME *tbl, int indent);
""",
    "ASN1_BIT_STRING_name_print",
)

# ----- stack_st_ASN1_INTEGER -----

patch_one(
    "asn1.h",
    """/* clang-format off */
SKM_DEFINE_STACK_OF_INTERNAL(ASN1_INTEGER, ASN1_INTEGER, ASN1_INTEGER)
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ASN1_INTEGER) container type.
 */
struct stack_st_ASN1_INTEGER;
SKM_DEFINE_STACK_OF_INTERNAL(ASN1_INTEGER, ASN1_INTEGER, ASN1_INTEGER)
""",
    "stack_st_ASN1_INTEGER",
)

patch_one(
    "asn1.h.in",
    """/* clang-format off */
{-
    generate_stack_macros("ASN1_INTEGER");
-}
""",
    """/* clang-format off */
/**
 * @brief Opaque STACK_OF(ASN1_INTEGER) container type.
 */
struct stack_st_ASN1_INTEGER;
{-
    generate_stack_macros("ASN1_INTEGER");
-}
""",
    "stack_st_ASN1_INTEGER",
)

# ----- ASN1_INTEGER_dup -----

patch_both(
    "asn1.h",
    """DECLARE_ASN1_DUP_FUNCTION(ASN1_INTEGER)
/**
 * @brief Compare two ASN.1 INTEGER values numerically (including sign).
""",
    """/**
 * @brief Deep-copy an ASN.1 INTEGER.
 * @param a INTEGER to duplicate.
 * @return Newly allocated ASN1_INTEGER copy, or NULL on error; free with ASN1_INTEGER_free().
 */
ASN1_INTEGER *ASN1_INTEGER_dup(const ASN1_INTEGER *a);
/**
 * @brief Compare two ASN.1 INTEGER values numerically (including sign).
""",
    "ASN1_INTEGER_dup",
)

# ----- UTCTIME / GENERALIZEDTIME check/set/set_string -----

patch_both(
    "asn1.h",
    """int ASN1_UTCTIME_check(const ASN1_UTCTIME *a);
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t);
""",
    """/**
 * @brief Check that an ASN1_UTCTIME value has valid UTCTime syntax.
 * @param a UTCTime value to validate.
 * @return 1 if syntactically correct, or 0 otherwise.
 */
int ASN1_UTCTIME_check(const ASN1_UTCTIME *a);
/**
 * @brief Set an ASN1_UTCTIME to the calendar time @p t (allocating when @p s is NULL).
 * @param s Existing UTCTIME to reuse, or NULL to allocate a new one.
 * @param t POSIX time (seconds since the Epoch).
 * @return The UTCTIME on success (possibly newly allocated), or NULL on error.
 */
ASN1_UTCTIME *ASN1_UTCTIME_set(ASN1_UTCTIME *s, time_t t);
""",
    "ASN1_UTCTIME_check+set",
)

patch_both(
    "asn1.h",
    """int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
""",
    """/**
 * @brief Set an ASN1_UTCTIME from an ASN.1 UTCTime string (or only validate when @p s is NULL).
 * @param s Destination UTCTIME, or NULL to format-check @p str only.
 * @param str NUL-terminated UTCTime string such as YYMMDDHHMMSSZ.
 * @return 1 on success, or 0 if the string is not a valid UTCTime.
 */
int ASN1_UTCTIME_set_string(ASN1_UTCTIME *s, const char *str);
""",
    "ASN1_UTCTIME_set_string",
)

patch_both(
    "asn1.h",
    """int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
    time_t t);
""",
    """/**
 * @brief Check that an ASN1_GENERALIZEDTIME value has valid GeneralizedTime syntax.
 * @param a GeneralizedTime value to validate.
 * @return 1 if syntactically correct, or 0 otherwise.
 */
int ASN1_GENERALIZEDTIME_check(const ASN1_GENERALIZEDTIME *a);
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_set(ASN1_GENERALIZEDTIME *s,
    time_t t);
""",
    "ASN1_GENERALIZEDTIME_check",
)

# ----- OCTET_STRING dup / set -----

patch_both(
    "asn1.h",
    """DECLARE_ASN1_DUP_FUNCTION(ASN1_OCTET_STRING)
/**
 * @brief Compare two ASN.1 OCTET STRING values lexicographically by content.
""",
    """/**
 * @brief Deep-copy an ASN.1 OCTET STRING.
 * @param a Octet string to duplicate.
 * @return Newly allocated ASN1_OCTET_STRING copy, or NULL on error; free with ASN1_OCTET_STRING_free().
 */
ASN1_OCTET_STRING *ASN1_OCTET_STRING_dup(const ASN1_OCTET_STRING *a);
/**
 * @brief Compare two ASN.1 OCTET STRING values lexicographically by content.
""",
    "ASN1_OCTET_STRING_dup",
)

patch_both(
    "asn1.h",
    """int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data,
    int len);
""",
    """/**
 * @brief Copy @p data of length @p len into an ASN.1 OCTET STRING.
 * @param str Octet string whose content is replaced.
 * @param data Bytes to copy into @p str.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
int ASN1_OCTET_STRING_set(ASN1_OCTET_STRING *str, const unsigned char *data,
    int len);
""",
    "ASN1_OCTET_STRING_set",
)

# ----- UTF8_getc / UTF8_putc -----

patch_both(
    "asn1.h",
    """int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
int UTF8_putc(unsigned char *str, int len, unsigned long value);
""",
    """/**
 * @brief Decode one Unicode code point from a UTF-8 byte sequence.
 * @param str Buffer holding UTF-8 octets.
 * @param len Number of bytes available at @p str.
 * @param val Receives the decoded code point on success.
 * @return Number of bytes consumed on success, 0 if @p len is too small for a character,
 *         or a negative value if the encoding is invalid.
 */
int UTF8_getc(const unsigned char *str, int len, unsigned long *val);
/**
 * @brief Encode one Unicode code point as UTF-8.
 * @param str Destination buffer, or NULL to measure the required length only.
 * @param len Capacity of @p str in bytes when @p str is non-NULL.
 * @param value Code point to encode (U+0000 .. U+10FFFF, excluding surrogates).
 * @return Number of UTF-8 bytes written (or that would be written), or -1 if @p str is too small.
 */
int UTF8_putc(unsigned char *str, int len, unsigned long value);
""",
    "UTF8_getc+putc",
)

# ----- UTCTIME_dup / GENERALIZEDTIME_dup / OCTET_STRING_NDEF_it -----

patch_both(
    "asn1.h",
    """DECLARE_ASN1_DUP_FUNCTION(ASN1_UTCTIME)
DECLARE_ASN1_DUP_FUNCTION(ASN1_GENERALIZEDTIME)

DECLARE_ASN1_ITEM(ASN1_OCTET_STRING_NDEF)
""",
    """/**
 * @brief Deep-copy an ASN1_UTCTIME value.
 * @param a Source UTCTime to duplicate.
 * @return Newly allocated ASN1_UTCTIME copy, or NULL on error.
 */
ASN1_UTCTIME *ASN1_UTCTIME_dup(const ASN1_UTCTIME *a);
/**
 * @brief Deep-copy an ASN1_GENERALIZEDTIME value.
 * @param a Source GeneralizedTime to duplicate.
 * @return Newly allocated ASN1_GENERALIZEDTIME copy, or NULL on error.
 */
ASN1_GENERALIZEDTIME *ASN1_GENERALIZEDTIME_dup(const ASN1_GENERALIZEDTIME *a);

/**
 * @brief Return the ASN.1 item descriptor for indefinite-length OCTET STRING (NDEF).
 * @return Pointer to the static ASN1_ITEM for ASN1_OCTET_STRING_NDEF.
 */
const ASN1_ITEM *ASN1_OCTET_STRING_NDEF_it(void);
""",
    "UTCTIME_dup+GENERALIZEDTIME_dup+OCTET_STRING_NDEF_it",
)

# ----- ASN1_TIME_normalize / cmp_time_t -----

patch_both(
    "asn1.h",
    """int ASN1_TIME_normalize(ASN1_TIME *s);
int ASN1_TIME_cmp_time_t(const ASN1_TIME *s, time_t t);
""",
    """/**
 * @brief Normalize an ASN1_TIME so it is suitable for certificates and consistent printing.
 * @param s Time (UTCTime or GeneralizedTime) to convert to a canonical GMT form.
 * @return 1 on success, or 0 on error.
 */
int ASN1_TIME_normalize(ASN1_TIME *s);
/**
 * @brief Compare an ASN.1 time value with a calendar time_t.
 * @param s ASN1_TIME (UTCTime or GeneralizedTime) to compare.
 * @param t POSIX time to compare against.
 * @return -1 if @p s is before @p t, 0 if equal, 1 if after, or -2 on error.
 */
int ASN1_TIME_cmp_time_t(const ASN1_TIME *s, time_t t);
""",
    "ASN1_TIME_normalize+cmp_time_t",
)

# ----- i2a_ASN1_OBJECT / i2a_ASN1_STRING -----

patch_both(
    "asn1.h",
    """int i2a_ASN1_OBJECT(BIO *bp, const ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp, ASN1_STRING *bs, char *buf, int size);
int i2a_ASN1_STRING(BIO *bp, const ASN1_STRING *a, int type);
""",
    """/**
 * @brief Write an OBJECT IDENTIFIER to a BIO as a dotted name or numeric OID text.
 * @param bp BIO that receives the textual OID (or the literal "NULL").
 * @param a Object identifier to print; may be NULL.
 * @return Number of characters written, or a negative value on error.
 */
int i2a_ASN1_OBJECT(BIO *bp, const ASN1_OBJECT *a);
int a2i_ASN1_STRING(BIO *bp, ASN1_STRING *bs, char *buf, int size);
/**
 * @brief Write an ASN.1 string's content to a BIO as uppercase hexadecimal digits.
 * @param bp BIO that receives the hex text (with newlines every 35 octets).
 * @param a String whose content octets are printed; may be NULL.
 * @param type Unused historical parameter (kept for API compatibility).
 * @return Number of characters written, or 0 if @p a is NULL / empty, or -1 on I/O error.
 */
int i2a_ASN1_STRING(BIO *bp, const ASN1_STRING *a, int type);
""",
    "i2a_ASN1_OBJECT+STRING",
)

# ----- INTEGER set/get uint64 / set / to_BN / ENUMERATED_set -----

patch_both(
    "asn1.h",
    """int ASN1_INTEGER_get_uint64(uint64_t *pr, const ASN1_INTEGER *a);
int ASN1_INTEGER_set_uint64(ASN1_INTEGER *a, uint64_t r);

int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
""",
    """/**
 * @brief Convert an ASN.1 INTEGER to a host uint64_t (must be non-negative and in range).
 * @param pr Receives the unsigned value on success.
 * @param a INTEGER to convert.
 * @return 1 on success, or 0 if @p a is NULL, negative, or out of uint64_t range.
 */
int ASN1_INTEGER_get_uint64(uint64_t *pr, const ASN1_INTEGER *a);
/**
 * @brief Set an ASN.1 INTEGER to an unsigned 64-bit value.
 * @param a Integer to update.
 * @param r Value to store.
 * @return 1 on success, or 0 on error.
 */
int ASN1_INTEGER_set_uint64(ASN1_INTEGER *a, uint64_t r);

/**
 * @brief Set an ASN.1 INTEGER to a C long value.
 * @param a Integer to update.
 * @param v Value to store.
 * @return 1 on success, or 0 on failure.
 */
int ASN1_INTEGER_set(ASN1_INTEGER *a, long v);
""",
    "ASN1_INTEGER_get/set_uint64+set",
)

patch_both(
    "asn1.h",
    """ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);
""",
    """ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *bn, ASN1_INTEGER *ai);
/**
 * @brief Convert an ASN.1 INTEGER to a BIGNUM (allocating or reusing @p bn).
 * @param ai Source INTEGER (may be negative).
 * @param bn Existing BIGNUM to reuse, or NULL to allocate.
 * @return Pointer to the BIGNUM result (possibly newly allocated), or NULL on error.
 */
BIGNUM *ASN1_INTEGER_to_BN(const ASN1_INTEGER *ai, BIGNUM *bn);
""",
    "ASN1_INTEGER_to_BN",
)

patch_both(
    "asn1.h",
    """int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
""",
    """/**
 * @brief Set an ASN.1 ENUMERATED to a C long value.
 * @param a Enumerated value to update.
 * @param v Value to store.
 * @return 1 on success, or 0 on failure.
 */
int ASN1_ENUMERATED_set(ASN1_ENUMERATED *a, long v);
""",
    "ASN1_ENUMERATED_set",
)

# ----- ASN1_PRINTABLE_type -----

patch_both(
    "asn1.h",
    """/* given a string, return the correct type, max is the maximum length */
int ASN1_PRINTABLE_type(const unsigned char *s, int max);
""",
    """/**
 * @brief Choose a PrintableString / IA5String / T61String type that can hold @p s.
 * @param s Bytes to classify; NULL is treated as PrintableString.
 * @param max Number of bytes at @p s, or a negative value to use strlen(@p s).
 * @return V_ASN1_PRINTABLESTRING, V_ASN1_IA5STRING, or V_ASN1_T61STRING.
 */
int ASN1_PRINTABLE_type(const unsigned char *s, int max);
""",
    "ASN1_PRINTABLE_type",
)

# ----- infinite end / put_eoc -----

patch_both(
    "asn1.h",
    """int ASN1_check_infinite_end(unsigned char **p, long len);
int ASN1_const_check_infinite_end(const unsigned char **p, long len);
""",
    """int ASN1_check_infinite_end(unsigned char **p, long len);
/**
 * @brief Consume an indefinite-length end-of-contents (EOC) marker of two zero octets.
 * @param p Address of the input cursor; advanced past EOC when present.
 * @param len Remaining bytes available at *@p p.
 * @return 1 if EOC was found (or @p len is too small / exhausted), or 0 otherwise.
 */
int ASN1_const_check_infinite_end(const unsigned char **p, long len);
""",
    "ASN1_const_check_infinite_end",
)

patch_both(
    "asn1.h",
    """int ASN1_put_eoc(unsigned char **pp);
""",
    """/**
 * @brief Write a two-octet ASN.1 end-of-contents (0x00 0x00) marker and advance @p pp.
 * @param pp Address of the output cursor; updated past the written EOC.
 * @return 2 (number of bytes written).
 */
int ASN1_put_eoc(unsigned char **pp);
""",
    "ASN1_put_eoc",
)

# ----- ASN1_item_verify_ex -----

patch_both(
    "asn1.h",
    """int ASN1_item_verify_ex(const ASN1_ITEM *it, const X509_ALGOR *alg,
    const ASN1_BIT_STRING *signature, const void *data,
    const ASN1_OCTET_STRING *id, EVP_PKEY *pkey,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Verify @p signature over the DER encoding of @p data described by @p it.
 * @param it ASN.1 item describing the type of @p data.
 * @param alg Signature AlgorithmIdentifier.
 * @param signature BIT STRING holding the signature bytes.
 * @param data Object whose DER encoding is verified.
 * @param id Optional ASN.1 OCTET STRING identity / SM2-id parameter, or NULL.
 * @param pkey Public key used to verify the signature.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return 1 on success, 0 on failure, or -1 on a more serious error.
 */
int ASN1_item_verify_ex(const ASN1_ITEM *it, const X509_ALGOR *alg,
    const ASN1_BIT_STRING *signature, const void *data,
    const ASN1_OCTET_STRING *id, EVP_PKEY *pkey,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "ASN1_item_verify_ex",
)

# ----- item_d2i_fp / i2d_fp / d2i_bio / item_d2i_bio_ex -----

patch_both(
    "asn1.h",
    """void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x);
int ASN1_i2d_fp(i2d_of_void *i2d, FILE *out, const void *x);
""",
    """/**
 * @brief Decode an ASN.1 value described by @p it from a FILE (default library context).
 * @param it ASN.1 item describing the type to decode.
 * @param in Open FILE positioned at DER input.
 * @param x Optional existing object to reuse, or NULL to allocate.
 * @return Decoded object pointer, or NULL on error.
 */
void *ASN1_item_d2i_fp(const ASN1_ITEM *it, FILE *in, void *x);
/**
 * @brief Encode an ASN.1 value to a FILE using a type-specific i2d function.
 * @param i2d Encoder such as i2d_X509.
 * @param out Output FILE that receives the DER encoding.
 * @param x Object to encode; must match the type expected by @p i2d.
 * @return 1 on success, or 0 on failure.
 */
int ASN1_i2d_fp(i2d_of_void *i2d, FILE *out, const void *x);
""",
    "ASN1_item_d2i_fp+ASN1_i2d_fp",
)

patch_both(
    "asn1.h",
    """void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x);
""",
    """/**
 * @brief Decode an ASN.1 value from a BIO using allocator and d2i callbacks.
 * @param xnew Allocator returning a new empty object (for example TYPE_new).
 * @param d2i Decoder of type d2i_of_void that parses DER into the object.
 * @param in BIO positioned at DER (or BER) encoding.
 * @param x Optional destination pointer updated to the decoded object, or NULL.
 * @return Decoded object pointer, or NULL on error.
 */
void *ASN1_d2i_bio(void *(*xnew)(void), d2i_of_void *d2i, BIO *in, void **x);
""",
    "ASN1_d2i_bio",
)

patch_both(
    "asn1.h",
    """void *ASN1_item_d2i_bio_ex(const ASN1_ITEM *it, BIO *in, void *pval,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Decode an ASN.1 value described by @p it from a BIO, with library context.
 * @param it ASN.1 item describing the type to decode.
 * @param in BIO positioned at DER input.
 * @param pval Optional existing object to reuse, or NULL to allocate.
 * @param libctx Library context for algorithm fetches during decode, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Decoded object pointer, or NULL on error.
 */
void *ASN1_item_d2i_bio_ex(const ASN1_ITEM *it, BIO *in, void *pval,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "ASN1_item_d2i_bio_ex",
)

# ----- print helpers -----

patch_both(
    "asn1.h",
    """int ASN1_UTCTIME_print(BIO *fp, const ASN1_UTCTIME *a);
""",
    """/**
 * @brief Print an ASN.1 UTCTime to a BIO in human-readable form.
 * @param fp BIO that receives text such as "Feb  3 00:55:52 2015 GMT".
 * @param a UTCTime value to print.
 * @return 1 on success, or 0 on I/O or format error.
 */
int ASN1_UTCTIME_print(BIO *fp, const ASN1_UTCTIME *a);
""",
    "ASN1_UTCTIME_print",
)

patch_both(
    "asn1.h",
    """int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v);
""",
    """/**
 * @brief Print an ASN.1 string to a BIO, replacing unprintable bytes with '.'.
 * @param bp BIO that receives the printable text.
 * @param v String to print; may be NULL.
 * @return 1 on success, or 0 on error.
 */
int ASN1_STRING_print(BIO *bp, const ASN1_STRING *v);
""",
    "ASN1_STRING_print",
)

patch_both(
    "asn1.h",
    """int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
    unsigned char *buf, int off);
""",
    """/**
 * @brief Print a labeled BIGNUM to a BIO in hex, with indentation.
 * @param bp BIO that receives the formatted output.
 * @param number Label printed before the value (for example a field name).
 * @param num Big integer to print; NULL prints nothing and returns success.
 * @param buf Unused historical parameter (ignored; may be NULL).
 * @param off Indentation depth in spaces.
 * @return 1 on success, or 0 on error.
 */
int ASN1_bn_print(BIO *bp, const char *number, const BIGNUM *num,
    unsigned char *buf, int off);
""",
    "ASN1_bn_print",
)

patch_both(
    "asn1.h",
    """const char *ASN1_tag2str(int tag);
""",
    """/**
 * @brief Return a human-readable name for an ASN.1 universal tag number.
 * @param tag Tag such as V_ASN1_UTF8STRING or V_ASN1_SEQUENCE.
 * @return Static string name for @p tag (do not free).
 */
const char *ASN1_tag2str(int tag);
""",
    "ASN1_tag2str",
)

# ----- UNIVERSALSTRING / TYPE octetstring helpers -----

patch_both(
    "asn1.h",
    """int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);
""",
    """/**
 * @brief Convert a UniversalString that holds only Latin-1 code points into a Printable/IA5/T61 string in place.
 * @param s UniversalString whose four-byte code units are collapsed to single octets when possible.
 * @return 1 on success (type and data updated), or 0 if @p s is not a convertible UniversalString.
 */
int ASN1_UNIVERSALSTRING_to_string(ASN1_UNIVERSALSTRING *s);
""",
    "ASN1_UNIVERSALSTRING_to_string",
)

patch_both(
    "asn1.h",
    """int ASN1_TYPE_set_octetstring(ASN1_TYPE *a, unsigned char *data, int len);
int ASN1_TYPE_get_octetstring(const ASN1_TYPE *a, unsigned char *data, int max_len);
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
    unsigned char *data, int len);
""",
    """/**
 * @brief Set an ASN1_TYPE to an OCTET STRING containing a copy of @p data.
 * @param a ANY value to update.
 * @param data Octets to store.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
int ASN1_TYPE_set_octetstring(ASN1_TYPE *a, unsigned char *data, int len);
/**
 * @brief Copy the OCTET STRING contents of an ASN1_TYPE into @p data.
 * @param a ASN1_TYPE that must hold V_ASN1_OCTET_STRING.
 * @param data Buffer that receives up to @p max_len content octets.
 * @param max_len Capacity of @p data in bytes.
 * @return Full OCTET STRING length on success, or -1 on type/content error.
 */
int ASN1_TYPE_get_octetstring(const ASN1_TYPE *a, unsigned char *data, int max_len);
/**
 * @brief Set an ASN1_TYPE to the SEQUENCE { INTEGER, OCTET STRING } pair used by some algorithm parameters.
 * @param a ANY value to update.
 * @param num INTEGER component.
 * @param data OCTET STRING content to embed.
 * @param len Number of bytes at @p data.
 * @return 1 on success, or 0 on failure.
 */
int ASN1_TYPE_set_int_octetstring(ASN1_TYPE *a, long num,
    unsigned char *data, int len);
""",
    "ASN1_TYPE_set/get_octetstring+set_int_octetstring",
)

# ----- item_unpack -----

patch_both(
    "asn1.h",
    """void *ASN1_item_unpack(const ASN1_STRING *oct, const ASN1_ITEM *it);
void *ASN1_item_unpack_ex(const ASN1_STRING *oct, const ASN1_ITEM *it,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    """/**
 * @brief Decode the DER content of an OCTET STRING / ASN1_STRING using item @p it.
 * @param oct String whose content octets are treated as DER input.
 * @param it ASN.1 item descriptor for the type to decode.
 * @return Newly allocated typed value, or NULL on error; free with ASN1_item_free.
 */
void *ASN1_item_unpack(const ASN1_STRING *oct, const ASN1_ITEM *it);
/**
 * @brief Decode DER from an ASN1_STRING using @p it, with library context for algorithm fetches.
 * @param oct String whose content octets are treated as DER input.
 * @param it ASN.1 item descriptor for the type to decode.
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Newly allocated typed value, or NULL on error; free with ASN1_item_free.
 */
void *ASN1_item_unpack_ex(const ASN1_STRING *oct, const ASN1_ITEM *it,
    OSSL_LIB_CTX *libctx, const char *propq);
""",
    "ASN1_item_unpack+unpack_ex",
)

# ----- default mask / mbstring / STRING_TABLE_add -----

patch_both(
    "asn1.h",
    """void ASN1_STRING_set_default_mask(unsigned long mask);
""",
    """/**
 * @brief Set the process-wide default B_ASN1_* mask used when selecting ASN.1 string types.
 * @param mask Bitmask of permitted string types (for example B_ASN1_UTF8STRING).
 */
void ASN1_STRING_set_default_mask(unsigned long mask);
""",
    "ASN1_STRING_set_default_mask",
)

patch_both(
    "asn1.h",
    """int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
    int inform, unsigned long mask);
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
    int inform, unsigned long mask,
    long minsize, long maxsize);
""",
    """/**
 * @brief Convert multibyte input into an ASN.1 string, choosing a type allowed by @p mask.
 * @param out Destination; if NULL a new string is allocated, otherwise *@p out may be reused.
 * @param in Input bytes in the encoding given by @p inform.
 * @param len Length of @p in in bytes, or -1 if @p in is NUL-terminated.
 * @param inform Input encoding (MBSTRING_ASC, MBSTRING_BMP, MBSTRING_UNIV, or MBSTRING_UTF8).
 * @param mask B_ASN1_* bitmask of permitted output string types (0 selects the default mask).
 * @return Positive ASN.1 string type on success, or a negative value on error.
 */
int ASN1_mbstring_copy(ASN1_STRING **out, const unsigned char *in, int len,
    int inform, unsigned long mask);
/**
 * @brief Like ASN1_mbstring_copy(), also enforcing minimum and maximum character counts.
 * @param out Destination; if NULL a new string is allocated, otherwise *@p out may be reused.
 * @param in Input bytes in the encoding given by @p inform.
 * @param len Length of @p in in bytes, or -1 if @p in is NUL-terminated.
 * @param inform Input encoding (MBSTRING_ASC, MBSTRING_BMP, MBSTRING_UNIV, or MBSTRING_UTF8).
 * @param mask B_ASN1_* bitmask of permitted output string types (0 selects the default mask).
 * @param minsize Minimum character count (0 disables the check).
 * @param maxsize Maximum character count (0 disables the check).
 * @return Positive ASN.1 string type on success, or a negative value on error.
 */
int ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
    int inform, unsigned long mask,
    long minsize, long maxsize);
""",
    "ASN1_mbstring_copy+ncopy",
)

patch_both(
    "asn1.h",
    """int ASN1_STRING_TABLE_add(int, long, long, unsigned long, unsigned long);
""",
    """/**
 * @brief Add or update a local ASN1_STRING_TABLE entry for @p nid.
 * @param nid Object identifier NID whose string policy is registered or updated.
 * @param minsize Minimum size in characters (>= 0 to update; negative leaves unchanged).
 * @param maxsize Maximum size in characters (>= 0 to update; negative leaves unchanged).
 * @param mask B_ASN1_* type mask (nonzero to update; 0 leaves unchanged).
 * @param flags STABLE_FLAGS_* bits (nonzero to update; 0 leaves unchanged).
 * @return 1 on success, or 0 on error.
 */
int ASN1_STRING_TABLE_add(int nid, long minsize, long maxsize,
    unsigned long mask, unsigned long flags);
""",
    "ASN1_STRING_TABLE_add",
)

# ----- item_new / ndef_i2d / add_oid / generate_v3 -----

patch_both(
    "asn1.h",
    """ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
ASN1_VALUE *ASN1_item_new_ex(const ASN1_ITEM *it, OSSL_LIB_CTX *libctx,
    const char *propq);
""",
    """/**
 * @brief Allocate a new ASN.1 value described by @p it using the default library context.
 * @param it ASN.1 item template for the type to create.
 * @return Newly allocated ASN1_VALUE, or NULL on error; free with ASN1_item_free.
 */
ASN1_VALUE *ASN1_item_new(const ASN1_ITEM *it);
/**
 * @brief Allocate a new ASN.1 value described by @p it, with library context for algorithm fetches.
 * @param it ASN.1 item template for the type to create.
 * @param libctx Library context for any algorithm fetches during construction, or NULL for the default.
 * @param propq Property query for those fetches, or NULL.
 * @return Newly allocated ASN1_VALUE, or NULL on error; free with ASN1_item_free.
 */
ASN1_VALUE *ASN1_item_new_ex(const ASN1_ITEM *it, OSSL_LIB_CTX *libctx,
    const char *propq);
""",
    "ASN1_item_new+new_ex",
)

patch_both(
    "asn1.h",
    """int ASN1_item_ndef_i2d(const ASN1_VALUE *val, unsigned char **out,
    const ASN1_ITEM *it);
""",
    """/**
 * @brief Encode an ASN.1 value to DER/BER using indefinite-length (NDEF) constructed form where applicable.
 * @param val Value to encode (typed according to @p it).
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @param it ASN.1 item descriptor for the type of @p val.
 * @return Number of bytes encoded, or a negative value on error.
 */
int ASN1_item_ndef_i2d(const ASN1_VALUE *val, unsigned char **out,
    const ASN1_ITEM *it);
""",
    "ASN1_item_ndef_i2d",
)

patch_both(
    "asn1.h",
    """void ASN1_add_oid_module(void);
""",
    """/**
 * @brief Register the built-in CONF module that loads OID name mappings from an "oid_section".
 */
void ASN1_add_oid_module(void);
""",
    "ASN1_add_oid_module",
)

patch_both(
    "asn1.h",
    """ASN1_TYPE *ASN1_generate_v3(const char *str, X509V3_CTX *cnf);
""",
    """/**
 * @brief Build an ASN1_TYPE from an ASN.1 generation string, resolving extras via an X509V3_CTX.
 * @param str Generation string describing the ASN.1 value to encode.
 * @param cnf Optional X.509v3 context supplying configuration for additional string references, or NULL.
 * @return Encoded ASN1_TYPE, or NULL on error.
 */
ASN1_TYPE *ASN1_generate_v3(const char *str, X509V3_CTX *cnf);
""",
    "ASN1_generate_v3",
)

# ----- PCTX set cert/str flags -----

patch_both(
    "asn1.h",
    """void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags);
""",
    """/**
 * @brief Set certificate-field print flags on an ASN.1 print context.
 * @param p Print context to update.
 * @param flags Mask controlling which certificate-related fields are shown.
 */
void ASN1_PCTX_set_cert_flags(ASN1_PCTX *p, unsigned long flags);
""",
    "ASN1_PCTX_set_cert_flags",
)

patch_both(
    "asn1.h",
    """void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags);
""",
    """/**
 * @brief Set ASN1_STRFLGS_* flags controlling how string fields are printed.
 * @param p Print context to update.
 * @param flags String print flags (same family as ASN1_STRING_print_ex).
 */
void ASN1_PCTX_set_str_flags(ASN1_PCTX *p, unsigned long flags);
""",
    "ASN1_PCTX_set_str_flags",
)

# ----- SCTX -----

patch_both(
    "asn1.h",
    """ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb)(ASN1_SCTX *ctx));
""",
    """/**
 * @brief Allocate an ASN.1 scan context with the given per-field scan callback.
 * @param scan_cb Callback invoked while scanning ASN.1 templates, or NULL.
 * @return New ASN1_SCTX, or NULL on allocation failure; free with ASN1_SCTX_free().
 */
ASN1_SCTX *ASN1_SCTX_new(int (*scan_cb)(ASN1_SCTX *ctx));
""",
    "ASN1_SCTX_new",
)

patch_both(
    "asn1.h",
    """void ASN1_SCTX_set_app_data(ASN1_SCTX *p, void *data);
""",
    """/**
 * @brief Store an application pointer on an ASN.1 scan context for use by the scan callback.
 * @param p Scan context to update.
 * @param data Opaque pointer retrieved later with ASN1_SCTX_get_app_data().
 */
void ASN1_SCTX_set_app_data(ASN1_SCTX *p, void *data);
""",
    "ASN1_SCTX_set_app_data",
)

# ----- streaming / SMIME / ITEM lookup -----

patch_both(
    "asn1.h",
    """int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
    const ASN1_ITEM *it);
""",
    """/**
 * @brief Stream-encode an ASN.1 value to @p out, optionally pulling content from @p in.
 * @param out BIO that receives the encoded ASN.1 output.
 * @param val ASN.1 value to encode (not const because streaming may update state).
 * @param in Optional content BIO for indefinite-length / streaming payloads, or NULL.
 * @param flags SMIME/CMS streaming flags (for example SMIME_STREAM).
 * @param it ASN.1 item descriptor for @p val.
 * @return 1 on success, or 0 on failure.
 */
int i2d_ASN1_bio_stream(BIO *out, ASN1_VALUE *val, BIO *in, int flags,
    const ASN1_ITEM *it);
""",
    "i2d_ASN1_bio_stream",
)

patch_both(
    "asn1.h",
    """/* cannot constify val because of CMS_dataFinal() */
int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
    int ctype_nid, int econt_nid,
    STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it);
int SMIME_write_ASN1_ex(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
    int ctype_nid, int econt_nid,
    STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it,
    OSSL_LIB_CTX *libctx, const char *propq);
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);
""",
    """/* cannot constify val because of CMS_dataFinal() */
/**
 * @brief Write an ASN.1 CMS/PKCS#7 value as an S/MIME message (default library context).
 * @param bio BIO that receives the S/MIME output.
 * @param val CMS_ContentInfo or PKCS7 value to wrap (not const because streaming may update state).
 * @param data Optional content BIO when streaming / detached content is used, or NULL.
 * @param flags CMS_* / SMIME_* flags (for example CMS_DETACHED, CMS_TEXT, CMS_STREAM).
 * @param ctype_nid NID of the content type.
 * @param econt_nid NID of the embedded content type.
 * @param mdalgs Digest algorithms for SignedData, or NULL when unused.
 * @param it Item descriptor such as ASN1_ITEM_rptr(CMS_ContentInfo) or ASN1_ITEM_rptr(PKCS7).
 * @return 1 on success, or 0 on failure.
 */
int SMIME_write_ASN1(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
    int ctype_nid, int econt_nid,
    STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it);
/**
 * @brief Write an ASN.1 CMS/PKCS#7 value as an S/MIME message with library context.
 * @param bio BIO that receives the S/MIME output.
 * @param val CMS_ContentInfo or PKCS7 value to wrap (not const because streaming may update state).
 * @param data Optional content BIO when streaming / detached content is used, or NULL.
 * @param flags CMS_* / SMIME_* flags (for example CMS_DETACHED, CMS_TEXT, CMS_STREAM).
 * @param ctype_nid NID of the content type.
 * @param econt_nid NID of the embedded content type.
 * @param mdalgs Digest algorithms for SignedData, or NULL when unused.
 * @param it Item descriptor such as ASN1_ITEM_rptr(CMS_ContentInfo) or ASN1_ITEM_rptr(PKCS7).
 * @param libctx Library context for algorithm fetches, or NULL for the default.
 * @param propq Property query for those fetches, or NULL.
 * @return 1 on success, or 0 on failure.
 */
int SMIME_write_ASN1_ex(BIO *bio, ASN1_VALUE *val, BIO *data, int flags,
    int ctype_nid, int econt_nid,
    STACK_OF(X509_ALGOR) *mdalgs, const ASN1_ITEM *it,
    OSSL_LIB_CTX *libctx, const char *propq);
/**
 * @brief Parse an S/MIME message into an ASN.1 structure described by @p it (flags=0).
 * @param bio BIO that supplies the S/MIME input.
 * @param bcont If non-NULL, set to a memory BIO holding cleartext signed content, or NULL when absent.
 * @param it Item descriptor such as ASN1_ITEM_rptr(CMS_ContentInfo) or ASN1_ITEM_rptr(PKCS7).
 * @return Parsed ASN1_VALUE, or NULL on error.
 */
ASN1_VALUE *SMIME_read_ASN1(BIO *bio, BIO **bcont, const ASN1_ITEM *it);
""",
    "SMIME_write_ASN1+write_ex+read",
)

patch_both(
    "asn1.h",
    """int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
int SMIME_text(BIO *in, BIO *out);
""",
    """/**
 * @brief Copy @p in to @p out applying S/MIME canonical CRLF line endings when appropriate.
 * @param in Source BIO.
 * @param out Destination BIO (often buffered for streaming).
 * @param flags SMIME/CMS flags controlling text vs binary handling (for example SMIME_BINARY).
 * @return 1 on success, or 0 on failure.
 */
int SMIME_crlf_copy(BIO *in, BIO *out, int flags);
/**
 * @brief Strip MIME headers from a text/plain S/MIME part and copy the body to @p out.
 * @param in BIO positioned at a MIME message (headers then body).
 * @param out BIO that receives the message body after headers are removed.
 * @return 1 on success, or 0 if headers cannot be parsed or Content-Type is not text/plain.
 */
int SMIME_text(BIO *in, BIO *out);
""",
    "SMIME_crlf_copy+text",
)

patch_both(
    "asn1.h",
    """const ASN1_ITEM *ASN1_ITEM_lookup(const char *name);
const ASN1_ITEM *ASN1_ITEM_get(size_t i);
""",
    """/**
 * @brief Look up a built-in ASN1_ITEM by its structure name.
 * @param name ASN.1 item name string.
 * @return Matching ASN1_ITEM, or NULL if not found / on error.
 */
const ASN1_ITEM *ASN1_ITEM_lookup(const char *name);
/**
 * @brief Return the built-in ASN1_ITEM at index @p i.
 * @param i Zero-based index into the static ASN1_ITEM table.
 * @return ASN1_ITEM at @p i, or NULL if @p i is out of range.
 */
const ASN1_ITEM *ASN1_ITEM_get(size_t i);
""",
    "ASN1_ITEM_lookup+get",
)

print()
print(f"OK: {len(ok)}  MISS: {len(missing)}")
if missing:
    print("Missing:")
    for m in missing:
        print(f"  - {m}")
