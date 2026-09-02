#!/usr/bin/env python3
"""Document symbols from one capped MrDocs documentation-repair batch."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
INC = ROOT / "include" / "openssl"

ok: list[str] = []
missing: list[str] = []


def patch_both(rel: str, old: str, new: str, label: str) -> None:
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
            if label.split("(")[0] in text and "@brief" in text[
                max(0, text.find(label.split("(")[0]) - 400) : text.find(label.split("(")[0]) + 50
            ]:
                print(f"  SKIP (likely already): {path.name} :: {label}")
                ok.append(f"{path.name}:{label}:skip")
                continue
            print(f"  MISS: {path.name} :: {label}")
            missing.append(f"{path.name}:{label}")
            continue
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        print(f"  OK: {path.name} :: {label}")
        ok.append(f"{path.name}:{label}")
    if not found:
        missing.append(f"{rel}:{label}:no-file")


def asn1_funcs(typename: str, brief: str) -> str:
    return f"""/**
 * @brief Allocate an empty {brief}.
 * @return New {typename}, or NULL on allocation failure.
 */
{typename} *{typename}_new(void);
/**
 * @brief Free a {brief} and its contents.
 * @param a Value to free, or NULL.
 */
void {typename}_free({typename} *a);
/**
 * @brief Decode a {brief} from DER.
 * @param a Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @return Decoded {typename}, or NULL on error.
 */
{typename} *d2i_{typename}({typename} **a, const unsigned char **in, long len);
/**
 * @brief Encode a {brief} to DER.
 * @param a Value to encode.
 * @param out Destination pointer updated like a standard i2d encoder, or NULL to measure length.
 * @return Number of bytes encoded, or a negative value on error.
 */
int i2d_{typename}(const {typename} *a, unsigned char **out);
/**
 * @brief Return the ASN.1 item descriptor for {typename}.
 * @return Pointer to the static ASN1_ITEM for {typename}.
 */
const ASN1_ITEM *{typename}_it(void);"""


def cipher_getter(decl: str, brief: str, alg: str) -> tuple[str, str]:
    new = f"""/**
 * @brief {brief}
 * @return EVP_CIPHER for {alg}, or NULL if unavailable.
 */
{decl}"""
    return decl, new


# ---------------------------------------------------------------------------
# asn1.h
# ---------------------------------------------------------------------------
patch_both(
    "asn1.h",
    """struct asn1_string_st {
    int length;
    int type;
    unsigned char *data;""",
    """struct asn1_string_st {
    /** Number of content octets in @c data (not including a trailing NUL unless present in the encoding). */
    int length;
    /** ASN.1 tag / string type (for example V_ASN1_OCTET_STRING or V_ASN1_UTF8STRING). */
    int type;
    unsigned char *data;""",
    "asn1_string_st fields",
)

patch_both(
    "asn1.h",
    """    union {
        char *ptr;
        ASN1_BOOLEAN boolean;""",
    """    union {
        /** Untyped pointer view of the ANY value when no more specific arm applies. */
        char *ptr;
        ASN1_BOOLEAN boolean;""",
    "asn1_type_st::ptr",
)

patch_both(
    "asn1.h",
    """        ASN1_BIT_STRING *bit_string;
        ASN1_OCTET_STRING *octet_string;
        ASN1_PRINTABLESTRING *printablestring;""",
    """        ASN1_BIT_STRING *bit_string;
        /** OCTET STRING value when type is V_ASN1_OCTET_STRING. */
        ASN1_OCTET_STRING *octet_string;
        ASN1_PRINTABLESTRING *printablestring;""",
    "asn1_type_st::octet_string",
)

patch_both(
    "asn1.h",
    """        ASN1_GENERALSTRING *generalstring;
        ASN1_BMPSTRING *bmpstring;
        /** UniversalString value when type is V_ASN1_UNIVERSALSTRING. */""",
    """        ASN1_GENERALSTRING *generalstring;
        /** BMPString (UCS-2) value when type is V_ASN1_BMPSTRING. */
        ASN1_BMPSTRING *bmpstring;
        /** UniversalString value when type is V_ASN1_UNIVERSALSTRING. */""",
    "asn1_type_st::bmpstring",
)

patch_both(
    "asn1.h",
    "void *ASN1_TYPE_unpack_sequence(const ASN1_ITEM *it, const ASN1_TYPE *t);",
    """/**
 * @brief Decode the SEQUENCE contents of an ASN1_TYPE into a typed structure.
 * @param it ASN.1 item describing the expected SEQUENCE type.
 * @param t ASN1_TYPE whose value holds SEQUENCE octets (typically V_ASN1_SEQUENCE).
 * @return Newly allocated structure of the type described by @p it, or NULL on error.
 */
void *ASN1_TYPE_unpack_sequence(const ASN1_ITEM *it, const ASN1_TYPE *t);""",
    "ASN1_TYPE_unpack_sequence",
)

patch_both(
    "asn1.h",
    """int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, const char *name, int value,
    BIT_STRING_BITNAME *tbl);""",
    """/**
 * @brief Set or clear a named bit in an ASN.1 bit string using a name table.
 * @param bs Bit string to update.
 * @param name Bit name to look up in @p tbl.
 * @param value Non-zero to set the bit, or 0 to clear it.
 * @param tbl Table of bit names and bit numbers (BIT_STRING_BITNAME entries).
 * @return 1 on success, or 0 if @p name is not found in @p tbl.
 */
int ASN1_BIT_STRING_set_asc(ASN1_BIT_STRING *bs, const char *name, int value,
    BIT_STRING_BITNAME *tbl);""",
    "ASN1_BIT_STRING_set_asc",
)

patch_both(
    "asn1.h",
    "DECLARE_ASN1_FUNCTIONS(ASN1_BMPSTRING)",
    asn1_funcs("ASN1_BMPSTRING", "ASN.1 BMPString"),
    "ASN1_BMPSTRING functions",
)

patch_both(
    "asn1.h",
    "DECLARE_ASN1_DUP_FUNCTION(ASN1_TIME)",
    """/**
 * @brief Duplicate an ASN1_TIME value (UTCTime or GeneralizedTime).
 * @param a Source time to copy.
 * @return Newly allocated ASN1_TIME copy, or NULL on error.
 */
ASN1_TIME *ASN1_TIME_dup(const ASN1_TIME *a);""",
    "ASN1_TIME_dup",
)

patch_both(
    "asn1.h",
    """ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(const ASN1_TIME *t,
    ASN1_GENERALIZEDTIME **out);""",
    """/**
 * @brief Convert an ASN1_TIME to GeneralizedTime form.
 * @param t Source time (UTCTime or GeneralizedTime).
 * @param out Optional destination; if non-NULL and *@p out is non-NULL it is reused, otherwise a new value is allocated and returned via *@p out when @p out is non-NULL.
 * @return Pointer to the GeneralizedTime result, or NULL on error.
 */
ASN1_GENERALIZEDTIME *ASN1_TIME_to_generalizedtime(const ASN1_TIME *t,
    ASN1_GENERALIZEDTIME **out);""",
    "ASN1_TIME_to_generalizedtime",
)

patch_both(
    "asn1.h",
    "ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(const BIGNUM *bn, ASN1_ENUMERATED *ai);",
    """/**
 * @brief Convert a BIGNUM to an ASN.1 ENUMERATED value.
 * @param bn Integer to convert.
 * @param ai Destination ENUMERATED to reuse, or NULL to allocate a new one.
 * @return Pointer to the ENUMERATED result (possibly newly allocated), or NULL on error.
 */
ASN1_ENUMERATED *BN_to_ASN1_ENUMERATED(const BIGNUM *bn, ASN1_ENUMERATED *ai);""",
    "BN_to_ASN1_ENUMERATED",
)

patch_both(
    "asn1.h",
    "int ASN1_STRING_print_ex_fp(FILE *fp, const ASN1_STRING *str, unsigned long flags);",
    """/**
 * @brief Print an ASN.1 string to a FILE with ASN1_STRING_print_ex() formatting flags.
 * @param fp Output stream.
 * @param str String to print.
 * @param flags ASN1_STRFLGS_* formatting flags.
 * @return 1 on success, or 0 on error.
 */
int ASN1_STRING_print_ex_fp(FILE *fp, const ASN1_STRING *str, unsigned long flags);""",
    "ASN1_STRING_print_ex_fp",
)

patch_both(
    "asn1.h",
    "int ASN1_STRING_to_UTF8(unsigned char **out, const ASN1_STRING *in);",
    """/**
 * @brief Convert an ASN.1 string to a newly allocated UTF-8 byte sequence.
 * @param out On success, set to a buffer allocated with OPENSSL_malloc() holding UTF-8 octets (caller frees).
 * @param in Source ASN.1 string of any supported string type.
 * @return Number of UTF-8 bytes written to *@p out on success, or a negative value on error.
 */
int ASN1_STRING_to_UTF8(unsigned char **out, const ASN1_STRING *in);""",
    "ASN1_STRING_to_UTF8",
)

patch_both(
    "asn1.h",
    """int ASN1_TYPE_get_int_octetstring(const ASN1_TYPE *a, long *num,
    unsigned char *data, int max_len);""",
    """/**
 * @brief Extract the INTEGER and OCTET STRING from an ASN1_TYPE holding that SEQUENCE pair.
 * @param a ASN1_TYPE previously set with ASN1_TYPE_set_int_octetstring().
 * @param num Receives the INTEGER value when non-NULL.
 * @param data Optional buffer that receives up to @p max_len OCTET STRING bytes.
 * @param max_len Capacity of @p data in bytes.
 * @return Length of the OCTET STRING on success, or -1 on error (including when @p data is too small).
 */
int ASN1_TYPE_get_int_octetstring(const ASN1_TYPE *a, long *num,
    unsigned char *data, int max_len);""",
    "ASN1_TYPE_get_int_octetstring",
)

patch_both(
    "asn1.h",
    """ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it,
    ASN1_OCTET_STRING **oct);""",
    """/**
 * @brief Encode @p obj with @p it and store the DER result in an OCTET STRING.
 * @param obj Typed ASN.1 value to encode.
 * @param it ASN.1 item descriptor for @p obj.
 * @param oct Optional destination OCTET STRING pointer; if NULL or *@p oct is NULL a new string is allocated.
 * @return The OCTET STRING holding the encoded bytes, or NULL on error.
 */
ASN1_STRING *ASN1_item_pack(void *obj, const ASN1_ITEM *it,
    ASN1_OCTET_STRING **oct);""",
    "ASN1_item_pack",
)

patch_both(
    "asn1.h",
    "void ASN1_STRING_TABLE_cleanup(void);",
    """/**
 * @brief Free dynamically registered ASN1_STRING_TABLE entries added at run time.
 *
 * Built-in table entries are left in place. Call during application teardown if
 * ASN1_STRING_TABLE_add() was used.
 */
void ASN1_STRING_TABLE_cleanup(void);""",
    "ASN1_STRING_TABLE_cleanup",
)

patch_both(
    "asn1.h",
    "void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);",
    """/**
 * @brief Free an ASN.1 value described by an ASN1_ITEM.
 * @param val Value to free, or NULL.
 * @param it ASN.1 item descriptor matching @p val.
 */
void ASN1_item_free(ASN1_VALUE *val, const ASN1_ITEM *it);""",
    "ASN1_item_free",
)

patch_both(
    "asn1.h",
    """ASN1_VALUE *ASN1_item_d2i_ex(ASN1_VALUE **val, const unsigned char **in,
    long len, const ASN1_ITEM *it,
    OSSL_LIB_CTX *libctx, const char *propq);""",
    """/**
 * @brief Decode a DER-encoded ASN.1 value using an item descriptor and library context.
 * @param val Optional destination pointer updated to the result, or NULL.
 * @param in Address of a pointer to the DER input; advanced past the decoded value.
 * @param len Number of bytes available at *@p in.
 * @param it ASN.1 item descriptor for the type to decode.
 * @param libctx Library context for algorithm fetches during decode, or NULL for the default.
 * @param propq Property query for algorithm fetches, or NULL.
 * @return Decoded ASN1_VALUE, or NULL on error.
 */
ASN1_VALUE *ASN1_item_d2i_ex(ASN1_VALUE **val, const unsigned char **in,
    long len, const ASN1_ITEM *it,
    OSSL_LIB_CTX *libctx, const char *propq);""",
    "ASN1_item_d2i_ex",
)

patch_both(
    "asn1.h",
    "void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags);",
    """/**
 * @brief Set name-printing flags for an ASN.1 print context.
 * @param p Print context to update.
 * @param flags XN_FLAG_* / ASN1_STRFLGS_* mask controlling how names are rendered.
 */
void ASN1_PCTX_set_nm_flags(ASN1_PCTX *p, unsigned long flags);""",
    "ASN1_PCTX_set_nm_flags",
)

patch_both(
    "asn1.h",
    "const BIO_METHOD *BIO_f_asn1(void);",
    """/**
 * @brief Return the filter BIO_METHOD that encodes ASN.1 values to a downstream BIO.
 * @return Pointer to the ASN.1 filter method used with BIO_new() / BIO_new_NDEF().
 */
const BIO_METHOD *BIO_f_asn1(void);""",
    "BIO_f_asn1",
)

print(f"\nPart asn1 done. ok={len(ok)} miss={len(missing)}")
