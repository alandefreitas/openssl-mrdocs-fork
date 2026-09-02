/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_STACK_H
#define OPENSSL_STACK_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_STACK_H
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque generic pointer stack; prefer the typed STACK_OF(...) wrappers.
 */
typedef struct stack_st OPENSSL_STACK; /* Use STACK_OF(...) instead */

/**
 * @brief Comparison callback used to order or search OPENSSL_STACK elements.
 * @param a First element pointer (as stored in the stack).
 * @param b Second element pointer (as stored in the stack).
 * @return Negative, zero, or positive like strcmp() when comparing @p a to @p b.
 */
typedef int (*OPENSSL_sk_compfunc)(const void *, const void *);
/**
 * @brief Callback that frees one element when OPENSSL_sk_pop_free() drains a stack.
 */
typedef void (*OPENSSL_sk_freefunc)(void *);
/**
 * @brief Deep-copy callback used by OPENSSL_sk_deep_copy() to duplicate one stack element.
 * @param p Element to copy.
 * @return Newly allocated copy of @p p, or NULL on failure.
 */
typedef void *(*OPENSSL_sk_copyfunc)(const void *);

/**
 * @brief Return the number of elements in a stack.
 * @param st Stack to query.
 * @return Element count, or 0 if @p st is NULL.
 */
int OPENSSL_sk_num(const OPENSSL_STACK *st);
/**
 * @brief Return the element at index @p idx in a stack (no bounds checking beyond returning NULL).
 * @param st Stack to query.
 * @param idx Zero-based index.
 * @return Element pointer, or NULL if @p idx is out of range.
 */
void *OPENSSL_sk_value(const OPENSSL_STACK *st, int idx);

/**
 * @brief Replace the pointer at index @p i in a stack.
 * @param st Stack to update.
 * @param i Zero-based index of the slot to replace.
 * @param data New element pointer stored at @p i.
 * @return Previous pointer at @p i, or NULL if @p i is out of range.
 */
void *OPENSSL_sk_set(OPENSSL_STACK *st, int i, const void *data);

/**
 * @brief Allocate an empty stack with an optional comparison function.
 * @param cmp Comparison callback for OPENSSL_sk_find()/sort, or NULL.
 * @return New stack, or NULL on failure; free with OPENSSL_sk_free().
 */
OPENSSL_STACK *OPENSSL_sk_new(OPENSSL_sk_compfunc cmp);
/**
 * @brief Allocate an empty stack with no comparison function.
 * @return New stack, or NULL on failure; free with OPENSSL_sk_free().
 */
OPENSSL_STACK *OPENSSL_sk_new_null(void);
/**
 * @brief Allocate a stack with comparison function @p c and room for @p n elements.
 * @param c Comparison callback, or NULL for an unordered stack.
 * @param n Number of element slots to reserve up front.
 * @return New stack, or NULL on failure; free with OPENSSL_sk_free().
 */
OPENSSL_STACK *OPENSSL_sk_new_reserve(OPENSSL_sk_compfunc c, int n);
/**
 * @brief Ensure a stack's internal array can hold at least @p n elements without reallocating.
 * @param st Stack to resize.
 * @param n Desired capacity.
 * @return 1 on success, or 0 on allocation failure.
 */
int OPENSSL_sk_reserve(OPENSSL_STACK *st, int n);
/**
 * @brief Free a stack structure without freeing its elements.
 * @param st Stack to free, or NULL.
 */
void OPENSSL_sk_free(OPENSSL_STACK *st);
/**
 * @brief Pop and free every element, then free the stack.
 * @param st Stack to destroy, or NULL.
 * @param func Destructor applied to each element (must accept the element pointer).
 */
void OPENSSL_sk_pop_free(OPENSSL_STACK *st, void (*func)(void *));
/**
 * @brief Deep-copy a stack by duplicating each element with @p c.
 * @param st Source stack.
 * @param c Element copy callback.
 * @param f Element free callback used to clean up on failure (and by callers later).
 * @return Newly allocated stack, or NULL on failure.
 */
OPENSSL_STACK *OPENSSL_sk_deep_copy(const OPENSSL_STACK *st,
    OPENSSL_sk_copyfunc c,
    OPENSSL_sk_freefunc f);
/**
 * @brief Insert @p data before index @p where (appending if @p where is out of range).
 * @param sk Stack to modify.
 * @param data Element pointer to store (not copied).
 * @param where Insertion index.
 * @return New number of elements, or 0 on failure.
 */
int OPENSSL_sk_insert(OPENSSL_STACK *sk, const void *data, int where);
/**
 * @brief Remove and return the element at index @p loc from a stack.
 * @param st Stack to modify.
 * @param loc Zero-based index of the element to remove.
 * @return Removed element pointer, or NULL if @p loc is out of range.
 */
void *OPENSSL_sk_delete(OPENSSL_STACK *st, int loc);
/**
 * @brief Delete the first stack element whose pointer equals @p p.
 * @param st Stack to modify.
 * @param p Element pointer to remove.
 * @return The removed pointer, or NULL if not found.
 */
void *OPENSSL_sk_delete_ptr(OPENSSL_STACK *st, const void *p);
/**
 * @brief Find the first stack element that compares equal to @p data.
 * @param st Stack to search (uses its comparison function when set).
 * @param data Value to locate.
 * @return Zero-based index of the match, or -1 if not found.
 */
int OPENSSL_sk_find(OPENSSL_STACK *st, const void *data);
/**
 * @brief Search for @p data; if absent, return the insertion index of the nearest greater element.
 * @param st Stack to search (sorted when a comparison function is set).
 * @param data Key passed to the comparison function.
 * @return Matching index, or a negative encoding of the insertion point when not found.
 */
int OPENSSL_sk_find_ex(OPENSSL_STACK *st, const void *data);
/**
 * @brief Search for @p data and report how many matching elements exist.
 * @param st Stack to search (sorted when a comparison function is set).
 * @param data Value to locate.
 * @param pnum Optional address updated to the number of matches (1 or 0 when no comparison function is set).
 * @return Zero-based index of a match, or -1 if not found.
 */
int OPENSSL_sk_find_all(OPENSSL_STACK *st, const void *data, int *pnum);
/**
 * @brief Append @p data to the end of a generic OPENSSL_STACK.
 * @param st Stack to modify.
 * @param data Element pointer to store.
 * @return Number of elements after the push, or 0 on failure.
 */
int OPENSSL_sk_push(OPENSSL_STACK *st, const void *data);
/**
 * @brief Insert @p data at the front of a generic OPENSSL_STACK.
 * @param st Stack to modify.
 * @param data Element pointer to store at index 0.
 * @return Number of elements after the insert, or 0 on failure.
 */
int OPENSSL_sk_unshift(OPENSSL_STACK *st, const void *data);
/**
 * @brief Remove and return the first element of a stack.
 * @param st Stack to modify.
 * @return Former front element, or NULL if @p st is empty/NULL.
 */
void *OPENSSL_sk_shift(OPENSSL_STACK *st);
/**
 * @brief Remove and return the last element of a stack.
 * @param st Stack to modify.
 * @return Former top element, or NULL if @p st is empty/NULL.
 */
void *OPENSSL_sk_pop(OPENSSL_STACK *st);
/**
 * @brief Clear a stack to zero elements without freeing the element pointers.
 * @param st Stack to reset, or NULL.
 */
void OPENSSL_sk_zero(OPENSSL_STACK *st);
/**
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
/**
 * @brief Report whether a stack is marked sorted under its comparison function.
 * @param st Stack to query.
 * @return 1 if sorted (or empty/no cmp), or 0 otherwise.
 */
int OPENSSL_sk_is_sorted(const OPENSSL_STACK *st);

#ifndef OPENSSL_NO_DEPRECATED_1_1_0
#define _STACK OPENSSL_STACK
#define sk_num OPENSSL_sk_num
#define sk_value OPENSSL_sk_value
#define sk_set OPENSSL_sk_set
#define sk_new OPENSSL_sk_new
#define sk_new_null OPENSSL_sk_new_null
#define sk_free OPENSSL_sk_free
#define sk_pop_free OPENSSL_sk_pop_free
#define sk_deep_copy OPENSSL_sk_deep_copy
#define sk_insert OPENSSL_sk_insert
#define sk_delete OPENSSL_sk_delete
#define sk_delete_ptr OPENSSL_sk_delete_ptr
#define sk_find OPENSSL_sk_find
#define sk_find_ex OPENSSL_sk_find_ex
#define sk_push OPENSSL_sk_push
#define sk_unshift OPENSSL_sk_unshift
#define sk_shift OPENSSL_sk_shift
#define sk_pop OPENSSL_sk_pop
#define sk_zero OPENSSL_sk_zero
#define sk_set_cmp_func OPENSSL_sk_set_cmp_func
#define sk_dup OPENSSL_sk_dup
#define sk_sort OPENSSL_sk_sort
#define sk_is_sorted OPENSSL_sk_is_sorted
#endif

#ifdef __cplusplus
}
#endif

#endif
