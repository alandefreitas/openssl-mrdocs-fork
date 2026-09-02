/*
 * Copyright 2015-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>

#ifndef OPENSSL_ASYNC_H
#define OPENSSL_ASYNC_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_ASYNC_H
#endif

#if defined(_WIN32)
#if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> to use this */
#define OSSL_ASYNC_FD HANDLE
#define OSSL_BAD_ASYNC_FD INVALID_HANDLE_VALUE
#endif
#else
#define OSSL_ASYNC_FD int
#define OSSL_BAD_ASYNC_FD -1
#endif
#include <openssl/asyncerr.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Opaque state for an asynchronous job.
 */
typedef struct async_job_st ASYNC_JOB;
/**
 * @brief Opaque wait context describing file descriptors an ASYNC_JOB is blocked on.
 */
typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;
/**
 * @brief Callback invoked when an asynchronous wait context is ready.
 * @param arg User data supplied when the callback was registered.
 * @return Application-defined status code.
 */
typedef int (*ASYNC_callback_fn)(void *arg);

#define ASYNC_ERR 0
#define ASYNC_NO_JOBS 1
#define ASYNC_PAUSE 2
#define ASYNC_FINISH 3

#define ASYNC_STATUS_UNSUPPORTED 0
#define ASYNC_STATUS_ERR 1
#define ASYNC_STATUS_OK 2
#define ASYNC_STATUS_EAGAIN 3

/**
 * @brief Initialise per-thread asynchronous job support for the current thread.
 * @param max_size Maximum stack pool size in bytes for ASYNC jobs (0 for the default).
 * @param init_size Initial stack pool size in bytes (0 for the default); must be <= @p max_size.
 * @return 1 on success, or 0 on failure.
 */
int ASYNC_init_thread(size_t max_size, size_t init_size);
/**
 * @brief Release per-thread asynchronous job resources allocated by ASYNC_init_thread().
 *
 * Must be called on a thread that previously called ASYNC_init_thread() (or used
 * async jobs) after no ASYNC_JOB remains outstanding for that thread.
 */
void ASYNC_cleanup_thread(void);

#ifdef OSSL_ASYNC_FD
/**
 * @brief Allocate a new asynchronous wait context.
 * @return New ASYNC_WAIT_CTX, or NULL on allocation failure.
 *
 * Create one before ASYNC_start_job(); a context is associated with at most one
 * ASYNC_JOB at a time but may be reused after that job finishes.
 */
ASYNC_WAIT_CTX *ASYNC_WAIT_CTX_new(void);
/**
 * @brief Free an asynchronous wait context and its associated resources.
 * @param ctx Wait context to free, or NULL.
 */
void ASYNC_WAIT_CTX_free(ASYNC_WAIT_CTX *ctx);
/**
 * @brief Associate a waitable file descriptor with a key in the wait context.
 * @param ctx Wait context to update.
 * @param key Unique key identifying this wait fd.
 * @param fd File descriptor to wait on.
 * @param custom_data Optional application data for the cleanup callback.
 * @param cleanup Optional callback to release @p custom_data when the fd is cleared.
 * @return 1 on success, or 0 on error.
 */
int ASYNC_WAIT_CTX_set_wait_fd(ASYNC_WAIT_CTX *ctx, const void *key,
    OSSL_ASYNC_FD fd,
    void *custom_data,
    void (*cleanup)(ASYNC_WAIT_CTX *, const void *,
        OSSL_ASYNC_FD, void *));
/**
 * @brief Look up the wait file descriptor registered under @p key.
 * @param ctx Wait context to query.
 * @param key Unique key previously passed to ASYNC_WAIT_CTX_set_wait_fd.
 * @param fd Receives the registered OSSL_ASYNC_FD on success.
 * @param custom_data Receives the custom_data pointer registered with the fd, or NULL.
 * @return 1 if a matching fd was found, or 0 otherwise.
 */
int ASYNC_WAIT_CTX_get_fd(ASYNC_WAIT_CTX *ctx, const void *key,
    OSSL_ASYNC_FD *fd, void **custom_data);
/**
 * @brief Collect every wait file descriptor currently registered on @p ctx.
 * @param ctx Wait context to query.
 * @param fd Optional array that receives up to *@p numfds descriptors; may be NULL to query the count only.
 * @param numfds On input, capacity of @p fd when non-NULL; on output, the number of registered fds.
 * @return 1 on success, or 0 on failure.
 */
int ASYNC_WAIT_CTX_get_all_fds(ASYNC_WAIT_CTX *ctx, OSSL_ASYNC_FD *fd,
    size_t *numfds);
/**
 * @brief Retrieve the completion callback previously set on an async wait context.
 * @param ctx Wait context to query.
 * @param callback Receives the registered callback function pointer.
 * @param callback_arg Receives the callback user argument.
 * @return 1 if a callback is set, or 0 if none was registered.
 */
int ASYNC_WAIT_CTX_get_callback(ASYNC_WAIT_CTX *ctx,
    ASYNC_callback_fn *callback,
    void **callback_arg);
/**
 * @brief Register a callback notified when an engine completes an async operation.
 * @param ctx Wait context that stores the callback.
 * @param callback Function invoked from a poll or interrupt context; must be small and nonblocking.
 * @param callback_arg User argument passed to @p callback.
 * @return 1 on success, or 0 on error.
 *
 * Prefer this when a wait file descriptor is too costly or unavailable. Pair with
 * ASYNC_WAIT_CTX_set_status() so the engine can report ASYNC_STATUS_* progress.
 */
int ASYNC_WAIT_CTX_set_callback(ASYNC_WAIT_CTX *ctx,
    ASYNC_callback_fn callback,
    void *callback_arg);
/**
 * @brief Set the engine-reported status of an asynchronous wait context.
 * @param ctx Wait context to update.
 * @param status One of the ASYNC_STATUS_* values describing progress or readiness.
 * @return 1 on success, or 0 on error.
 */
int ASYNC_WAIT_CTX_set_status(ASYNC_WAIT_CTX *ctx, int status);
/**
 * @brief Get the current status of an asynchronous wait context.
 * @param ctx Wait context to query.
 * @return One of the ASYNC_STATUS_* values.
 */
int ASYNC_WAIT_CTX_get_status(ASYNC_WAIT_CTX *ctx);
/**
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
/**
 * @brief Remove the wait file descriptor associated with @p key from a wait context.
 * @param ctx Wait context to update.
 * @param key Unique key previously passed to ASYNC_WAIT_CTX_set_wait_fd.
 * @return 1 on success, or 0 if no matching fd was found.
 *
 * Does not invoke the cleanup callback registered with set_wait_fd; the caller
 * is responsible for releasing the fd and any custom_data.
 */
int ASYNC_WAIT_CTX_clear_fd(ASYNC_WAIT_CTX *ctx, const void *key);
#endif

/**
 * @brief Report whether the current platform supports asynchronous jobs.
 * @return 1 if ASYNC_start_job() and related APIs are usable, or 0 otherwise.
 */
int ASYNC_is_capable(void);

/**
 * @brief Allocate a stack for an asynchronous job (POSIX custom stack allocator).
 * @param num On entry, requested stack size in bytes; on return, actual size of the allocated stack.
 * @return Pointer to the allocated stack base, or NULL on failure.
 */
typedef void *(*ASYNC_stack_alloc_fn)(size_t *num);
/**
 * @brief Free a stack previously returned by an ASYNC_stack_alloc_fn callback.
 * @param addr Stack base pointer returned by the matching allocator.
 */
typedef void (*ASYNC_stack_free_fn)(void *addr);

/**
 * @brief Install custom stack allocators used for ASYNC jobs on POSIX.
 * @param alloc_fn Allocator called when OpenSSL needs a job stack, or NULL for the default.
 * @param free_fn Matching free callback for stacks returned by @p alloc_fn, or NULL for the default.
 * @return 1 if custom allocators are supported and none have been used yet, or 0 otherwise.
 *
 * Must be called before any asynchronous job allocates a stack. On unsupported
 * platforms the call fails and the defaults remain in effect.
 */
int ASYNC_set_mem_functions(ASYNC_stack_alloc_fn alloc_fn,
    ASYNC_stack_free_fn free_fn);
/**
 * @brief Retrieve the current custom ASYNC stack allocator callbacks.
 * @param alloc_fn Receives the installed allocator, or NULL if the default is in use.
 * @param free_fn Receives the installed free callback, or NULL if the default is in use.
 */
void ASYNC_get_mem_functions(ASYNC_stack_alloc_fn *alloc_fn,
    ASYNC_stack_free_fn *free_fn);

/**
 * @brief Start or resume an asynchronous job.
 * @param job Location of the job pointer; updated when the job pauses or finishes.
 * @param ctx Wait context used while the job is running.
 * @param ret Receives the job function's return value when the job finishes.
 * @param func Function to run asynchronously; receives @p args.
 * @param args Argument passed to @p func.
 * @param size Size in bytes of the memory copied into the job for @p args.
 * @return ASYNC_ERR, ASYNC_NO_JOBS, ASYNC_PAUSE, or ASYNC_FINISH.
 */
int ASYNC_start_job(ASYNC_JOB **job, ASYNC_WAIT_CTX *ctx, int *ret,
    int (*func)(void *), void *args, size_t size);
/**
 * @brief Pause the current ASYNC_JOB and return control to ASYNC_start_job().
 * @return 1 if the job paused successfully, or 0 if pausing is blocked or no job is running.
 */
int ASYNC_pause_job(void);

/**
 * @brief Return the ASYNC_JOB currently executing on this thread, if any.
 * @return The current job, or NULL when called outside an ASYNC job.
 */
ASYNC_JOB *ASYNC_get_current_job(void);
/**
 * @brief Return the wait context associated with an asynchronous job.
 * @param job Job whose wait context is requested.
 * @return The job's ASYNC_WAIT_CTX, or NULL if @p job is NULL.
 */
ASYNC_WAIT_CTX *ASYNC_get_wait_ctx(ASYNC_JOB *job);
/**
 * @brief Temporarily ignore ASYNC_pause_job() on the current thread.
 *
 * Nested calls nest; each block must be matched by ASYNC_unblock_pause().
 * Use around code that must not yield (for example while holding locks).
 */
void ASYNC_block_pause(void);
/**
 * @brief Allow ASYNC_pause_job() again after a matching ASYNC_block_pause().
 */
void ASYNC_unblock_pause(void);

#ifdef __cplusplus
}
#endif
#endif
