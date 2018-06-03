/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Intel Corporation
 */

#ifndef _FD_MAN2_H_
#define _FD_MAN2_H_

/**
 * @file
 * fd_man is an util library for polling file descriptors.
 * It creates a background poll thread and calls provided
 * callbacks once a descriptor becomes readable or writeable.
 * To simplify the threading model for users, it is possible
 * to call custom callbacks on the background thread whenever
 * requested.
 */

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <poll.h>

#define MAX_FDS 1024

typedef void (*fd_cb)(int fd, void *ctx);
typedef void (*fd_modify_cb)(int fd, int rc, void *ctx);

/** Userspace entry for the polled descriptor. */
struct fdentry {
	int fd;
	fd_cb rcb;
	fd_cb wcb;
	void *ctx;
};

/** Set of the descriptors to be polled. */
struct fdset {
	/** Array for the poll (2). Accessible only by the poll thread. */
	struct pollfd	rwfds[MAX_FDS];
	/** Additional data for the descriptors. */
	struct fdentry	fds[MAX_FDS];
	/** Current number of polled descriptors. */
	int		num;
	/** Pipe for notifications. */
	union pipefds {
		struct {
			int pipefd[2];
		};
		struct {
			int readfd;
			int writefd;
		};
	} u;
};

/**
 * Init an fdset and start its background poll thread.
 *
 * \param pfdset polled fds set
 * \return 0 on success, negative errno otherwise
 */
int fdset_init(struct fdset *pfdset);

/**
 * Deinit an fdset and stop its background poll thread.
 *
 * \param pfdset polled fds set
 * \return 0 on success, negative errno otherwise
 */
int fdset_deinit(struct fdset *pfdset);

/**
 * Asynchronously add descriptor to the pfdset. Any blocking poll will be
 * interrupted to update the polled fds set as soon as possible.
 *
 * \param pfdset polled fds set
 * \param fd file descriptor
 * \param rcb optional callback to be called once `fd` becomes readable
 * \param wcb optional callback to be called once `fd` becomes writable
 * \param ctx context for the callbacks
 * \param cpl_cb optional callback to be called right after the fd addition
 * First param is the file descriptor, second param is the return code,
 * third param is the provided `ctx` argument. This function will be called
 * from the background poll thread - the same one that calls read/write
 * callbacks for this pfdset.
 * \return 0 on success, negative errno otherwise. In case of an immediate
 * error, the cpl_cb is not called.
 */
int fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *ctx,
	  fd_modify_cb cpl_cb);

/**
 * Asynchronously remove fd from the pfdset. Any blocking poll will be
 * interrupted to update the polled fds set as soon as possible.
 *
 * \param pfdset polled fds set
 * \param fd file descriptor
 * \param cpl_cb optional callback to be called right after the fd removal
 * First param is the file descriptor, second param is the return code,
 * third param is the context provided in `fdset_add`. This function will
 * be called from the background poll thread - the same one that calls
 * read/write callbacks for this pfdset.
 * \return 0 on success, negative errno otherwise. In case of an immediate
 * error, the cpl_cb is not called.
 */
int fdset_del(struct fdset *pfdset, int fd, fd_modify_cb cpl_cb);

/**
 * Call given function on the background poll thread of the fdset.
 *
 * \param pfdset polled fds set
 * \param cb_fn function to be called on the background thread. The
 * fist param (file descriptor) will be always -1.
 * \param ctx context for the `cb_fn`
 * \return 0 on success, negative errno otherwise. In case of error,
 * the cpl_cb is not called.
 */
int fdset_notify(struct fdset *pfdset, fd_cb cb_fn, void *ctx);

/**
 * Enable/disable polling given fd in an efficient manner. This function
 * is synchronous. If disabling, the `fd` won't be polled until after
 * it is enabled again.
 *
 * This function must be called from within the pfdset's polling thread.
 *
 * \param pfdset polled fds set
 * \param fd file descriptor
 * \param enabled enable or disable the `fd`
 */
void fdset_enable(struct fdset *pfdset, int fd, bool enabled);

#endif /* _FD_MAN2_H_ */
