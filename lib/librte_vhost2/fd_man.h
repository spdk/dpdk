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
#include <pthread.h>
#include <poll.h>

#define MAX_FDS 1024

/** Static initializer for an fdset. */
#define RTE_FDSET_INITIALIZER { \
		.fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} }, \
		.fd_mutex = PTHREAD_MUTEX_INITIALIZER, \
		.max_fds = 0, \
		.u = {0} \
	}

typedef void (*fd_cb)(int fd, void *ctx);

/** Userspace entry for the polled descriptor. */
struct fdentry {
	int fd;
	fd_cb rcb;
	fd_cb wcb;
	fd_cb del_cb;
	void *ctx;
};

/** Set of the descriptors to be polled. */
struct fdset {
	/** Array for the poll (2). Accessible only by the poll thread. */
	struct pollfd	rwfds[MAX_FDS];
	/** Additional data for the fds. */
	struct fdentry	fd[MAX_FDS];
	/** Mutex for the fdset access. */
	pthread_mutex_t fd_mutex;
	/** Current number of polled descriptors. */
	int	num;
	/** Pipe to be polled for manual notifications. */
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
 * Initialize an fdset struct.
 * \param pfdset polled fds set
 */
void fdset_init(struct fdset *pfdset);

/**
 * Add descriptor to the pfdset. If this is the first descriptor
 * in the pfdset, a background poll thread will be started. Any blocking
 * poll will be interrupted to update the polled fds set as soon as possible.
 *
 * \param pfdset polled fds set
 * \param fd file descriptor
 * \param rcb callback to be called once `fd` becomes readable
 * \param wcb callback to be called once `fd` becomes writable
 * \param ctx context for the callbacks
 */
int fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *ctx);

/**
 * Asynchronously remove fd from the pfdset. If this the last descriptor
 * in the pfdset, the background poll thread will be stopped. Any blocking
 * poll will be interrupted to update the polled fds set as soon as possible.
 *
 * \param pfdset polled fds set
 * \param fd file descriptor
 * \param cpl_cb optional callback to be called on fd removal. First param
 * is the file descriptor, second param is the context provided in `fdset_add`.
 * The context can be safely freed after this function is called.
 */
void *fdset_del(struct fdset *pfdset, int fd, fd_cb cpl_cb);

/**
 * Call given function on the background poll thread of the fdset.
 * The background thread must be started. That is - at least one
 * descriptor must be present in the fdset at the time of calling
 * this function.
 *
 * \param pfdset polled fds set
 * \param cb_fn function to be called on the background thread. The
 * fist param (file descriptor) will be always -1.
 * \param ctx context for the `cb_fn`
 */
int fdset_notify(struct fdset *pfdset, fd_cb cb_fn, void *ctx);

#endif
