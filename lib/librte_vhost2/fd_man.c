/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Intel Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

#include <rte_common.h>
#include <rte_log.h>

#include "fd_man.h"

#define FDPOLLERR (POLLERR | POLLHUP | POLLNVAL)

static int
_get_last_valid_idx(struct fdset *pfdset, int last_valid_idx)
{
	int i;

	for (i = last_valid_idx; i >= 0; i--) {
		if (pfdset->fd[i].fd != -1)
			return i;
	}

	return -1;
}

static unsigned
_fdset_shrink(struct fdset *pfdset)
{
	int i;
	int last_valid_idx = _get_last_valid_idx(pfdset, pfdset->num - 1);

	for (i = 0; i < last_valid_idx; i++) {
		if (pfdset->fd[i].fd != -1)
			continue;

		pfdset->fd[i]    = pfdset->fd[last_valid_idx];
		pfdset->rwfds[i] = pfdset->rwfds[last_valid_idx];
		last_valid_idx = _get_last_valid_idx(pfdset, last_valid_idx - 1);
	}

	pfdset->num = last_valid_idx + 1;
	return pfdset->num;
}

void
fdset_init(struct fdset *pfdset)
{
	int i;

	for (i = 0; i < MAX_FDS; i++) {
		pfdset->fd[i].fd = -1;
		pfdset->fd[i].ctx = NULL;
	}

	pfdset->num = 0;

	pthread_mutex_init(&pfdset->fd_mutex);
}

static void *_fdset_event_dispatch(void *arg);

static int
_fdset_start_thread(struct fdset *pfdset)
{
	int rc;

	if (pipe(pfdset->u.pipefd) < 0) {
		return -errno;
	}

	rc = fdset_add(pfdset, pfdset->u.readfd,
		       _fdset_pipe_read_cb, NULL, NULL);

	if (rc < 0) {
		close(pfdset->u.readfd);
		close(pfdset->u.writefd);
		return rc;
	}

	rc = rte_ctrl_thread_create(&pfdset->tid,
				"vhost-events", NULL, _fdset_event_dispatch,
				pfdset);
	if (rc) {
		fdset_del(pfdset, pfdset->u.readfd);
		close(pfdset->u.readfd);
		close(pfdset->u.writefd);
	}

	return rc;
}

int
fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *ctx)
{
	struct fdentry *pfdentry;
	struct pollfd *pfd;
	int i, rc;

	pthread_mutex_lock(&pfdset->fd_mutex);
	if (pfdset->num == MAX_FDS) {
		rc = -ENOSPC;
		goto out_unlock;
	}

	i = pfdset->num++;

	pfdentry = &pfdset->fd[i];
	pfdentry->fd  = fd;
	pfdentry->rcb = rcb;
	pfdentry->wcb = wcb;
	pfdentry->del_cb = NULL;
	pfdentry->ctx = ctx;

	pfd = &pfdset->rwfds[i];
	pfd->fd = fd;
	pfd->events  = rcb ? POLLIN : 0;
	pfd->events |= wcb ? POLLOUT : 0;
	pfd->revents = 0;

	if (i == 0) {
		/* This is the first and the only fd in the pfdset. */
		rc = _fdset_start_thread(pfdset);
		if (rc) {
			pfdentry->fd = -1;
			pfdentry->rcb = pfdentry->wcb = NULL;
			pfdentry->ctx = NULL;
		}
	}

out_unlock:
	pthread_mutex_unlock(&pfdset->fd_mutex);

	/* Interrupt any blocking poll. This will result in pollfd array
	 * being updated immediately. */
	fdset_notify(pfdset, NULL, NULL);

	return rc;
}

int
fdset_del(struct fdset *pfdset, int fd, fd_cb cb)
{
	struct fdentry *pfdentry;
	int i;

	if (fd == -1)
		return -1;

	pthread_mutex_lock(&pfdset->fd_mutex);
	for (i = 0; i < pfdset->num; i++) {
		pfdentry = &pfdset->fd[i];
		if (pfdentry->fd != fd)
			continue;

		if (pfdentry->del_cb)
			continue;

		pfdentry->fd = -1;
		pfdentry->del_cb = cb;
		break;
	}
	pthread_mutex_unlock(&pfdset->fd_mutex);

	if (i == pfdset->num)
		return -1;

	/* Interrupt any blocking poll. This will result in pollfd array
	 * being updated immediately. */
	fdset_notify(pfdset, NULL, NULL);

	return 0;
}

static void *
_fdset_event_dispatch(void *arg)
{
	int i;
	struct pollfd *pfd;
	struct fdentry *pfdentry;
	fd_cb rcb, wcb, del_cb;
	void *ctx;
	int fd, max_fds, rc;
	struct fdset *pfdset = arg;

	do {
		pthread_mutex_lock(&pfdset->fd_mutex);
		max_fds = pfdset->num;
		pthread_mutex_unlock(&pfdset->fd_mutex);

		rc = poll(pfdset->rwfds, max_fds, 1000 /* millisecs */);
		if (rc < 0)
			continue;

		pthread_mutex_lock(&pfdset->fd_mutex);
		for (i = 0; i < max_fds; i++) {
			pfdentry = &pfdset->fd[i];
			pfd = &pfdset->rwfds[i];
			fd = pfdentry->fd;
			rcb = pfdentry->rcb;
			wcb = pfdentry->wcb;
			del_cb = pfdentry->del_cb;
			ctx = pfdentry->ctx;

			if (fd < 0) {
				fd = pfd->fd; /* retrieve the actual fd */
				if (del_cb) {
					pthread_mutex_unlock(&pfdset->fd_mutex);
					del_cb(fd, ctx);
					pthread_mutex_lock(&pfdset->fd_mutex);
				}
				pfdentry->rcb = pfdentry->wcb = NULL;
				pfdentry->del_cb = NULL;
				pfdentry->ctx = NULL;
				max_fds = _fdset_shrink(pfdset);
				i--; /* process the next fd now at the same index */
				continue;
			}

			if (!pfd->revents)
				continue;

			pthread_mutex_unlock(&pfdset->fd_mutex);

			if (rcb && pfd->revents & (POLLIN | FDPOLLERR))
				rcb(fd, ctx);
			if (wcb && pfd->revents & (POLLOUT | FDPOLLERR))
				wcb(fd, ctx);

			pthread_mutex_lock(&pfdset->fd_mutex);
		}
		pthread_mutex_unlock(&pfdset->fd_mutex);
	} while (max_fds);

	return NULL;
}

struct fdset_event {
	fd_cb cb_fn;
	void *ctx;
};

static void
_fdset_pipe_read_cb(int readfd, void *ctx __rte_unused)
{
	struct fdset_event event;
	int r;

	r = read(readfd, &event, sizeof(event));
	if (r == -1) {
		//TODO RTE_LOG
		fprintf(stderr, "read failed: %d\n", errno);
		return;
	}

	if (r != sizeof(event)) {
		fprintf(stderr, "read %d bytes instead of %d\n", r, sizeof(event));
		return;
	}

	if (event.cb_fn) {
		event.cb_fn(-1, event.ctx);
	}
}

int
fdset_notify(struct fdset *fdset, fd_cb cb_fn, void *ctx)
{
	struct fdset_event event;
	int r;

	if (fdset->num == 0) {
		return -ESRCH;
	}

	event.cb_fn = cb_fn;
	event.ctx = ctx;

	r = write(fdset->u.writefd, &event, sizeof(event));
	if (r == -1) {
		return -errno;
	}

	if (r != sizeof(event)) {
		return -EIO;
	}

	return 0;
}
