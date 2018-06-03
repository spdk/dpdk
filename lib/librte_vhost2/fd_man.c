/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Intel Corporation
 */

#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <assert.h>

#include <rte_lcore.h>

#include "fd_man.h"

#define FDPOLLERR (POLLERR | POLLHUP | POLLNVAL)

struct fdset_event {
	fd_cb cb_fn;
	void *ctx;
};

static void *_fdset_event_dispatch(void *arg);

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
		return;
	}

	if (event.cb_fn) {
		event.cb_fn(-1, event.ctx);
	}
}


static void
_fdset_set_nolock(struct fdset *pfdset, int idx, int fd,
		fd_cb rcb, fd_cb wcb, void *ctx)
{
	struct fdentry *pfdentry;
	struct pollfd *pfd;
	int i = idx;

	pfdentry = &pfdset->fds[i];
	pfdentry->fd  = fd;
	pfdentry->rcb = rcb;
	pfdentry->wcb = wcb;
	pfdentry->removed = false;
	pfdentry->del_cb = NULL;
	pfdentry->ctx = ctx;

	pfd = &pfdset->rwfds[i];
	pfd->fd = fd;
	pfd->events  = rcb ? POLLIN : 0;
	pfd->events |= wcb ? POLLOUT : 0;
	pfd->revents = 0;
}

static int
_fdset_start_thread(struct fdset *pfdset)
{
	pthread_t tid;
	int rc;

	if (pipe(pfdset->u.pipefd) < 0) {
		return -errno;
	}

	_fdset_set_nolock(pfdset, 0, pfdset->u.readfd,
		       _fdset_pipe_read_cb, NULL, NULL);

	rc = rte_ctrl_thread_create(&tid,
				"vhost-events", NULL, _fdset_event_dispatch,
				pfdset);
	if (rc) {
		_fdset_set_nolock(pfdset, 0, -1, NULL, NULL, NULL);
		close(pfdset->u.readfd);
		close(pfdset->u.writefd);
	}

	return rc;
}

int
fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *ctx)
{
	int i, rc = 0;

	pthread_mutex_lock(&pfdset->fd_mutex);
	if (pfdset->num == MAX_FDS) {
		pthread_mutex_unlock(&pfdset->fd_mutex);
		return -ENOSPC;
	}

	i = pfdset->num++;

	if (i == 0) {
		/* This is the first and the only fd in the pfdset. */
		rc = _fdset_start_thread(pfdset);
		i = pfdset->num++;
	}

	pthread_mutex_unlock(&pfdset->fd_mutex);

	if (rc) {
		return rc;
	}

	_fdset_set_nolock(pfdset, i, fd, rcb, wcb, ctx);

	/* Interrupt any blocking poll. This will result in pollfd array
	 * being updated immediately. */
	fdset_notify(pfdset, NULL, NULL);
	return 0;
}

int
fdset_del(struct fdset *pfdset, int fd, fd_cb cb)
{
	struct fdentry *pfdentry;
	int i;

	if (fd == -1)
		return -EINVAL;

	pthread_mutex_lock(&pfdset->fd_mutex);
	for (i = 0; i < pfdset->num; i++) {
		pfdentry = &pfdset->fds[i];
		if (pfdentry->fd != fd)
			continue;

		if (pfdentry->removed)
			continue;

		pfdentry->removed = true;
		pfdentry->del_cb = cb;
		break;
	}

	if (i == pfdset->num) {
		pthread_mutex_unlock(&pfdset->fd_mutex);
		return -ENOENT;
	}

	pthread_mutex_unlock(&pfdset->fd_mutex);

	/* Interrupt any blocking poll. This will result in pollfd array
	 * being updated immediately. */
	fdset_notify(pfdset, NULL, NULL);

	return 0;
}

void
fdset_enable(struct fdset *pfdset, int fd, bool enabled)
{
	struct fdentry *pfdentry;
	struct pollfd *pfd;
	int i;

	/* called from within the poll thread */
	for (i = 0; i < pfdset->num; i++) {
		pfd = &pfdset->rwfds[i];
		pfdentry = &pfdset->fds[i];
		if (pfdentry->fd != fd)
			continue;

		if (enabled) {
			pfd->fd = pfdentry->fd;
			/* no point in notifying the fdset, since we are
			 * sure we're not blocked on poll(2) right now
			 */
		} else {
			pfd->fd = -1;
		}
	}
}

static unsigned
_fdset_shrink_by_one(struct fdset *pfdset)
{
	int last_valid_idx = -1;
	int i;

	for (i = pfdset->num - 1; i >= 0; i--) {
		if (pfdset->fds[i].fd != -1) {
			last_valid_idx = i;
			break;
		}
	}

	if (last_valid_idx == -1)
		return 0;

	for (i = 0; i < pfdset->num - 1; i++) {
		if (pfdset->fds[i].fd != -1)
			continue;

		pfdset->fds[i] = pfdset->fds[last_valid_idx];
		pfdset->rwfds[i] = pfdset->rwfds[last_valid_idx];
		break;
	}

	pfdset->num--;
	return pfdset->num;
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
			pfdentry = &pfdset->fds[i];
			pfd = &pfdset->rwfds[i];
			fd = pfdentry->fd;
			rcb = pfdentry->rcb;
			wcb = pfdentry->wcb;
			del_cb = pfdentry->del_cb;
			ctx = pfdentry->ctx;

			if (pfdentry->removed) {
				pfdentry->fd = -1;
				pfdentry->rcb = pfdentry->wcb = NULL;
				pfdentry->del_cb = NULL;
				pfdentry->ctx = NULL;
				max_fds = _fdset_shrink_by_one(pfdset);
				if (del_cb) {
					pthread_mutex_unlock(&pfdset->fd_mutex);
					del_cb(fd, ctx);
					pthread_mutex_lock(&pfdset->fd_mutex);
				}
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
	} while (max_fds > 1); /* there's always at least our pipe */

	close(pfdset->u.readfd);
	close(pfdset->u.writefd);
	assert(pfdset->num == 1);
	pfdset->num--;

	return NULL;
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
