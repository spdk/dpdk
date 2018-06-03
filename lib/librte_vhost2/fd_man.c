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

enum fdset_event_type {
	EVENT_FD_ADD,
	EVENT_FD_DEL,
	EVENT_NOTIFY,
};

struct fdset_event {
	enum fdset_event_type type;
	struct {
		int fd;
		fd_cb rcb;
		fd_cb wcb;
		fd_modify_cb modify_cb;
		fd_cb notify_cb;
		void *ctx;
	} data;
};

static void *_fdset_event_dispatch(void *arg);

int
fdset_init(struct fdset *pfdset)
{
	pthread_t tid;
	int rc;

	pfdset->num = 0;

	if (pipe(pfdset->u.pipefd) < 0)
		return -errno;

	rc = rte_ctrl_thread_create(&tid,
				"vhost-events", NULL, _fdset_event_dispatch,
				pfdset);
	return rc;
}

static void
_fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb,
	   void *ctx, fd_modify_cb cpl_cb)
{

	struct fdentry *pfdentry;
	struct pollfd *pfd;
	int idx;

	if (pfdset->num == MAX_FDS) {
		cpl_cb(fd, -ENOSPC, ctx);
		return;
	}

	idx = pfdset->num++;
	pfdentry = &pfdset->fds[idx];
	pfdentry->fd  = fd;
	pfdentry->rcb = rcb;
	pfdentry->wcb = wcb;
	pfdentry->ctx = ctx;

	pfd = &pfdset->rwfds[idx];
	pfd->fd = fd;
	pfd->events  = rcb ? POLLIN : 0;
	pfd->events |= wcb ? POLLOUT : 0;
	pfd->revents = 0;

	cpl_cb(fd, 0, ctx);
}

static void
_fdset_del(struct fdset *pfdset, int fd, fd_modify_cb cpl_cb)
{
	int i;

	for (i = 0; i < pfdset->num; i++) {
		if (pfdset->fds[i].fd != fd)
			continue;

		pfdset->fds[i] = pfdset->fds[pfdset->num - 1];
		pfdset->rwfds[i] = pfdset->rwfds[pfdset->num - 1];

		pfdset->rwfds[i].revents = 0;
		pfdset->num--;
		cpl_cb(fd, 0, pfdset->fds[i].ctx);
		break;
	}

	if (i == pfdset->num)
		cpl_cb(fd, -ENOENT, NULL);
}

static void
_fdset_pipe_read_cb(int readfd, void *ctx)
{
	struct fdset *pfdset = ctx;
	struct fdset_event event;
	int r;

	r = read(readfd, &event, sizeof(event));
	if (r == -1) {
		/* TODO RTE_LOG */
		fprintf(stderr, "read() failed: %d\n", errno);
		return;
	}

	if (r != sizeof(event)) {
		/* TODO RTE_LOG */
		fprintf(stderr, "read() could only read %d of %zu bytes\n",
			r, sizeof(event));
		return;
	}

	switch (event.type) {
	case EVENT_FD_ADD:
		_fdset_add(pfdset, event.data.fd, event.data.rcb,
			   event.data.wcb, event.data.ctx,
			   event.data.modify_cb);
		break;

	case EVENT_FD_DEL:
		_fdset_del(pfdset, event.data.fd, event.data.modify_cb);
		break;

	case EVENT_NOTIFY:
		event.data.notify_cb(-1, event.data.ctx);
		break;
	}

}

static void
_add_pipefd_cpl(int fd __rte_unused, int rc, void *ctx __rte_unused)
{
	if (rc)
		assert(false);
}

static void *
_fdset_event_dispatch(void *arg)
{
	int i;
	struct pollfd *pfd;
	struct fdentry *pfdentry;
	int polled_fds_num, rc;
	struct fdset *pfdset = arg;

	_fdset_add(pfdset, pfdset->u.readfd,_fdset_pipe_read_cb,
		   NULL, pfdset, _add_pipefd_cpl);
	assert(pfdset->num == 1);

	do {
		polled_fds_num = pfdset->num;
		rc = poll(pfdset->rwfds, polled_fds_num, 1000 /* millisecs */);
		if (rc < 0)
			continue;

		for (i = 0; i < polled_fds_num; i++) {
			pfdentry = &pfdset->fds[i];
			pfd = &pfdset->rwfds[i];

			if (!pfd->revents)
				continue;

			if (pfdentry->rcb && pfd->revents & (POLLIN | FDPOLLERR))
				pfdentry->rcb(pfdentry->fd, pfdentry->ctx);
			if (pfdentry->wcb && pfd->revents & (POLLOUT | FDPOLLERR))
				pfdentry->wcb(pfdentry->fd, pfdentry->ctx);

		}
	} while (polled_fds_num > 1); /* there's always at least our pipe */

	close(pfdset->u.readfd);
	close(pfdset->u.writefd);
	assert(pfdset->num == 1);
	pfdset->num--;

	return NULL;
}

int
fdset_add(struct fdset *pfdset, int fd, fd_cb rcb, fd_cb wcb, void *ctx,
	  fd_modify_cb modify_cb)
{
	struct fdset_event event = {0};
	int r;

	if (fd == -1)
		return -EINVAL;

	event.type = EVENT_FD_ADD;
	event.data.fd = fd;
	event.data.rcb = rcb;
	event.data.wcb = wcb;
	event.data.modify_cb = modify_cb;
	event.data.ctx = ctx;

	r = write(pfdset->u.writefd, &event, sizeof(event));
	if (r == -1)
		return -errno;

	if (r != sizeof(event))
		return -EIO;

	return 0;
}

int
fdset_del(struct fdset *pfdset, int fd, fd_modify_cb modify_cb)
{
	struct fdset_event event = {0};
	int r;

	if (fd == -1)
		return -EINVAL;

	event.type = EVENT_FD_DEL;
	event.data.fd = fd;
	event.data.modify_cb = modify_cb;

	r = write(pfdset->u.writefd, &event, sizeof(event));
	if (r == -1)
		return -errno;

	if (r != sizeof(event))
		return -EIO;

	return 0;
}

int
fdset_notify(struct fdset *pfdset, fd_cb cb_fn, void *ctx)
{
	struct fdset_event event = {0};
	int r;

	event.type = EVENT_NOTIFY;
	event.data.notify_cb = cb_fn;
	event.data.ctx = ctx;

	r = write(pfdset->u.writefd, &event, sizeof(event));
	if (r == -1) {
		return -errno;
	}

	if (r != sizeof(event)) {
		return -EIO;
	}

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

		if (enabled)
			pfd->fd = pfdentry->fd;
		else {
			pfd->fd = -1;
			pfd->revents = 0;
		}
	}
}
