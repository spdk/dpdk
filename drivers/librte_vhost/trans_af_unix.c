/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2016 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Copyright (C) 2017 Red Hat, Inc.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#ifdef RTE_LIBRTE_VHOST_POSTCOPY
#include <linux/userfaultfd.h>
#endif
#include <fcntl.h>

#include <rte_log.h>

#include "fd_man.h"
#include "vhost.h"
#include "vhost_user.h"

#define MAX_VIRTIO_BACKLOG 128

static struct fdset af_unix_fdset = {
	.fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} },
	.fd_mutex = PTHREAD_MUTEX_INITIALIZER,
	.fd_pooling_mutex = PTHREAD_MUTEX_INITIALIZER,
	.num = 0
};

TAILQ_HEAD(vhost_user_connection_list, vhost_user_connection);

struct vhost_user_connection {
	struct virtio_net device; /* must be the first field! */
	struct vhost_user_socket *vsocket;
	int connfd;
	int slave_req_fd;
	rte_spinlock_t slave_req_lock;

	TAILQ_ENTRY(vhost_user_connection) next;
};

struct af_unix_socket {
	struct vhost_user_socket socket; /* must be the first field! */
	struct vhost_user_connection_list conn_list;
	pthread_mutex_t conn_mutex;
	int socket_fd;
	struct sockaddr_un un;
};

static int read_vhost_message(int sockfd, struct VhostUserMsg *msg);
static int create_unix_socket(struct vhost_user_socket *vsocket);
static int vhost_user_start_server(struct vhost_user_socket *vsocket);
static int vhost_user_start_client(struct vhost_user_socket *vsocket);
static void vhost_user_read_cb(int connfd, void *dat, int *remove);

/*
 * return bytes# of read on success or negative val on failure. Update fdnum
 * with number of fds read.
 */
static int
read_fd_message(int sockfd, char *buf, int buflen, int *fds, int max_fds,
		int *fd_num)
{
	struct iovec iov;
	struct msghdr msgh;
	char control[CMSG_SPACE(max_fds * sizeof(int))];
	struct cmsghdr *cmsg;
	int got_fds = 0;
	int ret;

	*fd_num = 0;

	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = buf;
	iov.iov_len  = buflen;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;
	msgh.msg_control = control;
	msgh.msg_controllen = sizeof(control);

	ret = recvmsg(sockfd, &msgh, 0);
	if (ret <= 0) {
		RTE_LOG(ERR, VHOST_CONFIG, "recvmsg failed\n");
		return ret;
	}

	if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
		RTE_LOG(ERR, VHOST_CONFIG, "truncted msg\n");
		return -1;
	}

	for (cmsg = CMSG_FIRSTHDR(&msgh); cmsg != NULL;
		cmsg = CMSG_NXTHDR(&msgh, cmsg)) {
		if ((cmsg->cmsg_level == SOL_SOCKET) &&
			(cmsg->cmsg_type == SCM_RIGHTS)) {
			got_fds = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
			*fd_num = got_fds;
			memcpy(fds, CMSG_DATA(cmsg), got_fds * sizeof(int));
			break;
		}
	}

	/* Clear out unused file descriptors */
	while (got_fds < max_fds)
		fds[got_fds++] = -1;

	return ret;
}

static int
send_fd_message(int sockfd, void *buf, int buflen, int *fds, int fd_num)
{
	struct iovec iov;
	struct msghdr msgh;
	size_t fdsize = fd_num * sizeof(int);
	char control[CMSG_SPACE(fdsize)];
	struct cmsghdr *cmsg;
	int ret;

	memset(&msgh, 0, sizeof(msgh));
	iov.iov_base = buf;
	iov.iov_len = buflen;

	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	if (fds && fd_num > 0) {
		msgh.msg_control = control;
		msgh.msg_controllen = sizeof(control);
		cmsg = CMSG_FIRSTHDR(&msgh);
		if (cmsg == NULL) {
			RTE_LOG(ERR, VHOST_CONFIG, "cmsg == NULL\n");
			errno = EINVAL;
			return -1;
		}
		cmsg->cmsg_len = CMSG_LEN(fdsize);
		cmsg->cmsg_level = SOL_SOCKET;
		cmsg->cmsg_type = SCM_RIGHTS;
		memcpy(CMSG_DATA(cmsg), fds, fdsize);
	} else {
		msgh.msg_control = NULL;
		msgh.msg_controllen = 0;
	}

	do {
		ret = sendmsg(sockfd, &msgh, MSG_NOSIGNAL);
	} while (ret < 0 && errno == EINTR);

	if (ret < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,  "sendmsg error\n");
		return ret;
	}

	return ret;
}

static int
af_unix_send_reply(struct virtio_net *dev, struct VhostUserMsg *msg)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	return send_fd_message(conn->connfd, msg,
			       VHOST_USER_HDR_SIZE + msg->size, msg->fds, msg->fd_num);
}

static int
af_unix_send_slave_req(struct virtio_net *dev, struct VhostUserMsg *msg)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);
	int ret;

	if (msg->flags & VHOST_USER_NEED_REPLY)
		rte_spinlock_lock(&conn->slave_req_lock);

	ret = send_fd_message(conn->slave_req_fd, msg,
			VHOST_USER_HDR_SIZE + msg->size, msg->fds, msg->fd_num);

	if (ret < 0 && (msg->flags & VHOST_USER_NEED_REPLY))
		rte_spinlock_unlock(&conn->slave_req_lock);

	return ret;
}

static int
af_unix_process_slave_message_reply(struct virtio_net *dev,
				    const struct VhostUserMsg *msg)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);
	struct VhostUserMsg msg_reply;
	int ret;

	if ((msg->flags & VHOST_USER_NEED_REPLY) == 0)
		return 0;

	if (read_vhost_message(conn->slave_req_fd, &msg_reply) < 0) {
		ret = -1;
		goto out;
	}

	if (msg_reply.request.slave != msg->request.slave) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"Received unexpected msg type (%u), expected %u\n",
			msg_reply.request.slave, msg->request.slave);
		ret = -1;
		goto out;
	}

	ret = msg_reply.payload.u64 ? -1 : 0;

out:
	rte_spinlock_unlock(&conn->slave_req_lock);
	return ret;
}

static int
af_unix_set_slave_req_fd(struct virtio_net *dev, struct VhostUserMsg *msg)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);
	int fd = msg->fds[0];

	if (fd < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
				"Invalid file descriptor for slave channel (%d)\n",
				fd);
		return -1;
	}

	conn->slave_req_fd = fd;

	return 0;
}

static void
vhost_user_add_connection(int fd, struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *s =
		container_of(vsocket, struct af_unix_socket, socket);
	struct virtio_net *dev;
	size_t size;
	struct vhost_user_connection *conn;
	int ret;

	if (vsocket == NULL)
		return;

	dev = vhost_new_device(vsocket->trans_ops);
	if (!dev) {
		return;
	}

	conn = container_of(dev, struct vhost_user_connection, device);
	conn->connfd = fd;
	conn->slave_req_fd = -1;
	conn->vsocket = vsocket;
	rte_spinlock_init(&conn->slave_req_lock);

	size = strnlen(vsocket->path, PATH_MAX);
	vhost_set_ifname(dev->vid, vsocket->path, size);

	vhost_set_builtin_virtio_net(dev->vid, vsocket->use_builtin_virtio_net);

	vhost_attach_vdpa_device(dev->vid, vsocket->vdpa_dev_id);

	if (vsocket->dequeue_zero_copy)
		vhost_enable_dequeue_zero_copy(dev->vid);

	RTE_LOG(INFO, VHOST_CONFIG, "new device, handle is %d\n", dev->vid);

	if (vsocket->notify_ops->new_connection) {
		ret = vsocket->notify_ops->new_connection(dev->vid);
		if (ret < 0) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"failed to add vhost user connection with fd %d\n",
				fd);
			goto err;
		}
	}

	ret = fdset_add(&af_unix_fdset, fd, vhost_user_read_cb,
			NULL, conn);
	if (ret < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to add fd %d into vhost server fdset\n",
			fd);

		if (vsocket->notify_ops->destroy_connection)
			vsocket->notify_ops->destroy_connection(dev->vid);

		goto err;
	}

	pthread_mutex_lock(&s->conn_mutex);
	TAILQ_INSERT_TAIL(&s->conn_list, conn, next);
	pthread_mutex_unlock(&s->conn_mutex);

	fdset_pipe_notify(&af_unix_fdset);
	return;

err:
	close(conn->connfd);
	vhost_destroy_device(dev->vid);
}

/* call back when there is new vhost-user connection from client  */
static void
vhost_user_server_new_connection(int fd, void *dat, int *remove __rte_unused)
{
	struct vhost_user_socket *vsocket = dat;

	fd = accept(fd, NULL, NULL);
	if (fd < 0)
		return;

	RTE_LOG(INFO, VHOST_CONFIG, "new vhost user connection is %d\n", fd);
	vhost_user_add_connection(fd, vsocket);
}

/* return bytes# of read on success or negative val on failure. */
static int
read_vhost_message(int sockfd, struct VhostUserMsg *msg)
{
	int ret;

	ret = read_fd_message(sockfd, (char *)msg, VHOST_USER_HDR_SIZE,
		msg->fds, VHOST_MEMORY_MAX_NREGIONS, &msg->fd_num);
	if (ret <= 0)
		return ret;

	if (msg->size) {
		if (msg->size > sizeof(msg->payload)) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"invalid msg size: %d\n", msg->size);
			return -1;
		}
		ret = read(sockfd, &msg->payload, msg->size);
		if (ret <= 0)
			return ret;
		if (ret != (int)msg->size) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"read control message failed\n");
			return -1;
		}
	}

	return ret;
}

static void
vhost_user_read_cb(int connfd, void *dat, int *remove)
{
	struct vhost_user_connection *conn = dat;
	struct vhost_user_socket *vsocket = conn->vsocket;
	struct af_unix_socket *s =
		container_of(vsocket, struct af_unix_socket, socket);
	struct VhostUserMsg msg;
	int ret;

	ret = read_vhost_message(connfd, &msg);
	if (ret <= 0) {
		if (ret < 0)
			RTE_LOG(ERR, VHOST_CONFIG,
				"vhost read message failed\n");
		else if (ret == 0)
			RTE_LOG(INFO, VHOST_CONFIG,
				"vhost peer closed\n");
		goto err;
	}

	ret = vhost_user_msg_handler(conn->device.vid, &msg);
	if (ret < 0) {
err:
		close(connfd);
		*remove = 1;

		if (vsocket->notify_ops->destroy_connection)
			vsocket->notify_ops->destroy_connection(conn->device.vid);

		pthread_mutex_lock(&s->conn_mutex);
		TAILQ_REMOVE(&s->conn_list, conn, next);
		pthread_mutex_unlock(&s->conn_mutex);

		vhost_destroy_device(conn->device.vid);

		if (vsocket->reconnect) {
			create_unix_socket(vsocket);
			vhost_user_start_client(vsocket);
		}
	}
}

static int
create_unix_socket(struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *s =
		container_of(vsocket, struct af_unix_socket, socket);
	int fd;
	struct sockaddr_un *un = &s->un;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	RTE_LOG(INFO, VHOST_CONFIG, "vhost-user %s: socket created, fd: %d\n",
		vsocket->is_server ? "server" : "client", fd);

	if (!vsocket->is_server && fcntl(fd, F_SETFL, O_NONBLOCK)) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"vhost-user: can't set nonblocking mode for socket, fd: "
			"%d (%s)\n", fd, strerror(errno));
		close(fd);
		return -1;
	}

	memset(un, 0, sizeof(*un));
	un->sun_family = AF_UNIX;
	strncpy(un->sun_path, vsocket->path, sizeof(un->sun_path));
	un->sun_path[sizeof(un->sun_path) - 1] = '\0';

	s->socket_fd = fd;
	return 0;
}

static int
vhost_user_start_server(struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *s =
		container_of(vsocket, struct af_unix_socket, socket);
	int ret;
	int fd = s->socket_fd;
	const char *path = vsocket->path;

	/*
	 * bind () may fail if the socket file with the same name already
	 * exists. But the library obviously should not delete the file
	 * provided by the user, since we can not be sure that it is not
	 * being used by other applications. Moreover, many applications form
	 * socket names based on user input, which is prone to errors.
	 *
	 * The user must ensure that the socket does not exist before
	 * registering the vhost driver in server mode.
	 */
	ret = bind(fd, (struct sockaddr *)&s->un, sizeof(s->un));
	if (ret < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to bind to %s: %s; remove it and try again\n",
			path, strerror(errno));
		goto err;
	}
	RTE_LOG(INFO, VHOST_CONFIG, "bind to %s\n", path);

	ret = listen(fd, MAX_VIRTIO_BACKLOG);
	if (ret < 0)
		goto err;

	ret = fdset_add(&af_unix_fdset, fd, vhost_user_server_new_connection,
		  NULL, vsocket);
	if (ret < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to add listen fd %d to vhost server fdset\n",
			fd);
		goto err;
	}

	return 0;

err:
	close(fd);
	return -1;
}

struct vhost_user_reconnect {
	struct sockaddr_un un;
	int fd;
	struct vhost_user_socket *vsocket;

	TAILQ_ENTRY(vhost_user_reconnect) next;
};

TAILQ_HEAD(vhost_user_reconnect_tailq_list, vhost_user_reconnect);
struct vhost_user_reconnect_list {
	struct vhost_user_reconnect_tailq_list head;
	pthread_mutex_t mutex;
};

static struct vhost_user_reconnect_list reconn_list;
static pthread_t reconn_tid;

static int
vhost_user_connect_nonblock(int fd, struct sockaddr *un, size_t sz)
{
	int ret, flags;

	ret = connect(fd, un, sz);
	if (ret < 0 && errno != EISCONN)
		return -1;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"can't get flags for connfd %d\n", fd);
		return -2;
	}
	if ((flags & O_NONBLOCK) && fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)) {
		RTE_LOG(ERR, VHOST_CONFIG,
				"can't disable nonblocking on fd %d\n", fd);
		return -2;
	}
	return 0;
}

static void *
vhost_user_client_reconnect(void *arg __rte_unused)
{
	int ret;
	struct vhost_user_reconnect *reconn, *next;

	while (1) {
		pthread_mutex_lock(&reconn_list.mutex);

		/*
		 * An equal implementation of TAILQ_FOREACH_SAFE,
		 * which does not exist on all platforms.
		 */
		for (reconn = TAILQ_FIRST(&reconn_list.head);
		     reconn != NULL; reconn = next) {
			next = TAILQ_NEXT(reconn, next);

			ret = vhost_user_connect_nonblock(reconn->fd,
						(struct sockaddr *)&reconn->un,
						sizeof(reconn->un));
			if (ret == -2) {
				close(reconn->fd);
				RTE_LOG(ERR, VHOST_CONFIG,
					"reconnection for fd %d failed\n",
					reconn->fd);
				goto remove_fd;
			}
			if (ret == -1)
				continue;

			RTE_LOG(INFO, VHOST_CONFIG,
				"%s: connected\n", reconn->vsocket->path);
			vhost_user_add_connection(reconn->fd, reconn->vsocket);
remove_fd:
			TAILQ_REMOVE(&reconn_list.head, reconn, next);
			free(reconn);
		}

		pthread_mutex_unlock(&reconn_list.mutex);
		sleep(1);
	}

	return NULL;
}

static int
vhost_user_reconnect_init(void)
{
	int ret;

	ret = pthread_mutex_init(&reconn_list.mutex, NULL);
	if (ret < 0) {
		RTE_LOG(ERR, VHOST_CONFIG, "failed to initialize mutex");
		return ret;
	}
	TAILQ_INIT(&reconn_list.head);

	ret = rte_ctrl_thread_create(&reconn_tid, "vhost_reconn", NULL,
			     vhost_user_client_reconnect, NULL);
	if (ret != 0) {
		RTE_LOG(ERR, VHOST_CONFIG, "failed to create reconnect thread");
		if (pthread_mutex_destroy(&reconn_list.mutex)) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"failed to destroy reconnect mutex");
		}
	}

	return ret;
}

static int
vhost_user_start_client(struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *s =
		container_of(vsocket, struct af_unix_socket, socket);
	int ret;
	int fd = s->socket_fd;
	const char *path = vsocket->path;
	struct vhost_user_reconnect *reconn;

	ret = vhost_user_connect_nonblock(fd, (struct sockaddr *)&s->un,
					  sizeof(s->un));
	if (ret == 0) {
		vhost_user_add_connection(fd, vsocket);
		return 0;
	}

	RTE_LOG(WARNING, VHOST_CONFIG,
		"failed to connect to %s: %s\n",
		path, strerror(errno));

	if (ret == -2 || !vsocket->reconnect) {
		close(fd);
		return -1;
	}

	RTE_LOG(INFO, VHOST_CONFIG, "%s: reconnecting...\n", path);
	reconn = malloc(sizeof(*reconn));
	if (reconn == NULL) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to allocate memory for reconnect\n");
		close(fd);
		return -1;
	}
	reconn->un = s->un;
	reconn->fd = fd;
	reconn->vsocket = vsocket;
	pthread_mutex_lock(&reconn_list.mutex);
	TAILQ_INSERT_TAIL(&reconn_list.head, reconn, next);
	pthread_mutex_unlock(&reconn_list.mutex);

	return 0;
}

static bool
vhost_user_remove_reconnect(struct vhost_user_socket *vsocket)
{
	int found = false;
	struct vhost_user_reconnect *reconn, *next;

	pthread_mutex_lock(&reconn_list.mutex);

	for (reconn = TAILQ_FIRST(&reconn_list.head);
	     reconn != NULL; reconn = next) {
		next = TAILQ_NEXT(reconn, next);

		if (reconn->vsocket == vsocket) {
			TAILQ_REMOVE(&reconn_list.head, reconn, next);
			close(reconn->fd);
			free(reconn);
			found = true;
			break;
		}
	}
	pthread_mutex_unlock(&reconn_list.mutex);
	return found;
}

static int
af_unix_socket_init(struct vhost_user_socket *vsocket,
		    uint64_t flags __rte_unused)
{
	struct af_unix_socket *s =
		container_of(vsocket, struct af_unix_socket, socket);
	int ret;

	if (vsocket->reconnect && reconn_tid == 0) {
		if (vhost_user_reconnect_init() != 0)
			return -1;
	}

	TAILQ_INIT(&s->conn_list);
	ret = pthread_mutex_init(&s->conn_mutex, NULL);
	if (ret) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"error: failed to init connection mutex\n");
		return -1;
	}

	return create_unix_socket(vsocket);
}

static void
af_unix_socket_cleanup(struct vhost_user_socket *vsocket)
{
	struct af_unix_socket *s =
		container_of(vsocket, struct af_unix_socket, socket);
	struct vhost_user_connection *conn, *next;

	if (vsocket->is_server) {
		fdset_del(&af_unix_fdset, s->socket_fd);
		close(s->socket_fd);
		unlink(vsocket->path);
	} else if (vsocket->reconnect) {
		vhost_user_remove_reconnect(vsocket);
	}

again:
	pthread_mutex_lock(&s->conn_mutex);
	for (conn = TAILQ_FIRST(&s->conn_list);
	     conn != NULL;
	     conn = next) {
		next = TAILQ_NEXT(conn, next);

		/*
		 * If r/wcb is executing, release the
		 * conn_mutex lock, and try again since
		 * the r/wcb may use the conn_mutex lock.
		 */
		if (fdset_try_del(&af_unix_fdset,
				  conn->connfd) == -1) {
			pthread_mutex_unlock(
					&s->conn_mutex);
			goto again;
		}

		RTE_LOG(INFO, VHOST_CONFIG,
			"free connfd = %d for device '%s'\n",
			conn->connfd, vsocket->path);
		close(conn->connfd);
		TAILQ_REMOVE(&s->conn_list, conn, next);
		vhost_destroy_device(conn->device.vid);
	}
	pthread_mutex_unlock(&s->conn_mutex);

	pthread_mutex_destroy(&s->conn_mutex);
}

static int
af_unix_socket_start(struct vhost_user_socket *vsocket)
{
	static pthread_t fdset_tid;

	if (fdset_tid == 0) {
		/**
		 * create a pipe which will be waited by poll and notified to
		 * rebuild the wait list of poll.
		 */
		if (fdset_pipe_init(&af_unix_fdset) < 0) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"failed to create pipe for vhost fdset\n");
			return -1;
		}

		int ret = rte_ctrl_thread_create(&fdset_tid,
			"vhost-events", NULL, fdset_event_dispatch,
			&af_unix_fdset);
		if (ret != 0) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"failed to create fdset handling thread");

			fdset_pipe_uninit(&af_unix_fdset);
			return -1;
		}
	}

	if (vsocket->is_server)
		return vhost_user_start_server(vsocket);
	else
		return vhost_user_start_client(vsocket);
}

static void
af_unix_cleanup_device(struct virtio_net *dev, int destroy __rte_unused)
{
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	if (dev->log_addr) {
		munmap((void *)(uintptr_t)dev->log_addr, dev->log_size);
		dev->log_addr = 0;
	}

	if (conn->slave_req_fd >= 0) {
		close(conn->slave_req_fd);
		conn->slave_req_fd = -1;
	}
}

static int
af_unix_vring_call(struct virtio_net *dev __rte_unused,
		   struct vhost_virtqueue *vq)
{
	if (vq->callfd >= 0)
		eventfd_write(vq->callfd, (eventfd_t)1);
	return 0;
}

static uint64_t
get_blk_size(int fd)
{
	struct stat stat;
	int ret;

	ret = fstat(fd, &stat);
	return ret == -1 ? (uint64_t)-1 : (uint64_t)stat.st_blksize;
}

static int
af_unix_map_mem_regions(struct virtio_net *dev, struct VhostUserMsg *msg)
{
	uint32_t i;
	struct VhostUserMemory *memory = &msg->payload.memory;
	struct vhost_user_connection *conn =
		container_of(dev, struct vhost_user_connection, device);

	for (i = 0; i < dev->mem->nregions; i++) {
		struct rte_vhost_mem_region *reg = &dev->mem->regions[i];
		uint64_t mmap_size = reg->mmap_size;
		uint64_t mmap_offset = mmap_size - reg->size;
		uint64_t alignment;
		void *mmap_addr;
		int populate;

		/* mmap() without flag of MAP_ANONYMOUS, should be called
		 * with length argument aligned with hugepagesz at older
		 * longterm version Linux, like 2.6.32 and 3.2.72, or
		 * mmap() will fail with EINVAL.
		 *
		 * to avoid failure, make sure in caller to keep length
		 * aligned.
		 */
		alignment = get_blk_size(reg->fd);
		if (alignment == (uint64_t)-1) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"couldn't get hugepage size through fstat\n");
			return -1;
		}
		mmap_size = RTE_ALIGN_CEIL(mmap_size, alignment);

		populate = (dev->dequeue_zero_copy) ? MAP_POPULATE : 0;
		mmap_addr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
				 MAP_SHARED | populate, reg->fd, 0);

		if (mmap_addr == MAP_FAILED) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"mmap region %u failed.\n", i);
			return -1;
		}

		reg->mmap_addr = mmap_addr;
		reg->mmap_size = mmap_size;
		reg->host_user_addr = (uint64_t)(uintptr_t)reg->mmap_addr +
				      mmap_offset;

		if (dev->dequeue_zero_copy)
			if (add_guest_pages(dev, reg, alignment) < 0) {
				RTE_LOG(ERR, VHOST_CONFIG,
					"adding guest pages to region %u failed.\n",
					i);
				return -1;
			}

		RTE_LOG(INFO, VHOST_CONFIG,
			"guest memory region %u, size: 0x%" PRIx64 "\n"
			"\t guest physical addr: 0x%" PRIx64 "\n"
			"\t guest virtual  addr: 0x%" PRIx64 "\n"
			"\t host  virtual  addr: 0x%" PRIx64 "\n"
			"\t mmap addr : 0x%" PRIx64 "\n"
			"\t mmap size : 0x%" PRIx64 "\n"
			"\t mmap align: 0x%" PRIx64 "\n"
			"\t mmap off  : 0x%" PRIx64 "\n",
			i, reg->size,
			reg->guest_phys_addr,
			reg->guest_user_addr,
			reg->host_user_addr,
			(uint64_t)(uintptr_t)reg->mmap_addr,
			reg->mmap_size,
			alignment,
			mmap_offset);

		if (dev->postcopy_listening) {
			/*
			 * We haven't a better way right now than sharing
			 * DPDK's virtual address with Qemu, so that Qemu can
			 * retrieve the region offset when handling userfaults.
			 */
			memory->regions[i].userspace_addr =
				reg->host_user_addr;
		}
	}

	if (dev->postcopy_listening) {
		/* Send the addresses back to qemu */
		msg->fd_num = 0;
		/* Send reply */
		msg->flags &= ~VHOST_USER_VERSION_MASK;
		msg->flags &= ~VHOST_USER_NEED_REPLY;
		msg->flags |= VHOST_USER_VERSION;
		msg->flags |= VHOST_USER_REPLY_MASK;
		af_unix_send_reply(dev, msg);

		/* Wait for qemu to acknolwedge it's got the addresses
		 * we've got to wait before we're allowed to generate faults.
		 */
		VhostUserMsg ack_msg;
		if (read_vhost_message(conn->connfd, &ack_msg) <= 0) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"Failed to read qemu ack on postcopy set-mem-table\n");
			return -1;
		}
		if (ack_msg.request.master != VHOST_USER_SET_MEM_TABLE) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"Bad qemu ack on postcopy set-mem-table (%d)\n",
				ack_msg.request.master);
			return -1;
		}

		/* Now userfault register and we can use the memory */
		for (i = 0; i < memory->nregions; i++) {
#ifdef RTE_LIBRTE_VHOST_POSTCOPY
			reg = &dev->mem->regions[i];
			struct uffdio_register reg_struct;

			/*
			 * Let's register all the mmap'ed area to ensure
			 * alignment on page boundary.
			 */
			reg_struct.range.start =
				(uint64_t)(uintptr_t)reg->mmap_addr;
			reg_struct.range.len = reg->mmap_size;
			reg_struct.mode = UFFDIO_REGISTER_MODE_MISSING;

			if (ioctl(dev->postcopy_ufd, UFFDIO_REGISTER,
						&reg_struct)) {
				RTE_LOG(ERR, VHOST_CONFIG,
					"Failed to register ufd for region %d: (ufd = %d) %s\n",
					i, dev->postcopy_ufd,
					strerror(errno));
				return -1;
			}
			RTE_LOG(INFO, VHOST_CONFIG,
				"\t userfaultfd registered for range : %llx - %llx\n",
				reg_struct.range.start,
				reg_struct.range.start +
				reg_struct.range.len - 1);
#else
			return -1;
#endif
		}
	}

	return 0;
}

static void
af_unix_unmap_mem_regions(struct virtio_net *dev)
{
	uint32_t i;
	struct rte_vhost_mem_region *reg;

	for (i = 0; i < dev->mem->nregions; i++) {
		reg = &dev->mem->regions[i];
		if (reg->host_user_addr) {
			munmap(reg->mmap_addr, reg->mmap_size);
			close(reg->fd);
		}
	}
}

static int
af_unix_set_log_base(struct virtio_net *dev, const struct VhostUserMsg *msg)
{
	int fd = msg->fds[0];
	uint64_t size, off;
	void *addr;

	size = msg->payload.log.mmap_size;
	off  = msg->payload.log.mmap_offset;

	/*
	 * mmap from 0 to workaround a hugepage mmap bug: mmap will
	 * fail when offset is not page size aligned.
	 */
	addr = mmap(0, size + off, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		RTE_LOG(ERR, VHOST_CONFIG, "mmap log base failed!\n");
		return -1;
	}

	/*
	 * Free previously mapped log memory on occasionally
	 * multiple VHOST_USER_SET_LOG_BASE.
	 */
	if (dev->log_addr) {
		munmap((void *)(uintptr_t)dev->log_addr, dev->log_size);
	}
	dev->log_addr = (uint64_t)(uintptr_t)addr;
	dev->log_base = dev->log_addr + off;
	dev->log_size = size;

	return 0;
}

const struct vhost_transport_ops af_unix_trans_ops = {
	.socket_size = sizeof(struct af_unix_socket),
	.device_size = sizeof(struct vhost_user_connection),
	.socket_init = af_unix_socket_init,
	.socket_cleanup = af_unix_socket_cleanup,
	.socket_start = af_unix_socket_start,
	.cleanup_device = af_unix_cleanup_device,
	.vring_call = af_unix_vring_call,
	.send_reply = af_unix_send_reply,
	.send_slave_req = af_unix_send_slave_req,
	.process_slave_message_reply = af_unix_process_slave_message_reply,
	.set_slave_req_fd = af_unix_set_slave_req_fd,
	.map_mem_regions = af_unix_map_mem_regions,
	.unmap_mem_regions = af_unix_unmap_mem_regions,
	.set_log_base = af_unix_set_log_base,
};
