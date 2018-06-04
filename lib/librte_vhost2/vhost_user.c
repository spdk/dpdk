/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Intel Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/queue.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <assert.h>

#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_atomic.h>

#include "rte_vhost2.h"
#include "transport.h"
#include "fd_man.h"
#include "vhost.h"

#define MAX_SOCKET_BACKLOG 128

struct vhost_user_mem_region {
	uint64_t guest_phys_addr;
	uint64_t guest_user_addr;
	uint64_t host_user_addr;
	uint64_t size;
	void	 *mmap_addr;
	uint64_t mmap_size;
	int fd;
};

struct vhost_user_memory {
	uint32_t nregions;
	struct vhost_user_mem_region regions[];
};

struct vhost_user_socket {
	char *path;
	int socket_fd;
	uint64_t features;
	const struct rte_vhost2_tgt_ops *ops;

	TAILQ_HEAD(, vhost_user_connection) conn_list;

	struct sockaddr_un un;

	uint64_t flags;

	void (*del_cb_fn)(void *arg);
	void *del_cb_ctx;

	TAILQ_ENTRY(vhost_user_socket) tailq;
};

struct vhost_user_connection {
	struct vhost_user_socket *vsocket;
	struct vhost_dev vdev;

	struct vhost_user_memory *mem;

	int fd;
	struct vhost_user_msg msg;
	rte_atomic32_t op_rc;

	bool removed;

	TAILQ_ENTRY(vhost_user_connection) tailq;
};

struct vhost_user {
	TAILQ_HEAD(, vhost_user_socket) vsockets;
	struct fdset fdset;
};

static void vhost_user_server_new_connection(int fd, void *ctx);
static void vhost_user_destroy_connection(struct vhost_user_connection *conn);
static int create_unix_socket(struct vhost_user_socket *vsocket);
static struct vhost_transport_ops vhost_user_transport;
static struct vhost_dev_ops vhost_dev_user_ops;

static struct vhost_user vhost_user = {
	.vsockets = TAILQ_HEAD_INITIALIZER(vhost_user.vsockets),
};

/* return bytes# of read on success or negative val on failure. */
static int
read_fd_message(int sockfd, char *buf, int buflen, int *fds, int fd_num)
{
	struct iovec iov;
	struct msghdr msgh;
	size_t fdsize = fd_num * sizeof(int);
	char control[CMSG_SPACE(fdsize)];
	struct cmsghdr *cmsg;
	int got_fds = 0;
	int ret;

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
			memcpy(fds, CMSG_DATA(cmsg), got_fds * sizeof(int));
			break;
		}
	}

	/* Clear out unused file descriptors */
	while (got_fds < fd_num)
		fds[got_fds++] = -1;

	return ret;
}

static int
send_fd_message(int sockfd, char *buf, int buflen, int *fds, int fd_num)
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

	return 0;
}

/* return bytes# of read on success or negative val on failure. */
static int
read_vhost_message(struct vhost_user_connection *conn)
{
	struct vhost_user_msg *msg = &conn->msg;
	int ret;

	ret = read_fd_message(conn->fd, (char *)msg,
		offsetof(struct vhost_user_msg, payload.u64),
		msg->fds, VHOST_MEMORY_MAX_NREGIONS);
	if (ret <= 0)
		return ret;

	if (msg->size == 0)
		return ret;

	if (msg->size > sizeof(msg->payload)) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"unsupported msg size: %u, max %zu\n",
			msg->size, sizeof(msg->payload));
		return -1;
	}

	ret = read(conn->fd, &msg->payload, msg->size);
	if (ret <= 0)
		return ret;

	if (ret != (int)msg->size) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"read control message failed\n");
		return -1;
	}

	return ret;
}

static void
_vhost_user_free_vsocket(struct vhost_user_socket *vsocket)
{
	void (*del_cb_fn)(void *arg);
	void *del_cb_ctx;

	del_cb_fn = vsocket->del_cb_fn;
	del_cb_ctx = vsocket->del_cb_ctx;

	close(vsocket->socket_fd);
	free(vsocket->path);
	free(vsocket);

	del_cb_fn(del_cb_ctx);
}

static void
_vhost_user_free_connection(void *arg)
{
	struct vhost_user_connection *conn = arg;
	struct vhost_user_socket *vsocket = conn->vsocket;

	TAILQ_REMOVE(&vsocket->conn_list, conn, tailq);

	close(conn->fd);
	if (conn->mem) {
		rte_free(conn->mem);
		conn->mem = NULL;
	}
	free(conn);

	if (TAILQ_EMPTY(&vsocket->conn_list))
		_vhost_user_free_vsocket(vsocket);
}

static void
_vhost_user_connfd_del_cb(int fd __rte_unused, int rc, void *ctx)
{
	struct vhost_user_connection *conn = ctx;

	assert(rc == 0);
	vhost_dev_destroy(&conn->vdev, _vhost_user_free_connection, conn);
}

static void
vhost_user_destroy_connection(struct vhost_user_connection *conn)
{
	int rc;

	if (conn->removed) {
		/* async removal in progress */
		return;
	}
	conn->removed = true;

	rc = fdset_del(&vhost_user.fdset, conn->fd, _vhost_user_connfd_del_cb);
	if (rc)
		assert(false);
}

static void vhost_user_read_cb(int connfd __rte_unused, void *ctx);
static int vhost_user_handle_msg(struct vhost_dev *vdev,
		struct vhost_user_msg *msg);
static void vhost_user_msg_cpl(struct vhost_dev *vdev,
		struct vhost_user_msg *msg);

static void
_vhost_user_new_connection_cpl(int fd __rte_unused, int rc, void *ctx)
{
	struct vhost_user_connection *conn = ctx;

	if (rc) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to add fd %d into vhost server fdset\n",
			conn->fd);

		vhost_dev_destroy(&conn->vdev,
				_vhost_user_free_connection, conn);
		return;
	}

	RTE_LOG(INFO, VHOST_CONFIG, "new device on %s\n", conn->vsocket->path);
}

static void
_vhost_user_new_connection(struct vhost_dev *vdev, int rc,
		void *ctx __rte_unused)
{
	struct vhost_user_connection *conn = container_of(vdev,
			struct vhost_user_connection, vdev);

	if (rc) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to add vhost user connection with fd %d\n",
			conn->fd);
		conn->removed = true;
		vhost_dev_destroy(vdev, _vhost_user_free_connection, conn);
		return;
	}

	rc = fdset_add(&vhost_user.fdset, conn->fd, vhost_user_read_cb,
			NULL, conn, _vhost_user_new_connection_cpl);
	if (rc < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to add fd %d into vhost server fdset\n",
			conn->fd);
		conn->removed = true;
		vhost_dev_destroy(vdev, _vhost_user_free_connection, conn);
		return;
	}

	return;
}

static void
vhost_user_add_connection(int fd, struct vhost_user_socket *vsocket)
{
	struct vhost_user_connection *conn;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL) {
		close(fd);
		return;
	}

	conn->vsocket = vsocket;
	vhost_dev_init(&conn->vdev, conn->vsocket->features,
			&vhost_user_transport,
			&vhost_dev_user_ops, conn->vsocket->ops);
	conn->fd = fd;
	rte_atomic32_init(&conn->op_rc);

	TAILQ_INSERT_TAIL(&conn->vsocket->conn_list, conn, tailq);

	if (vsocket->ops->device_create) {
		vhost_dev_set_ops_cb(&conn->vdev,
			_vhost_user_new_connection, NULL);
		vsocket->ops->device_create(&conn->vdev.dev);
		return;
	}

	_vhost_user_new_connection(&conn->vdev, 0, NULL);
}

/* call back when there is new vhost-user connection from client  */
static void
vhost_user_server_new_connection(int fd, void *ctx)
{
	struct vhost_user_socket *vsocket = ctx;

	fd = accept(fd, NULL, NULL);
	if (fd < 0)
		return;

	RTE_LOG(INFO, VHOST_CONFIG, "new vhost user connection is %d\n", fd);
	vhost_user_add_connection(fd, vsocket);
}

static int
create_unix_socket(struct vhost_user_socket *vsocket)
{
	struct sockaddr_un *un = &vsocket->un;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;

	memset(un, 0, sizeof(*un));
	un->sun_family = AF_UNIX;
	strncpy(un->sun_path, vsocket->path, sizeof(un->sun_path));
	un->sun_path[sizeof(un->sun_path) - 1] = '\0';

	vsocket->socket_fd = fd;
	return 0;
}

static void
_vhost_user_start_server_cpl(int fd, int rc, void *ctx)
{
	struct vhost_user_socket *vsocket = ctx;

	if (rc) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to add listen fd %d to vhost server fdset\n",
			fd);
		close(fd);
		vsocket->socket_fd = -1;
		/* there's nothing more we can do at this point */
	}
}

static int
vhost_user_start_server(struct vhost_user_socket *vsocket)
{
	int ret;
	int fd = vsocket->socket_fd;
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
	ret = bind(fd, (struct sockaddr *)&vsocket->un, sizeof(vsocket->un));
	if (ret < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to bind to %s: %s; remove it and try again\n",
			path, strerror(errno));
		goto err;
	}
	RTE_LOG(INFO, VHOST_CONFIG, "bind to %s\n", path);

	ret = listen(fd, MAX_SOCKET_BACKLOG);
	if (ret < 0)
		goto err;

	ret = fdset_add(&vhost_user.fdset, fd, vhost_user_server_new_connection,
		  NULL, vsocket, _vhost_user_start_server_cpl);
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

static int
vhost_user_tgt_register(const char *path, uint64_t flags,
		void *ctx __rte_unused,
		const struct rte_vhost2_tgt_ops *tgt_ops,
		uint64_t features)
{
	int rc;
	struct vhost_user_socket *vsocket;

	vsocket = calloc(1, sizeof(struct vhost_user_socket));
	if (!vsocket) {
		RTE_LOG(ERR, VHOST_CONFIG, "calloc failed\n");
		return -ENOMEM;
	}

	vsocket->path = strdup(path);
	if (vsocket->path == NULL) {
		RTE_LOG(ERR, VHOST_CONFIG, "strdup failed\n");
		free(vsocket);
		return -ENOMEM;
	}

	rc = create_unix_socket(vsocket);
	if (rc < 0) {
		free(vsocket->path);
		free(vsocket);
	}

	vsocket->flags = flags;
	vsocket->ops = tgt_ops;
	vsocket->features = features;
	TAILQ_INIT(&vsocket->conn_list);

	TAILQ_INSERT_TAIL(&vhost_user.vsockets, vsocket, tailq);

	rc = vhost_user_start_server(vsocket);
	if (rc) {
		free(vsocket->path);
		free(vsocket);
	}

	return rc;
}

static void
_vhost_user_vsocketfd_del_cb(int fd __rte_unused, int rc, void *ctx)
{
	struct vhost_user_socket *vsocket = ctx;
	struct vhost_user_connection *conn;

	if (rc)
		assert(false);

	if (TAILQ_EMPTY(&vsocket->conn_list)) {
		_vhost_user_free_vsocket(vsocket);
		return;
	}

	/* the last destroyed connection will call `vsocket->del_cb_fn` */
	TAILQ_FOREACH(conn, &vsocket->conn_list, tailq)
		vhost_user_destroy_connection(conn);
}

static int
vhost_user_tgt_unregister(const char *path,
			  void (*cb_fn)(void *arg), void *cb_ctx)
{
	struct vhost_user_socket *vsocket;
	int rc;

	TAILQ_FOREACH(vsocket, &vhost_user.vsockets, tailq) {
		if (strcmp(path, vsocket->path) == 0)
			break;
	}

	if (vsocket == NULL)
		return -ENODEV;

	vsocket->del_cb_fn = cb_fn;
	vsocket->del_cb_ctx = cb_ctx;

	rc = fdset_del(&vhost_user.fdset, vsocket->socket_fd,
			_vhost_user_vsocketfd_del_cb);
	if (rc)
		assert(false);

	return rc;
}

static void
_vhost_user_dev_op_complete(int fd __rte_unused, void *ctx)
{
	struct vhost_user_connection *conn = ctx;

	vhost_dev_ops_complete(&conn->vdev, rte_atomic32_read(&conn->op_rc));
}

static void
vhost_user_dev_op_complete(struct rte_vhost2_dev *_vdev, int rc)
{
	struct vhost_dev *vdev = container_of(_vdev,
			struct vhost_dev, dev);
	struct vhost_user_connection *conn = container_of(vdev,
			struct vhost_user_connection, vdev);

	rte_atomic32_set(&conn->op_rc, rc);
	fdset_notify(&vhost_user.fdset, _vhost_user_dev_op_complete, conn);
}

static void
vhost_user_dev_call(struct rte_vhost2_dev *vdev __rte_unused,
		struct rte_vhost2_vq *_vq)
{
	struct vhost_vq *vq = container_of(_vq,
			struct vhost_vq, q);

	eventfd_write(vq->callfd, (eventfd_t)1);
}


static bool
vhost_user_memory_changed(struct vhost_user_msg_memory *new,
		     struct vhost_user_memory *old)
{
	uint32_t i;

	if (new->nregions != old->nregions)
		return true;

	for (i = 0; i < new->nregions; ++i) {
		struct vhost_user_msg_mem_region *new_r = &new->regions[i];
		struct vhost_user_mem_region *old_r = &old->regions[i];

		if (new_r->guest_phys_addr != old_r->guest_phys_addr)
			return true;
		if (new_r->memory_size != old_r->size)
			return true;
		if (new_r->userspace_addr != old_r->guest_user_addr)
			return true;
	}

	return false;
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
vhost_user_set_mem_table(struct vhost_dev *vdev, struct vhost_user_msg *msg)
{
	struct vhost_user_msg_memory memory = msg->payload.memory;
	struct vhost_user_connection *conn = container_of(vdev,
			struct vhost_user_connection, vdev);
	struct vhost_user_memory *mem;
	struct rte_vhost2_memory *vhost_mem;
	struct vhost_user_mem_region *reg;
	struct rte_vhost2_mem_region *vhost_reg;
	void *mmap_addr;
	uint64_t mmap_size;
	uint64_t mmap_offset;
	uint64_t alignment;
	uint32_t i;
	int fd;

	if (memory.nregions > VHOST_MEMORY_MAX_NREGIONS) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"too many memory regions (%u)\n", memory.nregions);
		return -1;
	}

	if (conn->mem && !vhost_user_memory_changed(&memory, conn->mem)) {
		for (i = 0; i < memory.nregions; i++)
			close(msg->fds[i]);

		return 0;
	}

	if (conn->mem) {
		assert(vdev->dev.mem);
		rte_free(vdev->dev.mem);
		vdev->dev.mem = NULL;

		rte_free(conn->mem);
		conn->mem = NULL;

	}

	mem = rte_zmalloc("vhost-user-mem-table",
		sizeof(struct vhost_user_memory) +
		sizeof(struct vhost_user_mem_region) * memory.nregions, 0);
	if (mem == NULL) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to allocate memory for vhost user mem\n");
		return -1;
	}

	vhost_mem = rte_zmalloc("vhost-mem-table",
		sizeof(struct rte_vhost2_memory) +
		sizeof(struct rte_vhost2_mem_region) * memory.nregions, 0);
	if (mem == NULL) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"failed to allocate memory for vhost mem\n");
		rte_free(mem);
		return -1;
	}

	mem->nregions = memory.nregions;
	vhost_mem->nregions = mem->nregions;

	for (i = 0; i < memory.nregions; i++) {
		fd  = msg->fds[i];
		reg = &mem->regions[i];
		vhost_reg = &vhost_mem->regions[i];

		reg->guest_phys_addr = memory.regions[i].guest_phys_addr;
		reg->guest_user_addr = memory.regions[i].userspace_addr;
		reg->size            = memory.regions[i].memory_size;
		reg->fd              = fd;

		mmap_offset = memory.regions[i].mmap_offset;

		/* Check for memory_size + mmap_offset overflow */
		if (mmap_offset >= -reg->size) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"mmap_offset and memory_size overflow\n");
			goto err_free;
		}

		mmap_size = reg->size + mmap_offset;

		/* mmap() without flag of MAP_ANONYMOUS, should be called
		 * with length argument aligned with hugepagesz at older
		 * longterm version Linux, like 2.6.32 and 3.2.72, or
		 * mmap() will fail with EINVAL.
		 *
		 * to avoid failure, make sure in caller to keep length
		 * aligned.
		 */
		alignment = get_blk_size(fd);
		if (alignment == (uint64_t)-1) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"couldn't get hugepage size through fstat\n");
			goto err_free;
		}
		mmap_size = RTE_ALIGN_CEIL(mmap_size, alignment);

		mmap_addr = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_POPULATE, fd, 0);

		if (mmap_addr == MAP_FAILED) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"mmap region %u failed.\n", i);
			goto err_free;
		}

		reg->mmap_addr = mmap_addr;
		reg->mmap_size = mmap_size;
		reg->host_user_addr = (uint64_t)(uintptr_t)mmap_addr +
				      mmap_offset;

		vhost_reg->guest_phys_addr = reg->guest_phys_addr;
		vhost_reg->guest_user_addr = reg->guest_user_addr;
		vhost_reg->host_user_addr = reg->host_user_addr;
		vhost_reg->size = reg->size;
	}

	conn->mem = mem;
	vdev->dev.mem = vhost_mem;

	return 0;

err_free:
	rte_free(mem);
	rte_free(vhost_mem);
	return -1;
}

static int
vhost_user_handle_msg(struct vhost_dev *vdev, struct vhost_user_msg *msg)
{
	switch (msg->type) {
	case VHOST_USER_SET_MEM_TABLE:
		return vhost_user_set_mem_table(vdev, msg);
	default:
		return 1;
	}
}

static void
_vhost_user_device_init_cpl(struct vhost_dev *vdev __rte_unused,
		int rc, void *ctx)
{
	struct vhost_user_connection *conn = ctx;

	if (rc) {
		vhost_user_destroy_connection(conn);
		return;
	}

	fdset_enable(&vhost_user.fdset, conn->fd, true);
}

static void
vhost_user_msg_cpl(struct vhost_dev *vdev,
		struct vhost_user_msg *msg __rte_unused)
{
	struct vhost_user_connection *conn = container_of(vdev,
			struct vhost_user_connection, vdev);

	switch (msg->type) {
	case VHOST_USER_SET_MEM_TABLE:
		if (conn->mem && vdev->ops->device_init) {
			vhost_dev_set_ops_cb(vdev,
					_vhost_user_device_init_cpl, conn);
			vdev->ops->device_init(&vdev->dev);
			return;
		}
		break;
	default:
		break;
	}

	fdset_enable(&vhost_user.fdset, conn->fd, true);
}

static int
vhost_user_send_reply(struct vhost_dev *vdev, struct vhost_user_msg *msg)
{
	struct vhost_user_connection *conn = container_of(vdev,
			struct vhost_user_connection, vdev);

	return send_fd_message(conn->fd, (char *)msg,
			offsetof(struct vhost_user_msg, payload.u64)
			+ msg->size, NULL, 0);
}

static void
vhost_user_read_cb(int connfd __rte_unused, void *ctx)
{
	struct vhost_user_connection *conn = ctx;
	int ret;

	fdset_enable(&vhost_user.fdset, conn->fd, false);
	ret = read_vhost_message(conn);
	if (ret < 0) {
		vhost_user_destroy_connection(conn);
		return;
	}

	ret = vhost_dev_msg_handler(&conn->vdev, &conn->msg);
	if (ret < 0) {
		vhost_user_destroy_connection(conn);
		return;
	}
}

static struct vhost_dev_ops vhost_dev_user_ops = {
	.handle_msg = vhost_user_handle_msg,
	.msg_cpl = vhost_user_msg_cpl,
	.send_reply = vhost_user_send_reply,
};

static struct vhost_transport_ops vhost_user_transport = {
	.type = "vhost-user",
	.tgt_register = vhost_user_tgt_register,
	.tgt_unregister = vhost_user_tgt_unregister,
	.dev_op_cpl = vhost_user_dev_op_complete,
	.dev_call = vhost_user_dev_call,
};

VHOST_TRANSPORT_REGISTER(vhost_user_transport);
