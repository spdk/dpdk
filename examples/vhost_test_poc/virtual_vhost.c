/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <rte_malloc.h>

#include "virtual_vhost.h"

static uint64_t
get_blk_size(int fd)
{
	struct stat stat;
	int ret;

	ret = fstat(fd, &stat);
	return ret == -1 ? (uint64_t)-1 : (uint64_t)stat.st_blksize;
}

struct virtual_vhost *
virtual_vhost_create(const char *path)
{
	struct virtual_vhost *vhost;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0)
		return NULL;

	vhost = calloc(1, sizeof(struct virtual_vhost));
	vhost->sockfd = fd;

	memset(&vhost->saddr, 0, sizeof(vhost->saddr));
	vhost->saddr.sun_family = AF_UNIX;
	strncpy(vhost->saddr.sun_path, path, sizeof(vhost->saddr.sun_path));
	vhost->saddr.sun_path[sizeof(vhost->saddr.sun_path) - 1] = '\0';

	vhost->path = strdup(path);
	vhost->saddrlen = strlen(path) + sizeof(struct sockaddr);

	/* Prepare memory region */
	//long pg_size = sysconf(_SC_PAGE_SIZE);

	vhost->memory_size = 1024 * 1024;
	vhost->shmfd = shm_open("memory_region", O_CREAT|O_RDWR, 0);
	if (ftruncate(vhost->shmfd, vhost->memory_size) != 0) {
		/* FIXIT: cleanup and free vhost */
		printf("[MASTER] Booo!\n");
		return NULL;
	}

	vhost->userspace_addr = (uint64_t)mmap(0, vhost->memory_size /* pg_size */, PROT_WRITE, MAP_SHARED, vhost->shmfd, 0);
	if (vhost->userspace_addr == 0) {
		/* FIXIT: cleanup and free vhost */
		printf("[MASTER] Booo!\n");
		return NULL;
	}

	vhost->guest_phys_addr = vhost->userspace_addr;
	//vhost->guest_phys_addr = (uint64_t)rte_mem_virt2phy((void *)vhost->userspace_addr);

	printf("[MASTER] blksize = %" PRIu64 "\n", get_blk_size(vhost->shmfd));

	/* Allocate virtual queue */
	/* FIXIT! */
	int queue_size = 32;
	vhost->desc = rte_malloc("vhost_desc", 16 * queue_size, 16);
	vhost->avail = rte_malloc("vhost_avail", 6 + 2 * queue_size, 2);
	vhost->used = rte_malloc("vhost_used", 6 + 4 * queue_size, 4);

	return vhost;
}

int
virtual_vhost_connect(struct virtual_vhost *vhost)
{
	/* Create client socket -- we suppose that vhost slave is running as
	 * a server
	 */

	int conn;

	conn = connect(vhost->sockfd, &vhost->saddr, vhost->saddrlen);
	if (conn != 0) {
		//printf("Cannot connect to the socket %s.\n", vhost->path);
		return -1;
	}

	printf("virtual_vhost connected\n");

	return 0;
}

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
		return ret;
	}

	if (msgh.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
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
		return ret;
	}

	return ret;
}

ssize_t
virtual_vhost_recv_message(struct virtual_vhost *vhost, struct VhostUserMsg *msg) {
	int ret;

	ret = read_fd_message(vhost->sockfd, (char *)msg, VHOST_USER_HDR_SIZE,
		msg->fds, VHOST_MEMORY_MAX_NREGIONS);
	if (ret <= 0)
		return ret;

	if (msg && msg->size) {
		if (msg->size > sizeof(msg->payload)) {
			return -1;
		}
		ret = read(vhost->sockfd, &msg->payload, msg->size);
		if (ret <= 0)
			return ret;
		if (ret != (int)msg->size) {
			return -1;
		}
	}

	return ret;
}

ssize_t
virtual_vhost_send_message(struct virtual_vhost *vhost, struct VhostUserMsg *msg) {
	return send_fd_message(vhost->sockfd, (char *)msg,
		VHOST_USER_HDR_SIZE + msg->size, &vhost->shmfd, 1);
}
