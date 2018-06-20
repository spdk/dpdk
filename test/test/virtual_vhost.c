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

static int g_vid;

struct virtual_vhost *
virtual_vhost_create(const char *path)
{
	struct virtual_vhost *vhost;
	char shm_path[1024];
	int fd;
	int q;

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
	long pg_size = sysconf(_SC_PAGE_SIZE);
	printf("[MASTER] pg_size = %ld\n", pg_size);

	vhost->memory_size = 1024 * 1024;
	sprintf(shm_path, "memory_region_%d-%d.pid%d", g_vid, 0, getpid());
	vhost->shmfd = shm_open(shm_path, O_CREAT|O_RDWR, 0);
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

	/* For now initialize only one queue */
	vhost->vring_num = 1;
	for (q = 0; q < vhost->vring_num; q++) {
		/* Allocate virtual queue */
		/* FIXIT -- add padding */
		vhost->vring[q].size = 32;
		vhost->vring[q].desc = (struct vring_desc *)vhost->guest_phys_addr;
		vhost->vring[q].avail = (struct vring_avail *)(vhost->vring[q].desc + 16 * vhost->vring[q].size);
		vhost->vring[q].used = (struct vring_used *)(vhost->vring[q].avail + 6 + 2 * vhost->vring[q].size);

		vhost->vring[q].callfd = eventfd(0, 0);
		if (vhost->vring[q].callfd < 0) {
			/* FIXIT: cleanup and free vhost */
			printf("[MASTER] Booo!\n");
			return NULL;
		}
		vhost->vring[q].kickfd = eventfd(0, 0);
		if (vhost->vring[q].kickfd < 0) {
			/* FIXIT: cleanup and free vhost */
			printf("[MASTER] Booo!\n");
			return NULL;
		}
	}

	g_vid++;

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

int virtual_vhost_notify(int fd)
{
	ssize_t n;
	unsigned long long v = 1;
	n = write(fd, &v, sizeof(v));
	if (n != sizeof(v))
		return -1;
	return 0;
}

int virtual_vhost_wait(int fd)
{
	ssize_t n;
	unsigned long long v = 1;
	n = read(fd, &v, sizeof(v));
	if (n != sizeof(v))
		return -1;
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
	if (ret <= 0) {
		printf("No response\n");
		return ret;
	}

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
virtual_vhost_send_message(struct virtual_vhost *vhost, struct VhostUserMsg *msg, int num_fds) {
	msg->flags = VHOST_USER_VERSION;
	return send_fd_message(vhost->sockfd, (char *)msg,
		VHOST_USER_HDR_SIZE + msg->size, msg->fds, num_fds);
}
