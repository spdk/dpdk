/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#ifndef __VIRTUAL_VHOST_H_
#define __VIRTUAL_VHOST_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include "vhost_user.h"

struct virtual_vhost {
	struct sockaddr_un saddr;
	socklen_t saddrlen;
	char *path;

	int sockfd;

	/* One memory region for now */
	int shmfd;
	uint64_t guest_phys_addr;
	uint64_t memory_size;
	uint64_t userspace_addr;

	/* One virtqueue for now */
	struct vring_desc	*desc;
	struct vring_avail	*avail;
	struct vring_used	*used;

};

struct virtual_vhost *virtual_vhost_create(const char *path);
int virtual_vhost_connect(struct virtual_vhost *vhost);
ssize_t virtual_vhost_recv_message(struct virtual_vhost *vhost, struct VhostUserMsg *msg);
ssize_t virtual_vhost_send_message(struct virtual_vhost *vhost, struct VhostUserMsg *msg);


#ifdef __cplusplus
}
#endif

#endif /* __VIRTUAL_VHOST_H_ */
