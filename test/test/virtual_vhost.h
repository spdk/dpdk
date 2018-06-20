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

enum virtual_vhost_state {
	VHOST_STATE_DISCONNECTED = 0,
	VHOST_STATE_CREATED,
	VHOST_STATE_CONNECTING,
	VHOST_STATE_CONNECTED,
	VHOST_STATE_READY
};

struct virtual_vhost {
	enum virtual_vhost_state state;

	struct sockaddr_un saddr;
	socklen_t saddrlen;
	char path[PATH_MAX];

	int sockfd;

	/* One memory region for now */
	int shmfd;
	uint64_t guest_phys_addr;
	uint64_t memory_size;
	uint64_t userspace_addr;

	uint16_t vring_num;
	struct rte_vhost_vring vring[1];
};

struct virtual_vhost *virtual_vhost_create(const char *path);
int virtual_vhost_connect(struct virtual_vhost *vhost);
int virtual_vhost_disconnect(struct virtual_vhost *vhost);

enum virtual_vhost_state virtual_vhost_state_get(struct virtual_vhost *vhost);
enum virtual_vhost_state virtual_vhost_state_set(struct virtual_vhost *vhost,
		enum virtual_vhost_state state);
enum virtual_vhost_state virtual_vhost_state_wait(struct virtual_vhost *vhost,
		enum virtual_vhost_state state);

struct virtual_vhost *virtual_vhost_get(int vid);
struct virtual_vhost *virtual_vhost_get_by_path(char *path);

ssize_t virtual_vhost_recv_message(struct virtual_vhost *vhost, struct VhostUserMsg *msg);
ssize_t virtual_vhost_send_message(struct virtual_vhost *vhost, struct VhostUserMsg *msg, int num_fds);

int virtual_vhost_notify(int fd);
int virtual_vhost_wait(int fd);

#ifdef __cplusplus
}
#endif

#endif /* __VIRTUAL_VHOST_H_ */
