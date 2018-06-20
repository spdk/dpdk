/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <unistd.h>

#include "test.h"
#include "vhost_user.h"
#include "virtual_vhost.h"

#define TEST_SOCKET_FILE			"/tmp/vhost_test1.socket"

static int
new_device(int vid)
{
	char path[PATH_MAX];
	int ret;
	struct rte_vhost_vring vring;

	ret = rte_vhost_get_ifname(vid, path, PATH_MAX);
	if (ret) {
		RTE_LOG(ERR, USER1, "Cannot find matched socket\n");
		return ret;
	}

	printf("Path = %s\n", path);

	/* Use only one socket for now */
	if (strcmp(path, TEST_SOCKET_FILE) != 0) {
		RTE_LOG(ERR, USER1, "Cannot find recorded socket\n");
		return -ENOENT;
	}

	ret = rte_vhost_get_vhost_vring(vid, 0, &vring);
	//assert(ret == 0);

	RTE_LOG(INFO, USER1, "New Vhost-test Device %s, Device ID %d\n", path,
			vid);

	return 0;
}

static void
destroy_device(int vid)
{
	if (vid != 0) {
		RTE_LOG(ERR, USER1, "Cannot find socket file from list\n");
		return;
	}

	RTE_LOG(INFO, USER1, "Vhost Test Device %i Removed\n", vid);
}

static const struct vhost_device_ops virtio_test_device_ops = {
	.new_device =  new_device,
	.destroy_device = destroy_device,
};

static int
vhost_test_master(__rte_unused void *arg)
{
	struct virtual_vhost *vhost = NULL;
	ssize_t n;
	//struct rte_vhost_vring vring;

	vhost = virtual_vhost_create(TEST_SOCKET_FILE);
	if (vhost == NULL) {
		printf("Booooo!!\n");
		return -1;
	}

	//FIXIT: wait until vhost slave finishes initialization except polling
	//       socket for connection
	while (virtual_vhost_connect(vhost) != 0);

	struct VhostUserMsg msg;

	msg.request.master = VHOST_USER_GET_FEATURES;
	msg.size = 0;

	virtual_vhost_send_message(vhost, &msg, 0);
	n = virtual_vhost_recv_message(vhost, &msg);

	printf("Received %ld bytes (Message size %d)\n", n, msg.size);
	printf("Features: %" PRIx64 "\n", msg.payload.u64);

	msg.request.master = VHOST_USER_GET_PROTOCOL_FEATURES;
	msg.size = 0;

	virtual_vhost_send_message(vhost, &msg, 0);
	n = virtual_vhost_recv_message(vhost, &msg);

	printf("Received %ld bytes (Message size %d)\n", n, msg.size);
	printf("Features: %" PRIx64 "\n", msg.payload.u64);

	/* Set protocol features */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_PROTOCOL_FEATURES;
	msg.size = sizeof(msg.payload.u64);
	msg.payload.u64 = 0;
	virtual_vhost_send_message(vhost, &msg, 0);

	/* Get queue num */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_GET_QUEUE_NUM;
	msg.size = sizeof(msg.payload.u64);
	msg.payload.u64 = 0;
	virtual_vhost_send_message(vhost, &msg, 0);
	n = virtual_vhost_recv_message(vhost, &msg);

	printf("Received %ld bytes (Message size %d)\n", n, msg.size);
	printf("Queue num: %" PRIx64 "\n", msg.payload.u64);

	/* Set owner */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_OWNER;
	msg.size = 0;
	virtual_vhost_send_message(vhost, &msg, 0);

	/* Get features */
	msg.request.master = VHOST_USER_GET_FEATURES;
	msg.size = 0;

	virtual_vhost_send_message(vhost, &msg, 0);
	n = virtual_vhost_recv_message(vhost, &msg);

	printf("Received %ld bytes (Message size %d)\n", n, msg.size);
	printf("Features: %" PRIx64 "\n", msg.payload.u64);

	/* Set callfd */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_VRING_CALL;
	msg.size = sizeof(msg.payload.u64);
	msg.payload.u64 = 0;
	msg.fds[0] = vhost->vring[0].callfd;
	virtual_vhost_send_message(vhost, &msg, 1);

	/* Set features */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_FEATURES;
	msg.size = sizeof(msg.payload.u64);
	msg.payload.u64 = 0;
	virtual_vhost_send_message(vhost, &msg, 0);

	/* Set memtable (one region) */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_MEM_TABLE;
	msg.size = sizeof(msg.payload.memory) + sizeof(msg.fds[0]);
	msg.payload.memory.nregions = 1;
	msg.payload.memory.padding = 0;
	msg.payload.memory.regions[0].guest_phys_addr = vhost->guest_phys_addr;
	msg.payload.memory.regions[0].memory_size = vhost->memory_size;
	msg.payload.memory.regions[0].mmap_offset = 0; /* FIXIT: change it! */
	msg.payload.memory.regions[0].userspace_addr = vhost->userspace_addr;
	msg.fds[0] = vhost->shmfd;
	virtual_vhost_send_message(vhost, &msg, 1);

	/* Set vring num */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_VRING_NUM;
	msg.size = sizeof(msg.payload.u64);
	msg.payload.u64 = 1;
	virtual_vhost_send_message(vhost, &msg, 0);

	/* Set vring base */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_VRING_BASE;
	msg.size = sizeof(msg.payload.state);
	msg.payload.state.index = 0;
	msg.payload.state.num = 0;
	virtual_vhost_send_message(vhost, &msg, 0);

	/* Set vring addr */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_VRING_ADDR;
	msg.size = sizeof(msg.payload.addr);
	msg.payload.addr.index = 0;
	msg.payload.addr.avail_user_addr = (uint64_t)vhost->vring[0].avail;
	msg.payload.addr.desc_user_addr = (uint64_t)vhost->vring[0].desc;
	msg.payload.addr.used_user_addr = (uint64_t)vhost->vring[0].used;
	virtual_vhost_send_message(vhost, &msg, 0);

	/* Set kickfd */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_VRING_KICK;
	msg.size = sizeof(msg.payload.u64);
	msg.payload.u64 = 0;
	msg.fds[0] = vhost->vring[0].kickfd;
	virtual_vhost_send_message(vhost, &msg, 1);

	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_VRING_ENABLE;
	msg.payload.state.index = 0;
	msg.size = sizeof(msg.payload.state);
	virtual_vhost_send_message(vhost, &msg, 0);

	/* Vhost should be initialized here */

	/* TODO: Wait until vhost starts */
#if 0
	/* We should have one vring here (for now) */
	uint16_t vring_num = rte_vhost_get_vring_num(0);
	if (vring_num != 1) {
		printf("[SLAVE] vring_num != 1\n");
		return -1;
	}

	/* Only vid==0 */
	int ret = rte_vhost_get_vhost_vring(0, 0, &vring);
	if (ret == 0) {

	}
#endif
	return 0;
}

static void
unregister_drivers(__rte_unused int socket_num)
{
	int ret;

	ret = rte_vhost_driver_unregister(TEST_SOCKET_FILE);
	if (ret != 0)
		RTE_LOG(ERR, USER1,
			"Fail to unregister vhost driver for %s.\n",
			TEST_SOCKET_FILE);
}

static int
test_vhost(void)
{
	int ret = 0;

	unlink(TEST_SOCKET_FILE);


	if (rte_vhost_driver_register(TEST_SOCKET_FILE,
			RTE_VHOST_USER_DEQUEUE_ZERO_COPY) < 0) {
		RTE_LOG(ERR, USER1, "socket %s already exists\n",
				TEST_SOCKET_FILE);
		goto end;
	}

	rte_vhost_driver_callback_register(TEST_SOCKET_FILE,
			&virtio_test_device_ops);

	if (rte_vhost_driver_start(TEST_SOCKET_FILE) < 0) {
		RTE_LOG(ERR, USER1, "failed to start vhost driver.\n");
		goto end;
	}

	vhost_test_master(NULL);

end:
	//app_free_resources();
	unregister_drivers(0);

	return ret;
}

REGISTER_TEST_COMMAND(vhost_autotest, test_vhost);
