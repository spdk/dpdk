/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <unistd.h>

#include "test.h"
#include "vhost_user.h"
#include "virtual_vhost.h"

#define TEST_SOCKET_FILE			"/tmp/vhost_test1.socket"

static int
vhost_test_master(__rte_unused void *arg)
{
	struct VhostUserMsg msg;
	struct virtual_vhost *vhost = NULL;
	ssize_t n;
	int q;

	vhost = virtual_vhost_create(TEST_SOCKET_FILE);
	if (vhost == NULL) {
		RTE_LOG(ERR, USER1, "Cannot initialize virtual vhost on '%s'\n",
				TEST_SOCKET_FILE);
		return TEST_FAILED;
	}

	virtual_vhost_connect(vhost);

	if (virtual_vhost_state_wait(vhost, VHOST_STATE_CONNECTED)
			!= VHOST_STATE_CONNECTED) {
		/**/
		RTE_LOG(ERR, USER1, "Cannot connect to the virtual vhost on '%s'\n",
				TEST_SOCKET_FILE);
		return TEST_FAILED;
	}

	msg.request.master = VHOST_USER_GET_FEATURES;
	msg.size = 0;

	if (virtual_vhost_send_message(vhost, &msg, 0) < 0) {
		printf("Cannot send message\n");
	}
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
	msg.payload.u64 = (1ULL << VHOST_USER_F_PROTOCOL_FEATURES);
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

	for (q = 0; q < vhost->vring_num; q++) {
		/* Set callfd */
		memset(&msg, 0, sizeof(msg));
		msg.request.master = VHOST_USER_SET_VRING_CALL;
		msg.size = sizeof(msg.payload.u64);
		msg.payload.u64 = q;
		msg.fds[0] = vhost->vring[0].callfd;
		virtual_vhost_send_message(vhost, &msg, 1);
	}

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
#if 0
	/* Set vring num */
	memset(&msg, 0, sizeof(msg));
	msg.request.master = VHOST_USER_SET_VRING_NUM;
	msg.size = sizeof(msg.payload.u64);
	msg.payload.u64 = vhost->vring_num;
	virtual_vhost_send_message(vhost, &msg, 0);
#endif
	for (q = 0; q < vhost->vring_num; q++) {
		/* Set vring base */
		printf("Set vring base\n");
		memset(&msg, 0, sizeof(msg));
		msg.request.master = VHOST_USER_SET_VRING_BASE;
		msg.size = sizeof(msg.payload.state);
		msg.payload.state.index = q;
		msg.payload.state.num = 0;
		virtual_vhost_send_message(vhost, &msg, 0);

		/* Set vring addr */
		memset(&msg, 0, sizeof(msg));
		msg.request.master = VHOST_USER_SET_VRING_ADDR;
		msg.size = sizeof(msg.payload.addr);
		msg.payload.addr.index = q;
		msg.payload.addr.avail_user_addr = (uint64_t)vhost->vring[0].avail;
		msg.payload.addr.desc_user_addr = (uint64_t)vhost->vring[0].desc;
		msg.payload.addr.used_user_addr = (uint64_t)vhost->vring[0].used;
		virtual_vhost_send_message(vhost, &msg, 0);

		/* Set kickfd */
		memset(&msg, 0, sizeof(msg));
		msg.request.master = VHOST_USER_SET_VRING_KICK;
		msg.size = sizeof(msg.payload.u64);
		msg.payload.u64 = q;
		msg.fds[0] = vhost->vring[0].kickfd;
		virtual_vhost_send_message(vhost, &msg, 1);
#if 0
		memset(&msg, 0, sizeof(msg));
		msg.request.master = VHOST_USER_SET_VRING_ENABLE;
		msg.payload.state.num = 1;
		msg.payload.state.index = q;
		msg.size = sizeof(msg.payload.state);
		virtual_vhost_send_message(vhost, &msg, 0);
#endif
	}

	/* Vhost should be initialized here */
	if (virtual_vhost_state_wait(vhost, VHOST_STATE_READY) != VHOST_STATE_READY) {
		RTE_LOG(ERR, USER1, "Cannot initialize virtual vhost on '%s'\n",
				TEST_SOCKET_FILE);
		return TEST_FAILED;
	}

	/* Disconnect vhost */
	virtual_vhost_disconnect(vhost);

	if (virtual_vhost_state_wait(vhost, VHOST_STATE_DISCONNECTED)
			!= VHOST_STATE_DISCONNECTED) {
		RTE_LOG(ERR, USER1, "Cannot disconnect virtual vhost on '%s'\n",
				TEST_SOCKET_FILE);
		return TEST_FAILED;
	}

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

/*****************************************************************************
 * vhost
 */
static int
new_device(int vid)
{
	char path[PATH_MAX];
	int ret;
	struct rte_vhost_vring vring;
	struct virtual_vhost *vhost;

	printf("New device\n");

	ret = rte_vhost_get_ifname(vid, path, PATH_MAX);
	if (ret) {
		RTE_LOG(ERR, USER1, "Cannot find matched socket\n");
		return ret;
	}

	vhost = virtual_vhost_get_by_path(path);
	if (vhost == NULL) {
		RTE_LOG(ERR, USER1, "Cannot find recorded socket\n");
		return -ENOENT;
	}

	ret = rte_vhost_get_vhost_vring(vid, 0, &vring);
	//assert(ret == 0);

	RTE_LOG(INFO, USER1, "New Vhost-test Device %s, Device ID %d\n", path,
			vid);

	virtual_vhost_state_set(vhost, VHOST_STATE_READY);

	return 0;
}

static void
destroy_device(int vid)
{
	struct virtual_vhost *vhost;
	char path[PATH_MAX];
	int ret;

	printf("Destroy device\n");

	if (vid != 0) {
		RTE_LOG(ERR, USER1, "Cannot find socket file from list\n");
		return;
	}

	ret = rte_vhost_get_ifname(vid, path, PATH_MAX);
	if (ret) {
		RTE_LOG(ERR, USER1, "Cannot find matched socket\n");
		return;
	}

	vhost = virtual_vhost_get_by_path(path);
	if (vhost == NULL) {
		RTE_LOG(ERR, USER1, "Cannot find recorded socket\n");
		return;
	}

	RTE_LOG(INFO, USER1, "Vhost Test Device %i Removed\n", vid);
}

static int
vring_state_changed(int vid, uint16_t queue_id, int enable)
{
	printf("vring_state_changed of %d, queue %d, enable=%d\n", vid, queue_id,
			enable);
	return 0;
}

static int
features_changed(int vid, uint64_t features) {
	printf("features_changed of %d to %" PRIx64 "\n", vid, features);
	return 0;
}

static int
new_connection(int vid) {
	struct virtual_vhost *vhost;
	char path[PATH_MAX];
	int ret;

	ret = rte_vhost_get_ifname(vid, path, PATH_MAX);
	if (ret) {
		RTE_LOG(ERR, USER1, "Cannot find matched socket\n");
		return ret;
	}

	vhost = virtual_vhost_get_by_path(path);
	if (vhost == NULL) {
		RTE_LOG(ERR, USER1, "Cannot find recorded socket\n");
		return -ENOENT;
	}

	if (virtual_vhost_state_wait(vhost, VHOST_STATE_CONNECTING)
			!= VHOST_STATE_CONNECTING) {
		RTE_LOG(ERR, USER1, "Cannot make new connection virtual vhost on '%s'\n",
				path);
		return TEST_FAILED;
	}

	virtual_vhost_state_set(vhost, VHOST_STATE_CONNECTED);
	return 0;
}

static void
destroy_connection(int vid) {
	struct virtual_vhost *vhost;
	char path[PATH_MAX];
	int ret;

	ret = rte_vhost_get_ifname(vid, path, PATH_MAX);
	if (ret) {
		RTE_LOG(ERR, USER1, "Cannot find matched socket\n");
		return;
	}

	vhost = virtual_vhost_get_by_path(path);
	if (vhost == NULL) {
		RTE_LOG(ERR, USER1, "Cannot find recorded socket\n");
		return;
	}
	virtual_vhost_state_set(vhost, VHOST_STATE_DISCONNECTED);
}

static const struct vhost_device_ops virtio_test_device_ops = {
	.new_device =  new_device,
	.destroy_device = destroy_device,

	.vring_state_changed = vring_state_changed,
	.features_changed = features_changed,

	.new_connection = new_connection,
	.destroy_connection = destroy_connection,

};

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

	if (rte_vhost_driver_set_features(TEST_SOCKET_FILE, 0 /* (1ULL << VHOST_USER_F_PROTOCOL_FEATURES) */) ||
		    rte_vhost_driver_disable_features(TEST_SOCKET_FILE, 0)) {
			rte_vhost_driver_unregister(TEST_SOCKET_FILE);
			ret = -EIO;
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
	unregister_drivers(0);

	return ret;
}

#ifdef VHOST2
/*****************************************************************************
 * vhost2
 */
static void device_create(struct rte_vhost2_dev *vdev) {
	int rc = 0;

	printf("[] Device create\n");

	rte_vhost2_dev_op_complete(vdev, rc);
}

static void device_init(struct rte_vhost2_dev *vdev) {
	int rc = 0;
	printf("[] Device init\n");

	rte_vhost2_dev_op_complete(vdev, rc);
}

static void device_features_changed(struct rte_vhost2_dev *vdev,
		uint64_t features) {
	printf("[] device_features_changed\n");
	rte_vhost2_dev_op_complete(vdev, 0);
}

static void
queue_start(struct rte_vhost2_dev *rte_vdev, struct rte_vhost2_vq *rte_vq) {

}

static void
queue_stop(struct rte_vhost2_dev *rte_vdev, struct rte_vhost2_vq *rte_vq) {

}

static void custom_msg(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq,
		const char *id, void *ctx) {
	printf("[] custom_msg\n");
	rte_vhost2_dev_op_complete(vdev, 0);
}

static void queue_kick(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq) {
	printf("[] queue_kick\n");
	rte_vhost2_dev_op_complete(vdev, 0);
}

static int get_config(struct rte_vhost2_dev *vdev, uint8_t *config,
		uint32_t len) {

	rte_vhost2_dev_op_complete(vdev, 0);
}

static int set_config(struct rte_vhost2_dev *vdev, uint8_t *config,
		uint32_t offset, uint32_t len,
		enum rte_vhost2_set_config_type type) {

	rte_vhost2_dev_op_complete(vdev, 0);
}

const struct rte_vhost2_tgt_ops g_spdk_vhost_ops = {
	.device_create = device_create,
	.device_init = device_init,
	.device_features_changed = device_features_changed,
	.queue_start = queue_start,
	.queue_stop = queue_stop,
	.device_destroy = device_destroy,
	.custom_msg = custom_msg,
	.queue_kick = queue_kick,
	.get_config = get_config,
	.set_config = set_config,
};

static int
test_vhost2(void)
{
	int ret = 0;

	unlink(TEST_SOCKET_FILE);

	if (rte_vhost2_tgt_register("vhost-user", TEST_SOCKET_FILE, 0, NULL,
			&g_spdk_vhost_ops, backend->virtio_features) != 0) {
		SPDK_ERRLOG("Could not register controller %s with vhost library\n", name);
		SPDK_ERRLOG("Check if domain socket %s already exists\n", path);
		ret = -EIO;
		goto end;
	}

	vhost_test_master(NULL);

end:
	unregister_drivers(0);

	return ret;
}
#endif /* VHOST2 */

REGISTER_TEST_COMMAND(vhost_autotest, test_vhost);

#ifdef VHOST2
REGISTER_TEST_COMMAND(vhost2_autotest, test_vhost2);
#endif
