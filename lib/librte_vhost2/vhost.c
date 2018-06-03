/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2018 Intel Corporation
 */

/* Security model
 * --------------
 * The vhost-user protocol connection is an external interface, so it must be
 * robust against invalid inputs.
 *
 * This is important because the vhost-user master is only one step removed
 * from the guest.  Malicious guests that have escaped will then launch further
 * attacks from the vhost-user master.
 *
 * Even in deployments where guests are trusted, a bug in the vhost-user master
 * can still cause invalid messages to be sent.  Such messages must not
 * compromise the stability of the DPDK application by causing crashes, memory
 * corruption, or other problematic behavior.
 *
 * Do not assume received VhostUserMsg fields contain sensible values!
 */

#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_atomic.h>

#include "vhost.h"

static rte_atomic32_t g_vhost_dev_count = RTE_ATOMIC32_INIT(0);

static const char *vhost_message_str[VHOST_USER_MAX] = {
	[VHOST_USER_NONE] = "VHOST_USER_NONE",
	[VHOST_USER_GET_FEATURES] = "VHOST_USER_GET_FEATURES",
	[VHOST_USER_SET_FEATURES] = "VHOST_USER_SET_FEATURES",
	[VHOST_USER_SET_OWNER] = "VHOST_USER_SET_OWNER",
	[VHOST_USER_RESET_OWNER] = "VHOST_USER_RESET_OWNER",
	[VHOST_USER_SET_MEM_TABLE] = "VHOST_USER_SET_MEM_TABLE",
	[VHOST_USER_SET_LOG_BASE] = "VHOST_USER_SET_LOG_BASE",
	[VHOST_USER_SET_LOG_FD] = "VHOST_USER_SET_LOG_FD",
	[VHOST_USER_SET_VRING_NUM] = "VHOST_USER_SET_VRING_NUM",
	[VHOST_USER_SET_VRING_ADDR] = "VHOST_USER_SET_VRING_ADDR",
	[VHOST_USER_SET_VRING_BASE] = "VHOST_USER_SET_VRING_BASE",
	[VHOST_USER_GET_VRING_BASE] = "VHOST_USER_GET_VRING_BASE",
	[VHOST_USER_SET_VRING_KICK] = "VHOST_USER_SET_VRING_KICK",
	[VHOST_USER_SET_VRING_CALL] = "VHOST_USER_SET_VRING_CALL",
	[VHOST_USER_SET_VRING_ERR]  = "VHOST_USER_SET_VRING_ERR",
	[VHOST_USER_GET_PROTOCOL_FEATURES]  = "VHOST_USER_GET_PROTOCOL_FEATURES",
	[VHOST_USER_SET_PROTOCOL_FEATURES]  = "VHOST_USER_SET_PROTOCOL_FEATURES",
	[VHOST_USER_GET_QUEUE_NUM]  = "VHOST_USER_GET_QUEUE_NUM",
	[VHOST_USER_SET_VRING_ENABLE]  = "VHOST_USER_SET_VRING_ENABLE",
	[VHOST_USER_SET_SLAVE_REQ_FD]  = "VHOST_USER_SET_SLAVE_REQ_FD",
	[VHOST_USER_IOTLB_MSG]  = "VHOST_USER_IOTLB_MSG",
};

static void _process_vhost_msg(struct vhost_dev *vdev);

int
vhost_dev_init(struct vhost_dev *vdev, uint64_t features,
	       const struct vhost_transport_ops *transport,
	       const struct vhost_dev_transport_ops *vdev_transport,
	       const struct rte_vhost2_tgt_ops *ops)
{
	memset(vdev, 0, sizeof(*vdev));

	vdev->dev.transport = transport;
	/* this might be later unset if the driver doesn't support it */
	vdev->dev.iommu = features & (1ULL << VIRTIO_F_IOMMU_PLATFORM);

	vdev->id = rte_atomic32_add_return(&g_vhost_dev_count, 1);

	vdev->transport_ops = vdev_transport;
	vdev->ops = ops;
	vdev->supported_features = features;
	vdev->features = 0;
	vdev->ops = ops;

	return 0;
}

void
vhost_dev_set_ops_cb(struct vhost_dev *vdev,
		vhost_dev_ops_cb cb_fn, void *ctx)
{
	assert(vdev->op_cpl_fn == NULL);
	vdev->op_cpl_fn = cb_fn;
	vdev->op_cpl_ctx = ctx;
}

void
vhost_dev_ops_complete(struct vhost_dev *vdev, int rc)
{
	assert(vdev->op_cpl_fn);
	vdev->op_cpl_fn(vdev, rc, vdev->op_cpl_ctx);
	vdev->op_cpl_fn = NULL;
	vdev->op_cpl_ctx = NULL;
}

static void _stop_all_vqs(struct vhost_dev *vdev);

static void
_stop_all_vqs_cpl(struct vhost_dev *vdev, int rc, void *ctx)
{
	struct vhost_vq *vq = ctx;

	if (rc == 0) {
		vq->started = false;
	}

	/* Stop the next queue. */
	_stop_all_vqs(vdev);
}

static void
_stop_all_vqs(struct vhost_dev *vdev)
{
	struct vhost_vq *vq;
	uint32_t vq_idx;

	for (vq_idx = 0; vq_idx < VHOST_MAX_VIRTQUEUES; vq_idx++) {
		vq = vdev->vq[vq_idx];

		if (!vq || !vq->started)
			continue;

		if (vdev->ops->queue_stop) {
			vhost_dev_set_ops_cb(vdev, _stop_all_vqs_cpl, vq);
			vdev->ops->queue_stop(&vdev->dev, &vq->q);
		} else {
			_stop_all_vqs_cpl(vdev, 0, vq);
		}
		return;
	}

	_process_vhost_msg(vdev);
}

static void _start_all_vqs(struct vhost_dev *vdev);

static void
_start_all_vqs_cpl(struct vhost_dev *vdev, int rc, void *ctx)
{
	struct vhost_vq *vq = ctx;

	if (rc == 0) {
		vq->started = true;
	}

	/* Start the next queue. */
	_start_all_vqs(vdev);
}

static void
_start_all_vqs(struct vhost_dev *vdev)
{
	struct vhost_vq *vq;
	uint32_t vq_idx;

	for (vq_idx = 0; vq_idx < VHOST_MAX_VIRTQUEUES; vq_idx++) {
		vq = vdev->vq[vq_idx];

		if (!vq || vq->kickfd == -1 || vq->started)
			continue;

		if (vdev->ops->queue_start) {
			vhost_dev_set_ops_cb(vdev, _start_all_vqs_cpl, vq);
			vdev->ops->queue_start(&vdev->dev, &vq->q);
		} else {
			_start_all_vqs_cpl(vdev, 0, vq);
		}
		return;
	}
}

static void
_stop_vq_cpl(struct vhost_dev *vdev, int rc, void *ctx)
{
	int vq_idx = (uintptr_t)ctx;

	if (rc) {
		//todo
		abort();
	}

	vdev->vq[vq_idx]->started = false;
	_process_vhost_msg(vdev);
}

static void
_stop_vq(struct vhost_dev *vdev, struct vhost_vq *vq)
{
	if (vdev->ops->queue_stop) {
		vhost_dev_set_ops_cb(vdev, _stop_vq_cpl, vq);
		vdev->ops->queue_stop(&vdev->dev, &vq->q);
	} else {
		_stop_vq_cpl(vdev, 0, vq);
	}
}

static int
_alloc_stop_vq(struct vhost_dev *vdev, uint16_t vq_idx)
{
	struct vhost_vq *vq;

	if (vq_idx >= VHOST_MAX_VIRTQUEUES) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"invalid vring index: %u\n", vq_idx);
		return -1;
	}

	vq = vdev->vq[vq_idx];
	if (vq) {
		if (vq->started) {
			_stop_vq(vdev, vq);
		}
		return 0;
	}

	vq = rte_malloc(NULL, sizeof(struct vhost_vq), 0);
	if (vq == NULL) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"Failed to allocate memory for vring:%u.\n", vq_idx);
		return -1;
	}

	vdev->vq[vq_idx] = vq;
	_process_vhost_msg(vdev);
	return 0;
}

static void *
uva_to_vva(struct vhost_dev *vdev, uint64_t qva, uint64_t len)
{
	struct rte_vhost2_mem_region *r;
	uint32_t i;

	/* Find the region where the address lives. */
	for (i = 0; i < vdev->dev.mem->nregions; i++) {
		r = &vdev->dev.mem->regions[i];

		if (qva >= r->guest_user_addr &&
		    qva <  r->guest_user_addr + r->size) {

			if (unlikely(len > r->guest_user_addr + r->size - qva))
				return NULL;

			return (void *)(uintptr_t)(qva - r->guest_user_addr +
			       r->host_user_addr);
		}
	}

	return NULL;
}


/*
 * Converts ring address to Vhost virtual address.
 * If IOMMU is enabled, the ring address is a guest IO virtual address,
 * else it is a QEMU virtual address.
 */
static void *
ring_addr_to_vva(struct vhost_dev *vdev, struct vhost_vq *vq,
		uint64_t ra, uint64_t size)
{
	(void) vq;
	if (vdev->dev.iommu) {
		// todo
		abort();
	}

	return uva_to_vva(vdev, ra, size);
}

static int
translate_ring_addresses(struct vhost_dev *dev, struct vhost_vq *vq, VhostUserMsg *msg)
{
	struct vhost_vring_addr addr = msg->payload.addr;
	uint64_t len;

	len = sizeof(struct vring_desc) * vq->q.size;
	vq->q.desc = ring_addr_to_vva(dev, vq, addr.desc_user_addr, len);
	if (vq->q.desc == NULL) {
		RTE_LOG(DEBUG, VHOST_CONFIG,
			"(%d) failed to map desc ring.\n",
			dev->id);
		return -1;
	}

	len = sizeof(struct vring_avail) + sizeof(uint16_t) * vq->q.size;
	vq->q.avail = ring_addr_to_vva(dev, vq, addr.avail_user_addr, len);
	if (vq->q.avail == NULL) {
		RTE_LOG(DEBUG, VHOST_CONFIG,
			"(%d) failed to map avail ring.\n",
			dev->id);
		return -1;
	}

	len = sizeof(struct vring_used) +
		sizeof(struct vring_used_elem) * vq->q.size;
	vq->q.used = ring_addr_to_vva(dev, vq, addr.used_user_addr, len);
	if (vq->q.used == NULL) {
		RTE_LOG(DEBUG, VHOST_CONFIG,
			"(%d) failed to map used ring.\n",
			dev->id);
		return -1;
	}

	if (vq->q.last_used_idx != vq->q.used->idx) {
		RTE_LOG(WARNING, VHOST_CONFIG,
			"last_used_idx (%u) and vq->used->idx (%u) mismatches; "
			"some packets maybe resent for Tx and dropped for Rx\n",
			vq->q.last_used_idx, vq->q.used->idx);
		vq->q.last_used_idx  = vq->q.used->idx;
		vq->q.last_avail_idx = vq->q.used->idx;
	}

	vq->q.log_guest_addr = addr.log_guest_addr;

	RTE_LOG(DEBUG, VHOST_CONFIG, "(%d) mapped address desc: %p\n",
			dev->id, vq->q.desc);
	RTE_LOG(DEBUG, VHOST_CONFIG, "(%d) mapped address avail: %p\n",
			dev->id, vq->q.avail);
	RTE_LOG(DEBUG, VHOST_CONFIG, "(%d) mapped address used: %p\n",
			dev->id, vq->q.used);
	RTE_LOG(DEBUG, VHOST_CONFIG, "(%d) log_guest_addr: %lu\n",
			dev->id, vq->q.log_guest_addr);

	return 0;
}

#ifdef RTE_LIBRTE_VHOST_DEBUG
/* TODO: enable it only in debug mode? */
static void
dump_guest_pages(struct virtio_net *dev)
{
	uint32_t i;
	struct guest_page *page;

	for (i = 0; i < dev->nr_guest_pages; i++) {
		page = &dev->guest_pages[i];

		RTE_LOG(INFO, VHOST_CONFIG,
			"guest physical page region %u\n"
			"\t guest_phys_addr: %" PRIx64 "\n"
			"\t host_phys_addr : %" PRIx64 "\n"
			"\t size           : %" PRIx64 "\n",
			i,
			page->guest_phys_addr,
			page->host_phys_addr,
			page->size);
	}
}
#else
#define dump_guest_pages(dev)
#endif

static int
send_vhost_reply(struct vhost_dev *vdev, struct VhostUserMsg *msg)
{
	msg->flags &= ~VHOST_USER_VERSION_MASK;
	msg->flags &= ~VHOST_USER_NEED_REPLY;
	msg->flags |= VHOST_USER_VERSION;
	msg->flags |= VHOST_USER_REPLY_MASK;

	return vdev->transport_ops->send_reply(vdev, msg);
}

int
vhost_dev_msg_handler(struct vhost_dev *vdev, struct VhostUserMsg *msg)
{
	if (msg->type >= VHOST_USER_MAX)
		return -1;

	RTE_LOG(ERR, VHOST_CONFIG, "read message (%d) %s\n",
		msg->type, vhost_message_str[msg->type]);
	vdev->op_msg = msg;

	switch (msg->type) {
	case VHOST_USER_SET_VRING_KICK:
	case VHOST_USER_SET_VRING_CALL:
	case VHOST_USER_SET_VRING_ERR:
		return _alloc_stop_vq(vdev,
				msg->payload.u64 & VHOST_USER_VRING_IDX_MASK);
	case VHOST_USER_SET_VRING_NUM:
	case VHOST_USER_SET_VRING_BASE:
	case VHOST_USER_SET_VRING_ENABLE:
		return _alloc_stop_vq(vdev, msg->payload.state.index);
	case VHOST_USER_SET_VRING_ADDR:
		return _alloc_stop_vq(vdev, msg->payload.addr.index);
	case VHOST_USER_SET_MEM_TABLE:
		_stop_all_vqs(vdev);
		return 0;
	default:
		_process_vhost_msg(vdev);
		return 0;
	}

	return 0;
}

static int
_process_msg(struct vhost_dev *vdev)
{
	struct VhostUserMsg *msg = vdev->op_msg;
	struct vhost_vq *vq;
	struct vhost_vring_file file;

	switch (msg->type) {
	case VHOST_USER_GET_FEATURES:
		msg->payload.u64 = vdev->supported_features;
		msg->size = sizeof(msg->payload.u64);
		return send_vhost_reply(vdev, msg);

	case VHOST_USER_SET_FEATURES:
		if (msg->payload.u64 & ~vdev->supported_features) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"received invalid negotiated features.\n");
			return -1;
		}

		vdev->features = msg->payload.u64;

		if (vdev->ops->device_features_changed) {
			vhost_dev_set_ops_cb(vdev, NULL, NULL);
			vdev->ops->device_features_changed(&vdev->dev, vdev->features);
		}
		return 0;

	case VHOST_USER_SET_OWNER:
		//todo
		return 0;

	case VHOST_USER_RESET_OWNER:
		if (vdev->dev.mem) {
			rte_free(vdev->dev.mem);
			vdev->dev.mem = NULL;
		}

		//todo
		return 0;

	case VHOST_USER_SET_MEM_TABLE:
		/* mem table is managed by the transport layer */
		return 0;

	case VHOST_USER_SET_VRING_NUM:
		vq = vdev->vq[msg->payload.state.index];
		vq->q.size = msg->payload.state.num;

		/* VIRTIO 1.0, 2.4 Virtqueues says:
		 *
		 *   Queue Size value is always a power of 2. The maximum Queue Size
		 *   value is 32768.
		 */
		if ((vq->q.size & (vq->q.size - 1)) || vq->q.size > 32768) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"invalid virtqueue size %u\n", vq->q.size);
			return -1;
		}
		return 0;

	case VHOST_USER_SET_VRING_ADDR:
		if (vdev->dev.mem == NULL)
			return -1;

		vq = vdev->vq[msg->payload.addr.index];
		translate_ring_addresses(vdev, vq, msg);
		return 0;

	case VHOST_USER_SET_VRING_BASE:
		vq = vdev->vq[msg->payload.state.index];
		vq->q.last_used_idx = msg->payload.state.num;
		vq->q.last_avail_idx = msg->payload.state.num;

		return 0;

	case VHOST_USER_GET_VRING_BASE:
		vq = vdev->vq[msg->payload.state.index];
		msg->payload.state.num = vq->q.last_avail_idx;

		RTE_LOG(INFO, VHOST_CONFIG,
			"vring base idx:%d file:%d\n", msg->payload.state.index,
			msg->payload.state.num);

		if (vq->kickfd >= 0)
			close(vq->kickfd);

		vq->kickfd = -1;

		msg->size = sizeof(msg->payload.state);
		return send_vhost_reply(vdev, msg);

	case VHOST_USER_SET_VRING_KICK:
		file.index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
		if (msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
			file.fd = -1;
		else
			file.fd = msg->fds[0];

		RTE_LOG(INFO, VHOST_CONFIG,
			"vring kick idx:%d file:%d\n", file.index, file.fd);

		vq = vdev->vq[file.index];

		if (vq->kickfd >= 0)
			close(vq->kickfd);

		vq->kickfd = file.fd;
		return 0;

	case VHOST_USER_SET_VRING_CALL:
		file.index = msg->payload.u64 & VHOST_USER_VRING_IDX_MASK;
		if (msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK)
			file.fd = -1;
		else
			file.fd = msg->fds[0];

		RTE_LOG(INFO, VHOST_CONFIG,
			"vring call idx:%d file:%d\n", file.index, file.fd);

		vq = vdev->vq[file.index];
		if (vq->callfd >= 0)
			close(vq->callfd);

		vq->callfd = file.fd;
		return 0;

	case VHOST_USER_SET_VRING_ERR:
		if (!(msg->payload.u64 & VHOST_USER_VRING_NOFD_MASK))
			close(msg->fds[0]);
		RTE_LOG(INFO, VHOST_CONFIG, "not implemented\n");
		return 0;

	case VHOST_USER_GET_QUEUE_NUM:
		msg->payload.u64 = (uint64_t)VHOST_MAX_VIRTQUEUES;
		msg->size = sizeof(msg->payload.u64);
		return send_vhost_reply(vdev, msg);

	default:
		//todo
		abort();
	}
}

//todo ret
static void
_process_vhost_msg(struct vhost_dev *vdev)
{
	struct VhostUserMsg *msg = vdev->op_msg;
	int ret = 0;

	if (vdev->transport_ops->handle_msg) {
		ret = vdev->transport_ops->handle_msg(vdev, msg);
		if (ret < 0) {
			return;
		}
	}

	ret = _process_msg(vdev);
	if (ret) {
		return;
	}

	if (msg->flags & VHOST_USER_NEED_REPLY) {
		msg->payload.u64 = !!ret;
		msg->size = sizeof(msg->payload.u64);
		ret = send_vhost_reply(vdev, msg);
		if (ret) {
			return;
		}
	}

	_start_all_vqs(vdev);
}
