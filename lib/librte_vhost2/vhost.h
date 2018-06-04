/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Intel Corporation
 */

#ifndef _VHOST_NET_USER_H
#define _VHOST_NET_USER_H

#include <stdint.h>
#include <linux/vhost.h>

#include "rte_vhost2.h"

#ifndef VHOST_USER_PROTOCOL_F_MQ
#define VHOST_USER_PROTOCOL_F_MQ	0
#endif

#ifndef VHOST_USER_PROTOCOL_F_REPLY_ACK
#define VHOST_USER_PROTOCOL_F_REPLY_ACK	3
#endif

#ifndef VIRTIO_F_ANY_LAYOUT
#define VIRTIO_F_ANY_LAYOUT 27
#endif

#ifndef VHOST_USER_F_PROTOCOL_FEATURES
#define VHOST_USER_F_PROTOCOL_FEATURES	30
#endif

#ifndef VIRTIO_F_VERSION_1
#define VIRTIO_F_VERSION_1 32
#endif

#ifndef VIRTIO_F_IOMMU_PLATFORM

#define VIRTIO_F_IOMMU_PLATFORM 33

struct vhost_iotlb_msg {
	__u64 iova;
	__u64 size;
	__u64 uaddr;
#define VHOST_ACCESS_RO      0x1
#define VHOST_ACCESS_WO      0x2
#define VHOST_ACCESS_RW      0x3
	__u8 perm;
#define VHOST_IOTLB_MISS           1
#define VHOST_IOTLB_UPDATE         2
#define VHOST_IOTLB_INVALIDATE     3
#define VHOST_IOTLB_ACCESS_FAIL    4
	__u8 type;
};

#define VHOST_IOTLB_MSG 0x1

struct vhost_msg {
	int type;
	union {
		struct vhost_iotlb_msg iotlb;
		__u8 padding[64];
	};
};
#endif

#define VHOST_MEMORY_MAX_NREGIONS	8

enum {
	VHOST_USER_NONE = 0,
	VHOST_USER_GET_FEATURES = 1,
	VHOST_USER_SET_FEATURES = 2,
	VHOST_USER_SET_OWNER = 3,
	VHOST_USER_RESET_OWNER = 4,
	VHOST_USER_SET_MEM_TABLE = 5,
	VHOST_USER_SET_LOG_BASE = 6,
	VHOST_USER_SET_LOG_FD = 7,
	VHOST_USER_SET_VRING_NUM = 8,
	VHOST_USER_SET_VRING_ADDR = 9,
	VHOST_USER_SET_VRING_BASE = 10,
	VHOST_USER_GET_VRING_BASE = 11,
	VHOST_USER_SET_VRING_KICK = 12,
	VHOST_USER_SET_VRING_CALL = 13,
	VHOST_USER_SET_VRING_ERR = 14,
	VHOST_USER_GET_PROTOCOL_FEATURES = 15,
	VHOST_USER_SET_PROTOCOL_FEATURES = 16,
	VHOST_USER_GET_QUEUE_NUM = 17,
	VHOST_USER_SET_VRING_ENABLE = 18,
	VHOST_USER_SET_SLAVE_REQ_FD = 21,
	VHOST_USER_IOTLB_MSG = 22,
	VHOST_USER_MAX = 28
};

enum {
	VHOST_USER_SLAVE_NONE = 0,
	VHOST_USER_SLAVE_IOTLB_MSG = 1,
	VHOST_USER_SLAVE_MAX
};

typedef struct VhostUserMemoryRegion {
	uint64_t guest_phys_addr;
	uint64_t memory_size;
	uint64_t userspace_addr;
	uint64_t mmap_offset;
} VhostUserMemoryRegion;

typedef struct VhostUserMemory {
	uint32_t nregions;
	uint32_t padding;
	VhostUserMemoryRegion regions[VHOST_MEMORY_MAX_NREGIONS];
} VhostUserMemory;

typedef struct VhostUserLog {
	uint64_t mmap_size;
	uint64_t mmap_offset;
} VhostUserLog;

typedef struct VhostUserMsg {
	uint32_t type;

#define VHOST_USER_VERSION_MASK     0x3
#define VHOST_USER_REPLY_MASK       (0x1 << 2)
#define VHOST_USER_NEED_REPLY	    (0x1 << 3)
	uint32_t flags;
	uint32_t size; /* the following payload size */
	union {
#define VHOST_USER_VRING_IDX_MASK   0xff
#define VHOST_USER_VRING_NOFD_MASK  (0x1<<8)
		uint64_t u64;
		struct vhost_vring_state state;
		struct vhost_vring_addr addr;
		VhostUserMemory memory;
		VhostUserLog    log;
		struct vhost_iotlb_msg iotlb;
	} payload;
	int fds[VHOST_MEMORY_MAX_NREGIONS];
} __attribute((packed)) VhostUserMsg;

/* The version of the protocol we support */
#define VHOST_USER_VERSION    0x1

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_VHOST_CONFIG	RTE_LOGTYPE_USER1
#define RTE_LOGTYPE_VHOST_DATA		RTE_LOGTYPE_USER1

#define VHOST_MAX_VIRTQUEUES		128

struct vhost_vq {
	struct rte_vhost2_vq q;
	uint16_t idx;
	int callfd;
	int kickfd;
	bool started;
} __rte_cache_aligned;

struct vhost_dev;

typedef void (*vhost_dev_ops_cb)(struct vhost_dev *vdev,
		int rc, void *ctx);

struct VhostUserMsg;

struct vhost_dev_ops {
	int (*handle_msg)(struct vhost_dev *vdev, struct VhostUserMsg *msg);
	void (*msg_cpl)(struct vhost_dev *vdev, struct VhostUserMsg *msg);
	int (*send_reply)(struct vhost_dev *vdev, struct VhostUserMsg *msg);
};

struct vhost_dev {
	struct rte_vhost2_dev dev;
	unsigned id;
	const struct vhost_dev_ops *dev_ops;
	const struct rte_vhost2_tgt_ops *ops;

	/* features supported by the slave */
	uint64_t supported_features;

	/* negotiated features */
	uint64_t features;

	/* negotiated protocol features */
	uint64_t protocol_features;
	struct vhost_vq *vq[VHOST_MAX_VIRTQUEUES];

	/* currently handled msg */
	struct VhostUserMsg *msg;

	unsigned op_pending_cnt;
	vhost_dev_ops_cb op_cpl_fn;
	void *op_cpl_ctx;
	bool op_failed_flag;
	bool op_completed_inline;

	bool removed;
	void (*del_cb_fn)(void *arg);
	void *del_cb_arg;
};

int vhost_dev_init(struct vhost_dev *vdev, uint64_t features,
		   const struct vhost_transport_ops *transport,
		   const struct vhost_dev_ops *dev_ops,
		   const struct rte_vhost2_tgt_ops *ops);

void vhost_dev_destroy(struct vhost_dev *vdev, void (*cb_fn)(void *arg),
		       void *arg);

void vhost_dev_set_ops_cb(struct vhost_dev *vdev,
		vhost_dev_ops_cb cb_fn, void *ctx);

void vhost_dev_ops_complete(struct vhost_dev *vdev, int rc);

int vhost_dev_msg_handler(struct vhost_dev *vdev, struct VhostUserMsg *msg);

#endif
