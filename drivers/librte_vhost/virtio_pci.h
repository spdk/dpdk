/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

/* XXX This file is based on drivers/net/virtio/virtio_pci.h.  It would be
 * better to create a shared rte_virtio library instead of duplicating this
 * code.
 */

#ifndef _VIRTIO_PCI_H_
#define _VIRTIO_PCI_H_

#include <stdint.h>

#include <rte_log.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_spinlock.h>

/* Macros for printing using RTE_LOG */
#define RTE_LOGTYPE_VIRTIO_PCI_CONFIG RTE_LOGTYPE_USER2

struct virtqueue;

/* VirtIO PCI vendor/device ID. */
#define VIRTIO_PCI_VENDORID     0x1AF4
#define VIRTIO_PCI_LEGACY_DEVICEID_VHOST_USER 0x1017
#define VIRTIO_PCI_MODERN_DEVICEID_VHOST_USER 0x1058

/* VirtIO ABI version, this must match exactly. */
#define VIRTIO_PCI_ABI_VERSION 0

/*
 * VirtIO Header, located in BAR 0.
 */
#define VIRTIO_PCI_HOST_FEATURES  0  /* host's supported features (32bit, RO)*/
#define VIRTIO_PCI_GUEST_FEATURES 4  /* guest's supported features (32, RW) */
#define VIRTIO_PCI_QUEUE_PFN      8  /* physical address of VQ (32, RW) */
#define VIRTIO_PCI_QUEUE_NUM      12 /* number of ring entries (16, RO) */
#define VIRTIO_PCI_QUEUE_SEL      14 /* current VQ selection (16, RW) */
#define VIRTIO_PCI_QUEUE_NOTIFY   16 /* notify host regarding VQ (16, RW) */
#define VIRTIO_PCI_STATUS         18 /* device status register (8, RW) */
#define VIRTIO_PCI_ISR		  19 /* interrupt status register, reading
				      * also clears the register (8, RO) */
/* Only if MSIX is enabled: */
#define VIRTIO_MSI_CONFIG_VECTOR  20 /* configuration change vector (16, RW) */
#define VIRTIO_MSI_QUEUE_VECTOR	  22 /* vector for selected VQ notifications
				      (16, RW) */

/* The bit of the ISR which indicates a device has an interrupt. */
#define VIRTIO_PCI_ISR_INTR   0x1
/* The bit of the ISR which indicates a device configuration change. */
#define VIRTIO_PCI_ISR_CONFIG 0x2
/* Vector value used to disable MSI for queue. */
#define VIRTIO_MSI_NO_VECTOR 0xFFFF

/* VirtIO device IDs. */
#define VIRTIO_ID_VHOST_USER  0x18

/* Status byte for guest to report progress. */
#define VIRTIO_CONFIG_STATUS_RESET     0x00
#define VIRTIO_CONFIG_STATUS_ACK       0x01
#define VIRTIO_CONFIG_STATUS_DRIVER    0x02
#define VIRTIO_CONFIG_STATUS_DRIVER_OK 0x04
#define VIRTIO_CONFIG_STATUS_FEATURES_OK 0x08
#define VIRTIO_CONFIG_STATUS_FAILED    0x80

/*
 * Each virtqueue indirect descriptor list must be physically contiguous.
 * To allow us to malloc(9) each list individually, limit the number
 * supported to what will fit in one page. With 4KB pages, this is a limit
 * of 256 descriptors. If there is ever a need for more, we can switch to
 * contigmalloc(9) for the larger allocations, similar to what
 * bus_dmamem_alloc(9) does.
 *
 * Note the sizeof(struct vring_desc) is 16 bytes.
 */
#define VIRTIO_MAX_INDIRECT ((int) (PAGE_SIZE / 16))

/* Do we get callbacks when the ring is completely used, even if we've
 * suppressed them? */
#define VIRTIO_F_NOTIFY_ON_EMPTY	24

/* Can the device handle any descriptor layout? */
#define VIRTIO_F_ANY_LAYOUT		27

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC	28

#define VIRTIO_F_VERSION_1		32
#define VIRTIO_F_IOMMU_PLATFORM	33

/*
 * Some VirtIO feature bits (currently bits 28 through 31) are
 * reserved for the transport being used (eg. virtio_ring), the
 * rest are per-device feature bits.
 */
#define VIRTIO_TRANSPORT_F_START 28

#ifndef VIRTIO_TRANSPORT_F_END
#define VIRTIO_TRANSPORT_F_END   34
#endif

/* The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field. */
/* The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field. */
#define VIRTIO_RING_F_EVENT_IDX		29

/* Common configuration */
#define VIRTIO_PCI_CAP_COMMON_CFG	1
/* Notifications */
#define VIRTIO_PCI_CAP_NOTIFY_CFG	2
/* ISR Status */
#define VIRTIO_PCI_CAP_ISR_CFG		3
/* Device specific configuration */
#define VIRTIO_PCI_CAP_DEVICE_CFG	4
/* PCI configuration access */
#define VIRTIO_PCI_CAP_PCI_CFG		5
/* Additional capabilities for the virtio-vhost-user device */
#define VIRTIO_PCI_CAP_DOORBELL_CFG    6
#define VIRTIO_PCI_CAP_NOTIFICATION_CFG 7
#define VIRTIO_PCI_CAP_SHARED_MEMORY_CFG 8


/* This is the PCI capability header: */
struct virtio_pci_cap {
	uint8_t cap_vndr;		/* Generic PCI field: PCI_CAP_ID_VNDR */
	uint8_t cap_next;		/* Generic PCI field: next ptr. */
	uint8_t cap_len;		/* Generic PCI field: capability length */
	uint8_t cfg_type;		/* Identifies the structure. */
	uint8_t bar;			/* Where to find it. */
	uint8_t padding[3];		/* Pad to full dword. */
	uint32_t offset;		/* Offset within bar. */
	uint32_t length;		/* Length of the structure, in bytes. */
};

struct virtio_pci_notify_cap {
	struct virtio_pci_cap cap;
	uint32_t notify_off_multiplier;	/* Multiplier for queue_notify_off. */
};

/* Fields in VIRTIO_PCI_CAP_COMMON_CFG: */
struct virtio_pci_common_cfg {
	/* About the whole device. */
	uint32_t device_feature_select;	/* read-write */
	uint32_t device_feature;	/* read-only */
	uint32_t guest_feature_select;	/* read-write */
	uint32_t guest_feature;		/* read-write */
	uint16_t msix_config;		/* read-write */
	uint16_t num_queues;		/* read-only */
	uint8_t device_status;		/* read-write */
	uint8_t config_generation;	/* read-only */

	/* About a specific virtqueue. */
	uint16_t queue_select;		/* read-write */
	uint16_t queue_size;		/* read-write, power of 2. */
	uint16_t queue_msix_vector;	/* read-write */
	uint16_t queue_enable;		/* read-write */
	uint16_t queue_notify_off;	/* read-only */
	uint32_t queue_desc_lo;		/* read-write */
	uint32_t queue_desc_hi;		/* read-write */
	uint32_t queue_avail_lo;	/* read-write */
	uint32_t queue_avail_hi;	/* read-write */
	uint32_t queue_used_lo;		/* read-write */
	uint32_t queue_used_hi;		/* read-write */
};

/* Fields in VIRTIO_PCI_CAP_NOTIFICATION_CFG */
struct virtio_pci_notification_cfg {
	uint16_t notification_select;              /* read-write */
	uint16_t notification_msix_vector;         /* read-write */
};

struct virtio_hw;

struct virtio_pci_ops {
	void (*read_dev_cfg)(struct virtio_hw *hw, size_t offset,
			     void *dst, int len);
	void (*write_dev_cfg)(struct virtio_hw *hw, size_t offset,
			      const void *src, int len);
	void (*reset)(struct virtio_hw *hw);

	uint8_t (*get_status)(struct virtio_hw *hw);
	void    (*set_status)(struct virtio_hw *hw, uint8_t status);

	uint64_t (*get_features)(struct virtio_hw *hw);
	void     (*set_features)(struct virtio_hw *hw, uint64_t features);

	uint8_t (*get_isr)(struct virtio_hw *hw);

	uint16_t (*set_config_irq)(struct virtio_hw *hw, uint16_t vec);

	uint16_t (*set_queue_irq)(struct virtio_hw *hw, struct virtqueue *vq,
			uint16_t vec);

	uint16_t (*get_queue_num)(struct virtio_hw *hw, uint16_t queue_id);
	int (*setup_queue)(struct virtio_hw *hw, struct virtqueue *vq);
	void (*del_queue)(struct virtio_hw *hw, struct virtqueue *vq);
	void (*notify_queue)(struct virtio_hw *hw, struct virtqueue *vq);
};

struct virtio_hw {
	uint64_t    guest_features;
	uint32_t    max_queue_pairs;
	uint16_t    started;
	uint8_t	    use_msix;
	uint16_t    internal_id;
	uint32_t    notify_off_multiplier;
	uint8_t     *isr;
	uint16_t    *notify_base;
	struct virtio_pci_common_cfg *common_cfg;
	void	    *dev_cfg;
	/* virtio-vhost-user additional device resource capabilities
	 * https://stefanha.github.io/virtio/vhost-user-slave.html#x1-2830007
	 */
	uint32_t    doorbell_off_multiplier;
	uint16_t    *doorbell_base;
	uint32_t     doorbell_length;
	struct virtio_pci_notification_cfg *notify_cfg;
	uint8_t     *shared_memory_cfg;
	/*
	 * App management thread and virtio interrupt handler thread
	 * both can change device state, this lock is meant to avoid
	 * such a contention.
	 */
	rte_spinlock_t state_lock;

	struct virtqueue **vqs;
};

/*
 * While virtio_hw is stored in shared memory, this structure stores
 * some infos that may vary in the multiple process model locally.
 * For example, the vtpci_ops pointer.
 */
struct virtio_hw_internal {
	const struct virtio_pci_ops *vtpci_ops;
};

#define VTPCI_OPS(hw)	(virtio_pci_hw_internal[(hw)->internal_id].vtpci_ops)

extern struct virtio_hw_internal virtio_pci_hw_internal[8];

/*
 * How many bits to shift physical queue address written to QUEUE_PFN.
 * 12 is historical, and due to x86 page size.
 */
#define VIRTIO_PCI_QUEUE_ADDR_SHIFT 12

/* The alignment to use between consumer and producer parts of vring. */
#define VIRTIO_PCI_VRING_ALIGN 4096

enum virtio_msix_status {
	VIRTIO_MSIX_NONE = 0,
	VIRTIO_MSIX_DISABLED = 1,
	VIRTIO_MSIX_ENABLED = 2
};

static inline int
virtio_pci_with_feature(struct virtio_hw *hw, uint64_t bit)
{
	return (hw->guest_features & (1ULL << bit)) != 0;
}

/*
 * Function declaration from virtio_pci.c
 */
int virtio_pci_init(struct rte_pci_device *dev, struct virtio_hw *hw);
void virtio_pci_reset(struct virtio_hw *);

void virtio_pci_reinit_complete(struct virtio_hw *);

uint8_t virtio_pci_get_status(struct virtio_hw *);
void virtio_pci_set_status(struct virtio_hw *, uint8_t);

uint64_t virtio_pci_negotiate_features(struct virtio_hw *, uint64_t);

void virtio_pci_write_dev_config(struct virtio_hw *, size_t, const void *, int);

void virtio_pci_read_dev_config(struct virtio_hw *, size_t, void *, int);

uint8_t virtio_pci_isr(struct virtio_hw *);

enum virtio_msix_status virtio_pci_msix_detect(struct rte_pci_device *dev);

extern const struct virtio_pci_ops virtio_pci_modern_ops;

#endif /* _VIRTIO_PCI_H_ */
