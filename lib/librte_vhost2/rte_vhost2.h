/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Intel Corporation
 */

#ifndef _RTE_VHOST2_H_
#define _RTE_VHOST2_H_

/**
 * @file
 * This library abstracts away most Vhost-user/virtio-vhost-user specifics
 * and allows developers to implement Vhost devices with an ease.
 * It calls user-provided callbacks once proper device initialization
 * state has been reached. That is - memory mappings have changed,
 * virtqueues are ready to be processed, features have changed in runtime, etc.
 */

#include <stdint.h>
#include <stdbool.h>

#include <rte_branch_prediction.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Not C++-aware. */
#include <linux/vhost.h>

#define RTE_VHOST2_CLIENT		(1ULL << 0)
#define RTE_VHOST2_NO_RECONNECT		(1ULL << 1)

enum rte_vhost2_set_config_type {
	/** Config changed on request by the vhost driver. */
	VHOST_SET_CONFIG_TYPE_MASTER = 0,
	/** Config is being restored after a successful migration. */
	VHOST_SET_CONFIG_TYPE_MIGRATION = 1,
};

/** Single memory region. Both physically and virtually contiguous */
struct rte_vhost2_mem_region {
	uint64_t guest_phys_addr;
	uint64_t guest_user_addr;
	uint64_t host_user_addr;
	uint64_t size;
};

struct rte_vhost2_memory {
	uint32_t nregions;
	struct rte_vhost2_mem_region regions[];
};

/**
 * Vhost device created and managed by rte_vhost2. Accessible via
 * \c rte_vhost2_tgt_ops callbacks. This is only a part of the real
 * vhost device data. This struct is published just for inline vdev
 * functions to access their data directly.
 */
struct rte_vhost2_dev {
	const struct vhost_transport_ops *transport;
	struct rte_vhost2_memory *mem;
	bool iommu; /**< \c VIRTIO_F_IOMMU_PLATFORM has been negotiated */
};

/**
 * Virtqueue created and managed by rte_vhost2. Accessible via
 * \c rte_vhost2_tgt_ops callbacks.
 */
struct rte_vhost2_vq {
	struct vring_desc *desc;
	struct vring_avail *avail;
	struct vring_used *used;
	/* available only if \c VHOST_F_LOG_ALL has been negotiated */
	uint64_t log_guest_addr;
	uint16_t size;
	uint16_t last_avail_idx;
	uint16_t last_used_idx;
};

/**
 * Device/queue related callbacks, all optional. Provided callback
 * parameters are guaranteed not to be NULL unless explicitly specified.
 */
struct rte_vhost2_tgt_ops {
	/**
	 * New driver connected. If this is completed with a non-zero status,
	 * rte_vhost2 will terminate the connection.
	 */
	void (*device_create)(struct rte_vhost2_dev *vdev);
	/**
	* Device is ready to operate. vdev data is now initialized. This callback
	* may be called multiple times as e.g. memory mappings can change
	* dynamically. All queues are guaranteed to be stopped by now.
	*/
	void (*device_init)(struct rte_vhost2_dev *vdev);
	/**
	* Features have changed in runtime. This is called at least once during
	* initialization before `device_init`. Queues might be still running
	* at this point.
	*/
	void (*device_features_changed)(struct rte_vhost2_dev *vdev,
			uint64_t features);
	/**
	* Start processing vq. The `vq` is guaranteed not to be modified before
	* `queue_stop` is called.
	*/
	void (*queue_start)(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq);
	/**
	* Stop processing vq. It shouldn't be accessed after this callback
	* completes (via \c rte_vhost2_tgt_cb_complete). This can be called
	* prior to shutdown or before actions that require changing vhost
	* device/vq state.
	*/
	void (*queue_stop)(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq);
	/** Device disconnected. All queues are guaranteed to be stopped by now */
	void (*device_destroy)(struct rte_vhost2_dev *vdev);
	/**
	 * Custom message handler. `vq` can be NULL. This is called for
	 * backend-specific actions. The `id` should be prefixed by the backend
	 * name (net/crypto/scsi) and `ctx` is message-specific data that should
	 * be available until \c rte_vhost2_tgt_cb_complete is called.
	 */
	void (*custom_msg)(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq,
			const char *id, void *ctx);

	/** Interrupt handler, synchronous. */
	void (*queue_kick)(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq);
	/**
	 * Full device config read, synchronous. Return 0 if `len` bytes of
	 * `config` have been successfully set, -1 otherwise.
	 */
	int (*get_config)(struct rte_vhost2_dev *vdev, uint8_t *config,
			uint32_t len);
	/**
	 * Device config changed by the driver, synchronous. `type` indicates
	 * the reason of change.
	 */
	int (*set_config)(struct rte_vhost2_dev *vdev, uint8_t *config,
			uint32_t offset, uint32_t len,
			enum rte_vhost2_set_config_type type);

	void *reserved[8]; /**< Reserved for future extension */
};

/**
 * Registers a new vhost target accepting remote connections. Multiple
 * available transports are available. It is possible to create a Vhost-user
 * Unix domain socket polling local connections or connect to a virtualized
 * PCI vhost device and install an interrupt handler. A separate `rte_vhost2_dev`
 * struct will be created for each end-point connection.
 *
 * This function is thread-safe.
 *
 * \param trtype type of the transport used, e.g. "vhost-user",
 * "PCI-vhost-user", "PCI-vDPA".
 * \param trid identifier of the device. For PCI this would be the BDF address,
 * for vhost-user the socket name.
 * \param trflags additional options for the specified transport
 * \param trctx additional data for the specified transport. Can be NULL.
 * \param tgt_ops callbacks to be called upon reaching specific initialization
 * states.
 * \param features supported vhost features. To be negotiated with the
 * driver ones. rte_vhost2 will append a couple of generic feature bits
 * which are required. TODO list these features here
 * \return 0 on success, negative errno otherwise
 */
int rte_vhost2_tgt_register(const char *trtype, const char *trid,
			    uint64_t trflags, void *trctx,
			    const struct rte_vhost2_tgt_ops *tgt_ops,
			    uint64_t features);

/**
 * Unregisters a vhost target asynchronously. All active queue will be stopped
 * and all devices destroyed.
 *
 * This function is thread-safe.
 *
 * \param cb_fn callback to be called on finish. It'll be called from the same
 * thread that calls \c rte_vhost2_tgt_ops.
 * \param cb_ctx argument for \c cb_fn
 * \return 0 on success, negative errno otherwise. `cb_fn` won't be called
 * if non-zero value is returned.
 */
int rte_vhost2_tgt_unregister(const char *trtype, const char *trid,
			       void (*cb_fn)(void *arg), void *cb_ctx);

/**
 * Finish async device tgt ops callback. Unless a tgt op has been documented
 * as 'synchronous' this function must be called at the end of the op handler.
 * It can be called either before or after the op handler returns. rte_vhost2
 * won't call any tgt ops callbacks while another one hasn't been finished yet.
 *
 * This function is thread-safe.
 *
 * \param vdev vhost device
 * \param rc 0 on success, negative errno otherwise. If non-zero value is
 * given, the current callback will be perceived as failed. A queue that failed
 * to start won't need to be stopped.
 */
void rte_vhost2_dev_op_complete(struct rte_vhost2_dev *vdev, int rc);

//todo
void *__vhost_iova_to_vva(struct rte_vhost2_dev *vdev,
		struct rte_vhost2_vq *vq,
		uint64_t iova, uint32_t *len, uint8_t perm);

/**
 * Translate I/O virtual address to vhost address space.
 *
 * If VIRTIO_F_IOMMU_PLATFORM has been negotiated, this might potentially send
 * a TLB miss and wait for the TLB update response.
 * If VIRTIO_F_IOMMU_PLATFORM has not been negotiated, `iova` is a physical
 * address and `perm` is ignored.
 *
 * This function is thread-safe.
 *
 * \param vdev vhost device
 * \param vq virtqueue. Must be started.
 * \param iova I/O virtual address
 * \param len length of the memory to translate (in bytes). If requested
 * memory chunk crosses memory region boundary, the *len will be set to
 * the remaining, maximum length of virtually contiguous memory. In such
 * case the user will be required to call another gpa_to_vva(gpa + *len).
 * \param perm VHOST_ACCESS_RO,VHOST_ACCESS_WO or VHOST_ACCESS_RW
 * \return vhost virtual address or NULL if requested `iova` is not mapped
 * or the `perm` doesn't match.
 */
static inline void *
rte_vhost2_iova_to_vva(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq,
		       uint64_t iova, uint32_t *len, uint8_t perm)
{
	struct rte_vhost2_mem_region *r;
	uint32_t i;

	if (vdev->iommu) {
		return __vhost_iova_to_vva(vdev, vq, iova, len, perm);
	}

	for (i = 0; i < vdev->mem->nregions; i++) {
		r = &vdev->mem->regions[i];
		if (iova >= r->host_user_addr &&
		    iova <  r->guest_phys_addr + r->size) {

			if (unlikely(*len > r->guest_phys_addr + r->size - iova)) {
				*len = r->guest_phys_addr + r->size - iova;
			}

			return (void *)(uintptr_t)(iova
					- r->guest_phys_addr + r->host_user_addr);
		}
	}
	*len = 0;

	return 0;
}

/**
 * Notify the driver about vq change. This is an eventfd_write for vhost-user
 * or MMIO write for PCI devices.
 *
 * \param vdev vhost device
 * \param vq virtqueue. Must be started.
 */
void rte_vhost2_dev_call(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq);

/**
 * Notify the driver about device config change. This will result in \c
 * rte_vhost2_tgt_ops->get_config being called.
 *
 * \param vdev vhost device
 */
void rte_vhost2_dev_cfg_call(struct rte_vhost2_dev *vdev);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_VHOST2_H_ */
