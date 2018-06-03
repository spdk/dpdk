/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Intel Corporation
 */

#ifndef _RTE_VHOST2_TRANSPORT_H_
#define _RTE_VHOST2_TRANSPORT_H_

#include "rte_vhost2.h"

struct vhost_transport_ops {
	char type[32];
	int (*tgt_register)(const char *trid, uint64_t trflags, void *trctx,
			const struct rte_vhost2_tgt_ops *tgt_ops,
			uint64_t features);
	int (*tgt_unregister)(const char *trid,
			void (*cb_fn)(void *arg), void *cb_arg);
	void (*dev_op_cpl)(struct rte_vhost2_dev *vdev, int rc);
	void (*dev_call)(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq);

	TAILQ_ENTRY(vhost_transport_ops) tailq;
};

void vhost_transport_register(struct vhost_transport_ops *transport);

#define VHOST_TRANSPORT_REGISTER(tr)					\
	void _tr_init_##tr(void);					\
	void __attribute__((constructor, used)) _tr_init_##tr(void)	\
	{								\
		vhost_transport_register(&tr);			\
	}

#endif /* _RTE_VHOST2_TRANSPORT_H_ */
