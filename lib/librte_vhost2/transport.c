/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) Intel Corporation
 */

#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <sys/queue.h>

#include "transport.h"
#include "rte_vhost2.h"

static pthread_mutex_t g_vhost_mutex = PTHREAD_MUTEX_INITIALIZER;
TAILQ_HEAD(, vhost_transport_ops) g_vhost_transports =
		TAILQ_HEAD_INITIALIZER(g_vhost_transports);

int
rte_vhost2_tgt_register(const char *trtype, const char *trid,
			uint64_t trflags, void *trctx,
			const struct rte_vhost2_tgt_ops *tgt_ops,
			uint64_t features)
{
	struct vhost_transport_ops *tr;
	int rc = -EINVAL;

	pthread_mutex_lock(&g_vhost_mutex);
	TAILQ_FOREACH(tr, &g_vhost_transports, tailq) {
		if (strcmp(trtype, tr->type) == 0) {
			rc = tr->tgt_register(trid, trflags, trctx, tgt_ops, features);
			break;
		}
	}
	pthread_mutex_unlock(&g_vhost_mutex);
	return rc;
}

int
rte_vhost2_tgt_unregister(const char *trtype, const char *trid,
			       void (*cb_fn)(void *arg), void *cb_ctx)
{
	struct vhost_transport_ops *tr;
	int rc = -EINVAL;

	pthread_mutex_lock(&g_vhost_mutex);
	TAILQ_FOREACH(tr, &g_vhost_transports, tailq) {
		if (strcmp(trtype, tr->type) == 0) {
			rc = tr->tgt_unregister(trid, cb_fn, cb_ctx);
			break;
		}
	}
	pthread_mutex_unlock(&g_vhost_mutex);
	return rc;
}

void
rte_vhost2_dev_op_complete(struct rte_vhost2_dev *vdev, int rc)
{
	vdev->transport->dev_op_cpl(vdev, rc);
}

void
rte_vhost2_dev_call(struct rte_vhost2_dev *vdev, struct rte_vhost2_vq *vq)
{
	vdev->transport->dev_call(vdev, vq);
}

void
vhost_transport_register(struct vhost_transport_ops *transport)
{
	pthread_mutex_lock(&g_vhost_mutex);
	TAILQ_INSERT_TAIL(&g_vhost_transports, transport, tailq);
	pthread_mutex_unlock(&g_vhost_mutex);
}
