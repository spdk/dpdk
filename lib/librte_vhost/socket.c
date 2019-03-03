/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <pthread.h>

#include <rte_log.h>

#include "fd_man.h"
#include "vhost.h"
#include "vhost_user.h"

struct vhost_user vhost_user = {
	.fdset = {
		.fd = { [0 ... MAX_FDS - 1] = {-1, NULL, NULL, NULL, 0} },
		.fd_mutex = PTHREAD_MUTEX_INITIALIZER,
		.fd_pooling_mutex = PTHREAD_MUTEX_INITIALIZER,
		.num = 0
	},
	.vsocket_cnt = 0,
	.mutex = PTHREAD_MUTEX_INITIALIZER,
};

static struct vhost_user_socket *
find_vhost_user_socket(const char *path)
{
	int i;

	for (i = 0; i < vhost_user.vsocket_cnt; i++) {
		struct vhost_user_socket *vsocket = vhost_user.vsockets[i];

		if (!strcmp(vsocket->path, path))
			return vsocket;
	}

	return NULL;
}

int
rte_vhost_driver_attach_vdpa_device(const char *path, int did)
{
	struct vhost_user_socket *vsocket;

	if (rte_vdpa_get_device(did) == NULL)
		return -1;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		vsocket->vdpa_dev_id = did;
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_detach_vdpa_device(const char *path)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		vsocket->vdpa_dev_id = -1;
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_get_vdpa_device_id(const char *path)
{
	struct vhost_user_socket *vsocket;
	int did = -1;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		did = vsocket->vdpa_dev_id;
	pthread_mutex_unlock(&vhost_user.mutex);

	return did;
}

int
rte_vhost_driver_disable_features(const char *path, uint64_t features)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);

	/* Note that use_builtin_virtio_net is not affected by this function
	 * since callers may want to selectively disable features of the
	 * built-in vhost net device backend.
	 */

	if (vsocket)
		vsocket->features &= ~features;
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_enable_features(const char *path, uint64_t features)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket) {
		if ((vsocket->supported_features & features) != features) {
			/*
			 * trying to enable features the driver doesn't
			 * support.
			 */
			pthread_mutex_unlock(&vhost_user.mutex);
			return -1;
		}
		vsocket->features |= features;
	}
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_set_features(const char *path, uint64_t features)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket) {
		vsocket->supported_features = features;
		vsocket->features = features;

		/* Anyone setting feature bits is implementing their own vhost
		 * device backend.
		 */
		vsocket->use_builtin_virtio_net = false;
	}
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_get_features(const char *path, uint64_t *features)
{
	struct vhost_user_socket *vsocket;
	uint64_t vdpa_features;
	struct rte_vdpa_device *vdpa_dev;
	int did = -1;
	int ret = 0;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (!vsocket) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"socket file %s is not registered yet.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	did = vsocket->vdpa_dev_id;
	vdpa_dev = rte_vdpa_get_device(did);
	if (!vdpa_dev || !vdpa_dev->ops->get_features) {
		*features = vsocket->features;
		goto unlock_exit;
	}

	if (vdpa_dev->ops->get_features(did, &vdpa_features) < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
				"failed to get vdpa features "
				"for socket file %s.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	*features = vsocket->features & vdpa_features;

unlock_exit:
	pthread_mutex_unlock(&vhost_user.mutex);
	return ret;
}

int
rte_vhost_driver_set_protocol_features(const char *path,
		uint64_t protocol_features)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		vsocket->protocol_features = protocol_features;
	pthread_mutex_unlock(&vhost_user.mutex);
	return vsocket ? 0 : -1;
}

int
rte_vhost_driver_get_protocol_features(const char *path,
		uint64_t *protocol_features)
{
	struct vhost_user_socket *vsocket;
	uint64_t vdpa_protocol_features;
	struct rte_vdpa_device *vdpa_dev;
	int did = -1;
	int ret = 0;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (!vsocket) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"socket file %s is not registered yet.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	did = vsocket->vdpa_dev_id;
	vdpa_dev = rte_vdpa_get_device(did);
	if (!vdpa_dev || !vdpa_dev->ops->get_protocol_features) {
		*protocol_features = vsocket->protocol_features;
		goto unlock_exit;
	}

	if (vdpa_dev->ops->get_protocol_features(did,
				&vdpa_protocol_features) < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
				"failed to get vdpa protocol features "
				"for socket file %s.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	*protocol_features = vsocket->protocol_features
		& vdpa_protocol_features;

unlock_exit:
	pthread_mutex_unlock(&vhost_user.mutex);
	return ret;
}

int
rte_vhost_driver_get_queue_num(const char *path, uint32_t *queue_num)
{
	struct vhost_user_socket *vsocket;
	uint32_t vdpa_queue_num;
	struct rte_vdpa_device *vdpa_dev;
	int did = -1;
	int ret = 0;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (!vsocket) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"socket file %s is not registered yet.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	did = vsocket->vdpa_dev_id;
	vdpa_dev = rte_vdpa_get_device(did);
	if (!vdpa_dev || !vdpa_dev->ops->get_queue_num) {
		*queue_num = VHOST_MAX_QUEUE_PAIRS;
		goto unlock_exit;
	}

	if (vdpa_dev->ops->get_queue_num(did, &vdpa_queue_num) < 0) {
		RTE_LOG(ERR, VHOST_CONFIG,
				"failed to get vdpa queue number "
				"for socket file %s.\n", path);
		ret = -1;
		goto unlock_exit;
	}

	*queue_num = RTE_MIN((uint32_t)VHOST_MAX_QUEUE_PAIRS, vdpa_queue_num);

unlock_exit:
	pthread_mutex_unlock(&vhost_user.mutex);
	return ret;
}

static void
vhost_user_socket_mem_free(struct vhost_user_socket *vsocket)
{
	if (vsocket && vsocket->path) {
		free(vsocket->path);
		vsocket->path = NULL;
	}

	if (vsocket) {
		free(vsocket);
		vsocket = NULL;
	}
}

/*
 * Register a new vhost-user socket; here we could act as server
 * (the default case), or client (when RTE_VHOST_USER_CLIENT) flag
 * is set.
 */
int
rte_vhost_driver_register(const char *path, uint64_t flags)
{
	int ret = -1;
	struct vhost_user_socket *vsocket;
	const struct vhost_transport_ops *trans_ops = &af_unix_trans_ops;

	if (!path)
		return -1;

	pthread_mutex_lock(&vhost_user.mutex);

	if (vhost_user.vsocket_cnt == MAX_VHOST_SOCKET) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"error: the number of vhost sockets reaches maximum\n");
		goto out;
	}

	vsocket = malloc(trans_ops->socket_size);
	if (!vsocket)
		goto out;
	memset(vsocket, 0, trans_ops->socket_size);
	vsocket->trans_ops = trans_ops;
	vsocket->path = strdup(path);
	if (vsocket->path == NULL) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"error: failed to copy socket path string\n");
		vhost_user_socket_mem_free(vsocket);
		goto out;
	}
	TAILQ_INIT(&vsocket->conn_list);
	ret = pthread_mutex_init(&vsocket->conn_mutex, NULL);
	if (ret) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"error: failed to init connection mutex\n");
		goto out_free;
	}
	vsocket->dequeue_zero_copy = flags & RTE_VHOST_USER_DEQUEUE_ZERO_COPY;

	/*
	 * Set the supported features correctly for the builtin vhost-user
	 * net driver.
	 *
	 * Applications know nothing about features the builtin virtio net
	 * driver (virtio_net.c) supports, thus it's not possible for them
	 * to invoke rte_vhost_driver_set_features(). To workaround it, here
	 * we set it unconditionally. If the application want to implement
	 * another vhost-user driver (say SCSI), it should call the
	 * rte_vhost_driver_set_features(), which will overwrite following
	 * two values.
	 */
	vsocket->use_builtin_virtio_net = true;
	vsocket->supported_features = VIRTIO_NET_SUPPORTED_FEATURES;
	vsocket->features           = VIRTIO_NET_SUPPORTED_FEATURES;
	vsocket->protocol_features  = VHOST_USER_PROTOCOL_FEATURES;

	/*
	 * Dequeue zero copy can't assure descriptors returned in order.
	 * Also, it requires that the guest memory is populated, which is
	 * not compatible with postcopy.
	 */
	if (vsocket->dequeue_zero_copy) {
		vsocket->supported_features &= ~(1ULL << VIRTIO_F_IN_ORDER);
		vsocket->features &= ~(1ULL << VIRTIO_F_IN_ORDER);

		RTE_LOG(INFO, VHOST_CONFIG,
			"Dequeue zero copy requested, disabling postcopy support\n");
		vsocket->protocol_features &=
			~(1ULL << VHOST_USER_PROTOCOL_F_PAGEFAULT);
	}

	if (!(flags & RTE_VHOST_USER_IOMMU_SUPPORT)) {
		vsocket->supported_features &= ~(1ULL << VIRTIO_F_IOMMU_PLATFORM);
		vsocket->features &= ~(1ULL << VIRTIO_F_IOMMU_PLATFORM);
	}

	if (!(flags & RTE_VHOST_USER_POSTCOPY_SUPPORT)) {
		vsocket->protocol_features &=
			~(1ULL << VHOST_USER_PROTOCOL_F_PAGEFAULT);
	} else {
#ifndef RTE_LIBRTE_VHOST_POSTCOPY
		RTE_LOG(ERR, VHOST_CONFIG,
			"Postcopy requested but not compiled\n");
		ret = -1;
		goto out_mutex;
#endif
	}

	if ((flags & RTE_VHOST_USER_CLIENT) != 0) {
		vsocket->reconnect = !(flags & RTE_VHOST_USER_NO_RECONNECT);
		if (vsocket->reconnect && reconn_tid == 0) {
			if (vhost_user_reconnect_init() != 0)
				goto out_mutex;
		}
	} else {
		vsocket->is_server = true;
	}
	ret = trans_ops->socket_init(vsocket, flags);
	if (ret < 0) {
		goto out_mutex;
	}

	vhost_user.vsockets[vhost_user.vsocket_cnt++] = vsocket;

	pthread_mutex_unlock(&vhost_user.mutex);
	return ret;

out_mutex:
	if (pthread_mutex_destroy(&vsocket->conn_mutex)) {
		RTE_LOG(ERR, VHOST_CONFIG,
			"error: failed to destroy connection mutex\n");
	}
out_free:
	vhost_user_socket_mem_free(vsocket);
out:
	pthread_mutex_unlock(&vhost_user.mutex);

	return ret;
}

/**
 * Unregister the specified vhost socket
 */
int
rte_vhost_driver_unregister(const char *path)
{
	int i;
	int count;
	struct vhost_user_connection *conn, *next;

again:
	pthread_mutex_lock(&vhost_user.mutex);

	for (i = 0; i < vhost_user.vsocket_cnt; i++) {
		struct vhost_user_socket *vsocket = vhost_user.vsockets[i];

		if (!strcmp(vsocket->path, path)) {
			pthread_mutex_lock(&vsocket->conn_mutex);
			for (conn = TAILQ_FIRST(&vsocket->conn_list);
			     conn != NULL;
			     conn = next) {
				next = TAILQ_NEXT(conn, next);

				/*
				 * If r/wcb is executing, release the
				 * conn_mutex lock, and try again since
				 * the r/wcb may use the conn_mutex lock.
				 */
				if (fdset_try_del(&vhost_user.fdset,
						  conn->connfd) == -1) {
					pthread_mutex_unlock(
							&vsocket->conn_mutex);
					pthread_mutex_unlock(&vhost_user.mutex);
					goto again;
				}

				RTE_LOG(INFO, VHOST_CONFIG,
					"free connfd = %d for device '%s'\n",
					conn->connfd, path);
				close(conn->connfd);
				vhost_destroy_device(conn->vid);
				TAILQ_REMOVE(&vsocket->conn_list, conn, next);
				free(conn);
			}
			pthread_mutex_unlock(&vsocket->conn_mutex);

			vsocket->trans_ops->socket_cleanup(vsocket);

			pthread_mutex_destroy(&vsocket->conn_mutex);
			vhost_user_socket_mem_free(vsocket);

			count = --vhost_user.vsocket_cnt;
			vhost_user.vsockets[i] = vhost_user.vsockets[count];
			vhost_user.vsockets[count] = NULL;
			pthread_mutex_unlock(&vhost_user.mutex);

			return 0;
		}
	}
	pthread_mutex_unlock(&vhost_user.mutex);

	return -1;
}

/*
 * Register ops so that we can add/remove device to data core.
 */
int
rte_vhost_driver_callback_register(const char *path,
	struct vhost_device_ops const * const ops)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	if (vsocket)
		vsocket->notify_ops = ops;
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? 0 : -1;
}

struct vhost_device_ops const *
vhost_driver_callback_get(const char *path)
{
	struct vhost_user_socket *vsocket;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	pthread_mutex_unlock(&vhost_user.mutex);

	return vsocket ? vsocket->notify_ops : NULL;
}

int
rte_vhost_driver_start(const char *path)
{
	struct vhost_user_socket *vsocket;
	static pthread_t fdset_tid;

	pthread_mutex_lock(&vhost_user.mutex);
	vsocket = find_vhost_user_socket(path);
	pthread_mutex_unlock(&vhost_user.mutex);

	if (!vsocket)
		return -1;

	if (fdset_tid == 0) {
		/**
		 * create a pipe which will be waited by poll and notified to
		 * rebuild the wait list of poll.
		 */
		if (fdset_pipe_init(&vhost_user.fdset) < 0) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"failed to create pipe for vhost fdset\n");
			return -1;
		}

		int ret = rte_ctrl_thread_create(&fdset_tid,
			"vhost-events", NULL, fdset_event_dispatch,
			&vhost_user.fdset);
		if (ret != 0) {
			RTE_LOG(ERR, VHOST_CONFIG,
				"failed to create fdset handling thread");

			fdset_pipe_uninit(&vhost_user.fdset);
			return -1;
		}
	}

	return vsocket->trans_ops->socket_start(vsocket);
}
