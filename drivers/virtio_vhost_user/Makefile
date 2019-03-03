# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2019 Arrikto Inc.

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_virtio_vhost_user.a

EXPORT_MAP := rte_virtio_vhost_user_version.map

LIBABIVER := 1

CFLAGS += $(WERROR_FLAGS) -O3
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_pci -lrte_vhost

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_VHOST) := trans_virtio_vhost_user.c \
				   virtio_pci.c

include $(RTE_SDK)/mk/rte.lib.mk
