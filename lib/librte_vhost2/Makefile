# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2010-2014 Intel Corporation

include $(RTE_SDK)/mk/rte.vars.mk

# library name
LIB = librte_vhost2.a

EXPORT_MAP := rte_vhost2_version.map

LIBABIVER := 1

CFLAGS += -DALLOW_EXPERIMENTAL_API -Wno-error=nested-externs
CFLAGS += $(WERROR_FLAGS) -I$(SRCDIR) -O0 -g3 -D_FILE_OFFSET_BITS=64
LDLIBS += -lpthread

ifeq ($(CONFIG_RTE_LIBRTE_VHOST_NUMA),y)
LDLIBS += -lnuma
endif
LDLIBS += -lrte_eal -lrte_mempool

# all source are stored in SRCS-y
SRCS-$(CONFIG_RTE_LIBRTE_VHOST) := transport.c vhost.c

# install includes
SYMLINK-$(CONFIG_RTE_LIBRTE_VHOST)-include += rte_vhost2.h

include $(RTE_SDK)/mk/rte.lib.mk
