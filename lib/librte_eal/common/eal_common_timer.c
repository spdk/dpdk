/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_compat.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_pause.h>
#include <rte_eal.h>

#include "eal_private.h"

#define EAL_TIMER_MP "eal_timer_mp_sync"

struct timer_mp_param {
	uint64_t tsc;
};

/* The frequency of the RDTSC timer resolution */
static uint64_t eal_tsc_resolution_hz;

/* Pointer to user delay function */
void (*rte_delay_us)(unsigned int) = NULL;

void
rte_delay_us_block(unsigned int us)
{
	const uint64_t start = rte_get_timer_cycles();
	const uint64_t ticks = (uint64_t)us * rte_get_timer_hz() / 1E6;
	while ((rte_get_timer_cycles() - start) < ticks)
		rte_pause();
}

void __rte_experimental
rte_delay_us_sleep(unsigned int us)
{
	struct timespec wait[2];
	int ind = 0;

	wait[0].tv_sec = 0;
	if (us >= US_PER_S) {
		wait[0].tv_sec = us / US_PER_S;
		us -= wait[0].tv_sec * US_PER_S;
	}
	wait[0].tv_nsec = 1000 * us;

	while (nanosleep(&wait[ind], &wait[1 - ind]) && errno == EINTR) {
		/*
		 * Sleep was interrupted. Flip the index, so the 'remainder'
		 * will become the 'request' for a next call.
		 */
		ind = 1 - ind;
	}
}

uint64_t
rte_get_tsc_hz(void)
{
	return eal_tsc_resolution_hz;
}

static uint64_t
estimate_tsc_freq(void)
{
#define CYC_PER_10MHZ 1E7
	RTE_LOG(WARNING, EAL, "WARNING: TSC frequency estimated roughly"
		" - clock timings may be less accurate.\n");
	/* assume that the sleep(1) will sleep for 1 second */
	uint64_t start = rte_rdtsc();
	sleep(1);
	/* Round up to 10Mhz. 1E7 ~ 10Mhz */
	return RTE_ALIGN_MUL_NEAR(rte_rdtsc() - start, CYC_PER_10MHZ);
}

static void
set_tsc_freq_primary(void)
{
	uint64_t freq;

	freq = get_tsc_freq_arch();
	if (!freq)
		freq = get_tsc_freq();
	if (!freq)
		freq = estimate_tsc_freq();

	RTE_LOG(DEBUG, EAL, "TSC frequency is ~%" PRIu64 " KHz\n", freq / 1000);
	eal_tsc_resolution_hz = freq;
}

static void
set_tsc_freq_secondary(void)
{
	struct rte_mp_msg mp_req;
	struct rte_mp_reply mp_reply;
	struct timer_mp_param *r;
	struct timespec ts = {.tv_sec = 1, .tv_nsec = 0};

	memset(&mp_req, 0, sizeof(mp_req));
	strcpy(mp_req.name, EAL_TIMER_MP);
	if (rte_mp_request_sync(&mp_req, &mp_reply, &ts) || mp_reply.nb_received != 1) {
		/* We weren't able to get the tsc hz from the primary process.  So we will
		 * just calculate it here in the secondary process instead.
		 */
		set_tsc_freq_primary();
		return;
	}

	r = (struct timer_mp_param *)mp_reply.msgs[0].param;
	eal_tsc_resolution_hz = r->tsc;
	free(mp_reply.msgs);
}

static int
timer_mp_primary(__attribute__((unused)) const struct rte_mp_msg *msg, const void *peer)
{
	struct rte_mp_msg reply;
	struct timer_mp_param *r = (struct timer_mp_param *)reply.param;

	memset(&reply, 0, sizeof(reply));
	r->tsc = eal_tsc_resolution_hz;
	strcpy(reply.name, EAL_TIMER_MP);
	reply.len_param = sizeof(*r);

	return rte_mp_reply(&reply, peer);
}

void
set_tsc_freq(void)
{
	int rc;

	/* We use a 100ms timer to calculate the TSC hz.  We can save this 100ms in
	 * secondary processes, by getting the TSC hz from the primary process.
	 * So register an mp_action callback in the primary process, which secondary
	 * processes will use to get the TSC hz.
	 */
	if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
		set_tsc_freq_primary();
		rc = rte_mp_action_register(EAL_TIMER_MP, timer_mp_primary);
		if (rc) {
			RTE_LOG(WARNING, EAL, "Could not register mp_action - secondary "
				" processes will calculate TSC independently.\n");
		}
	} else {
		set_tsc_freq_secondary();
	}
}

void rte_delay_us_callback_register(void (*userfunc)(unsigned int))
{
	rte_delay_us = userfunc;
}

RTE_INIT(rte_timer_init)
{
	/* set rte_delay_us_block as a delay function */
	rte_delay_us_callback_register(rte_delay_us_block);
}
