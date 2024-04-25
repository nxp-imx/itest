// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS  (1000u)

#define MAX_BUFF_SZ 16384
#define NUM_BUFF_SZ 6

int ele_rng_perf(void)
{
	uint32_t buff_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint8_t rng_out_buff[MAX_BUFF_SZ] = {0};
	open_session_args_t args = {0};
	op_get_random_args_t rng_get_random_args = {0};
	uint32_t i, j, iter = NUM_OPERATIONS;
	timer_perf_t t_perf;
	hsm_err_t err;
	hsm_hdl_t hsm_session_hdl;

	// ELE OPEN SESSION
	args.mu_type = HSM1;
	ASSERT_EQUAL(hsm_open_session(&args, &hsm_session_hdl), HSM_NO_ERROR);

	// GET RANDOM Mu SV/SG
	rng_get_random_args.output = rng_out_buff;

	for (i = 0; i < NUM_BUFF_SZ; i++) {
		ITEST_LOG("Generating %d byte random number for 1s: ", buff_size[i]);
		rng_get_random_args.random_size = buff_size[i];

		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = hsm_session_hdl;
		for (j = 0; j < iter; j++) {
			/* Start the timer */
			start_timer(&t_perf);
			err = hsm_get_random(hsm_session_hdl,
					     &rng_get_random_args);
			if (err)
				goto out;
			/* Stop the timer */
			stop_timer(&t_perf);
		}
		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		print_perf(&t_perf, iter);
	}

out:
	// ELE CLOSE SESSION
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
