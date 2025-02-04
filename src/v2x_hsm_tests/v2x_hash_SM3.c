// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS 1000

#define MAX_DGST_SIZE 0x40
#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6
#define dgst_size 0x20

int v2x_hash_SM3(void)
{
	open_session_args_t open_session_args = {0};
	hsm_hdl_t hash_serv = 0;
	timer_perf_t t_perf = {0};
	open_svc_hash_args_t hash_srv_args = {0};
	op_hash_one_go_args_t hash_args = {0};
	uint8_t dgst_in_buff[MAX_MSG_SIZE] = {0};
	uint8_t dgst_out_buff[MAX_DGST_SIZE] = {0};
	uint32_t block_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint32_t size_input = 0, num_msg_size = NUM_MSG_SIZE;
	uint32_t j = 0, k = 0, iter = NUM_OPERATIONS;
	hsm_err_t err = 0;

	open_session_args.mu_type = V2X_SV0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args,
				      &hsm_session_hdl),
		     HSM_NO_ERROR);

	/* set number of nessage sizes based on soc */
	if (soc != SOC_IMX8DXL)
		num_msg_size = NUM_MSG_SIZE - 2;

	ASSERT_EQUAL(hsm_open_hash_service(hsm_session_hdl, &hash_srv_args,
					   &hash_serv),
		     HSM_NO_ERROR);

	for (k = 0; k < num_msg_size; k++) {
		size_input = block_size[k];
		ITEST_LOG("Doing SM3_256 for 1s on %d byte block: ",
			  size_input);
		// GEN HASH Mu SV0
		hash_args.input = dgst_in_buff;
		hash_args.output = dgst_out_buff;
		hash_args.input_size = size_input;
		hash_args.output_size = dgst_size;
		hash_args.algo = HSM_HASH_ALGO_SM3_256;
		hash_args.svc_flags = HSM_HASH_FLAG_ONE_SHOT;

		// INPUT BUFF AS RANDOM
		ASSERT_EQUAL(randomize(dgst_in_buff, size_input),
			     size_input);

		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = hsm_session_hdl;
		for (j = 0; j < iter; j++) {
			/* Start the timer */
			start_timer(&t_perf);
			err = hsm_hash_one_go(hash_serv,
					      &hash_args);
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
	ASSERT_EQUAL(hsm_close_hash_service(hash_serv), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
