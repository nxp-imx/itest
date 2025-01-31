// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS  (2000u)

hsm_err_t cipher_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		      uint8_t *input, uint8_t *output, uint32_t block_size,
		      uint8_t *iv, uint16_t iv_size,
		      hsm_op_cipher_one_go_algo_t algo,
		      hsm_op_cipher_one_go_flags_t flags, uint32_t session_hdl)
{
	op_cipher_one_go_args_t cipher_args = {0};
	uint32_t j, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};
	hsm_err_t err = 0;

	cipher_args.key_identifier = key_identifier;
	cipher_args.iv = iv;
	cipher_args.iv_size = iv_size;
	cipher_args.cipher_algo = algo;
	cipher_args.flags = flags;
	cipher_args.input = input;
	cipher_args.output = output;
	cipher_args.input_size = block_size;
	cipher_args.output_size = block_size;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (j = 0; j < iter; j++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_cipher_one_go(cipher_hdl, &cipher_args);
		if (err)
			return err;
		/* Stop the timer */
		stop_timer(&t_perf);
	}
	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);

	return err;
}
