// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define RANDOM_SIZE 2050

int ele_rng_srv_001(void)
{
	uint8_t rng_out_buff[4096] = {0};
	open_session_args_t args = {0};
	op_get_random_args_t rng_get_random_args = {0};
	hsm_err_t err = 0;

	// ELE OPEN SESSION
	args.mu_type = HSM1;
	err = hsm_open_session(&args, &hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		goto out;
	}

	// GET RANDOM Mu SV/SG
	rng_get_random_args.output = rng_out_buff;
	rng_get_random_args.random_size = RANDOM_SIZE;
	err = hsm_get_random(hsm_session_hdl, &rng_get_random_args);

out:
	hsm_close_session(hsm_session_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
