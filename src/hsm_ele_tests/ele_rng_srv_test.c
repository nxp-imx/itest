// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
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

	hsm_hdl_t hsm_session_hdl;

	// ELE OPEN SESSION
	args.session_priority = 0;
	args.operating_mode = 0;
	ASSERT_EQUAL(hsm_open_session(&args, &hsm_session_hdl), HSM_NO_ERROR);

	// GET RANDOM Mu SV/SG
	rng_get_random_args.output = rng_out_buff;
	rng_get_random_args.random_size = RANDOM_SIZE;
	ASSERT_EQUAL(hsm_get_random(hsm_session_hdl, &rng_get_random_args),
		     HSM_NO_ERROR);

	// ELE CLOSE SESSION
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	return TRUE_TEST;
}




