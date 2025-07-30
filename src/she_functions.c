// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS  (3000u)

she_err_t she_cmac_test(she_hdl_t mac_hdl, uint32_t key_identifier,
			uint8_t *payload, uint16_t payload_size,
			uint8_t *mac, hsm_op_mac_flags_t flags,
			uint32_t session_hdl)
{
	op_mac_one_go_args_t mac_one_go = {0};
	she_mac_verification_status_t status;
	timer_perf_t t_perf = {0};
	uint32_t i = 0, iter = NUM_OPERATIONS;
	she_err_t err = 0;

	mac_one_go.algorithm = SHE_OP_MAC_ONE_GO_ALGO_CMAC;
	mac_one_go.key_identifier = key_identifier;
	mac_one_go.flags = flags;
	mac_one_go.mac = mac;
	mac_one_go.mac_size = SHE_MAC_SIZE;
	mac_one_go.payload = payload;
	mac_one_go.payload_size = payload_size;

	t_perf.session_hdl = session_hdl;
	for (i = 0; i < iter; i++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = she_mac_one_go(mac_hdl, &mac_one_go, &status);
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

she_err_t key_update_test(she_hdl_t utils_handle)
{
	she_err_t err = 0;
	op_key_update_ext_args_t key_update_args = {0};

	uint8_t m1[SHE_KEY_SIZE_IN_BYTES] = { 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x44};

	uint8_t m2_1[2 * SHE_KEY_SIZE_IN_BYTES] = {0xe0, 0xd0, 0x8b, 0xc3,
		0x17, 0x36, 0x34, 0x5a,
		0x16, 0x78, 0x57, 0x2d,
		0xf7, 0x1f, 0x22, 0xec,
		0x4a, 0xaf, 0x2f, 0xed,
		0xcd, 0x28, 0xa6, 0xfc,
		0xb4, 0xe4, 0x11, 0xd3,
		0x04, 0xb5, 0x53, 0x1f};

	uint8_t m3_1[SHE_KEY_SIZE_IN_BYTES] = {0xf0, 0xe9, 0x29, 0x9c,
		0x43, 0xf9, 0xbe, 0xc6,
		0x0a, 0x83, 0x10, 0xad,
		0xdf, 0x25, 0xba, 0xba};

	uint8_t m2_5[2 * SHE_KEY_SIZE_IN_BYTES] = {0xe0, 0xd0, 0x8b, 0xc3,
		0x17, 0x36, 0x34, 0x5a,
		0x16, 0x78, 0x57, 0x2d,
		0xf7, 0x1f, 0x22, 0xec,
		0x4a, 0xaf, 0x2f, 0xed,
		0xcd, 0x28, 0xa6, 0xfc,
		0xb4, 0xe4, 0x11, 0xd3,
		0x04, 0xb5, 0x53, 0x1f};

	uint8_t m3_5[SHE_KEY_SIZE_IN_BYTES] = {0x87, 0x7b, 0x6b, 0x2f,
		0x90, 0xbb, 0x2d, 0x10,
		0x4b, 0xb5, 0x0e, 0x57,
		0x6c, 0x3a, 0xc3, 0xf7};

	uint8_t m4[2 * SHE_KEY_SIZE_IN_BYTES] = {0};
	uint8_t m5[SHE_KEY_SIZE_IN_BYTES] = {0};

	key_update_args.key_id = SHE_KEY_1;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_1;
	key_update_args.m3 = m3_1;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_1);
	key_update_args.m3_size = sizeof(m3_1);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update_ext(utils_handle, &key_update_args);
	if (err) {
		printf("she_key_update failed err:0x%x\n", err);
		return err;
	}

	m1[15] = 0x88;
	memset(&key_update_args, 0, sizeof(key_update_args));

	key_update_args.key_id = SHE_KEY_5;
	key_update_args.m1 = m1;
	key_update_args.m2 = m2_5;
	key_update_args.m3 = m3_5;
	key_update_args.m4 = m4;
	key_update_args.m5 = m5;
	key_update_args.m1_size = sizeof(m1);
	key_update_args.m2_size = sizeof(m2_5);
	key_update_args.m3_size = sizeof(m3_5);
	key_update_args.m4_size = sizeof(m4);
	key_update_args.m5_size = sizeof(m5);

	err = she_key_update_ext(utils_handle, &key_update_args);
	if (err)
		printf("she_key_update failed err:0x%x\n", err);
	return err;
}
