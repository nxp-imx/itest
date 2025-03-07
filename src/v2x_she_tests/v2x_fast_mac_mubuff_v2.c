// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS 3000

#define MAX_MSG_SIZE 240
#define NUM_MSG_SIZE 3

int v2x_fast_mac_mubuff_v2(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	op_open_utils_args_t utils_args = {0};
	she_err_t err = 0, key_store_load = 0;
	op_generate_mac_t generate_mac_args = {0};
	op_verify_mac_t verify_mac_args = {0};
	uint8_t mac[SHE_MAC_SIZE] = {0}, message[MAX_MSG_SIZE] = {0};
	uint32_t msg_size[] = {16, 64, 240};
	uint32_t i = 0, j = 0, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};

	// Randomizing input message
	ASSERT_EQUAL(randomize(message, MAX_MSG_SIZE), MAX_MSG_SIZE);

	open_session_args.mu_type = V2X_SHE; // Use SHE1 to run on seco MU
	// SHE OPEN SESSION
	ASSERT_EQUAL(she_open_session(&open_session_args, &she_session_hdl),
		     SHE_NO_ERROR);

	/* Support for only single keystore on i.MX8DXL, whereas 5 on i.MX95 */
	key_store_args.key_store_identifier = 0x1;
	key_store_args.authentication_nonce = 0xbec00001;
	key_store_args.max_updates_number = 300;
	key_store_args.flags = KEY_STORE_OPEN_FLAGS_CREATE |
			       KEY_STORE_OPEN_FLAGS_SHE |
			       KEY_STORE_OPEN_FLAGS_STRICT_OPERATION;
	key_store_args.min_mac_length = 32;

	// SHE OPEN KEY STORE
	err = she_open_key_store_service(she_session_hdl,
					 &key_store_args);

	if (err != SHE_NO_ERROR) {
		if (err == SHE_KEY_STORE_CONFLICT || err == SHE_ID_CONFLICT) {
			key_store_args.flags = KEY_STORE_OPEN_FLAGS_SHE;
			err = she_open_key_store_service(she_session_hdl,
							 &key_store_args);
			ASSERT_EQUAL(err, SHE_NO_ERROR);
			key_store_load = 1;
		} else {
			ASSERT_EQUAL(she_close_session(she_session_hdl),
				     SHE_NO_ERROR);
			ASSERT_FALSE(err);
		}
	}

	key_store_hdl = key_store_args.key_store_hdl;

	// SHE OPEN UTILS
	ASSERT_EQUAL(she_open_utils(key_store_hdl, &utils_args), SHE_NO_ERROR);

	// SHE KEY UPDATE
	if (!key_store_load)
		key_update_test(utils_args.utils_handle);

	for (j = 0; j < NUM_MSG_SIZE; j++) {
		// MAC GENERATION
		ITEST_LOG("FAST MAC V2 generation for 1s on %d byte blocks: ",
			  msg_size[j]);
		generate_mac_args.key_ext = 0x00;
		generate_mac_args.key_id = SHE_KEY_5;
		generate_mac_args.mac = mac;
		generate_mac_args.message = message;
		generate_mac_args.message_length = msg_size[j];

		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = she_session_hdl;
		for (i = 0U; i < iter; i++) {
			/* Start the timer */
			start_timer(&t_perf);
			err = she_generate_fast_mac_mubuff_v2(utils_args.utils_handle,
							      &generate_mac_args);
			if (err)
				goto out;
			/* Stop the timer */
			stop_timer(&t_perf);
		}
		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		print_perf(&t_perf, iter);

		// MAC VERIFICATION
		ITEST_LOG("FAST MAC V2 verification for 1s on %d byte blocks: ",
			  msg_size[j]);
		verify_mac_args.key_ext = 0x00;
		verify_mac_args.key_id = SHE_KEY_1;
		verify_mac_args.mac = mac;
		verify_mac_args.mac_length = SHE_MAC_SIZE;
		verify_mac_args.message = message;
		verify_mac_args.message_length = msg_size[j];
		verify_mac_args.mac_length_encoding = MAC_BYTES_LENGTH;

		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = she_session_hdl;
		for (i = 0U; i < iter; i++) {
			/* Start the timer */
			start_timer(&t_perf);
			err = she_verify_fast_mac_mubuff_v2(utils_args.utils_handle,
							    &verify_mac_args);
			if (err)
				goto out;
			/* Stop the timer */
			stop_timer(&t_perf);
		}
		/* Finalize time to get stats */
		finalize_timer(&t_perf, iter);
		print_perf(&t_perf, iter);

		ASSERT_EQUAL(verify_mac_args.verification_status,
			     SHE_MAC_VERIFICATION_SUCCESS);
	}
out:
	ASSERT_EQUAL(she_close_utils(utils_args.utils_handle), SHE_NO_ERROR);
	she_close_key_store_service(key_store_hdl);
	ASSERT_EQUAL(she_close_session(she_session_hdl), SHE_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
