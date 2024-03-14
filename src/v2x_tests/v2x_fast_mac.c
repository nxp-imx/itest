// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS 3000

void key_update_test(she_hdl_t utils_handle)
{
	op_key_update_args_t key_update_args = {0};

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

	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_KEY_1 | key_update_args.key_ext;
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

	ASSERT_EQUAL(she_key_update(utils_handle, &key_update_args),
		     SHE_NO_ERROR);

	m1[15] = 0x88;
	memset(&key_update_args, 0, sizeof(key_update_args));

	key_update_args.key_ext = 0x00;
	key_update_args.key_id = SHE_KEY_5 | key_update_args.key_ext;
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

	ASSERT_EQUAL(she_key_update(utils_handle, &key_update_args),
		     SHE_NO_ERROR);
}

int v2x_fast_mac(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	op_open_utils_args_t utils_args = {'\0'};
	she_hdl_t she_session_hdl, key_store_hdl;
	she_err_t err, key_store_load = 0;
	op_generate_mac_t generate_mac_args = {0};
	op_verify_mac_t verify_mac_args = {0};
	uint8_t mac[SHE_MAC_SIZE] = {0}, message[SHE_MAC_SIZE];
	uint32_t i, iter = NUM_OPERATIONS;
	timer_perf_t t_perf;

	// Randomizing input message
	ASSERT_EQUAL(randomize(message, sizeof(message)), sizeof(message));

	open_session_args.mu_type = MU_CHANNEL_PLAT_SHE;
	// SHE OPEN SESSION
	ASSERT_EQUAL(she_open_session(&open_session_args, &she_session_hdl),
		     SHE_NO_ERROR);

	key_store_args.key_store_identifier = 0x0;
	key_store_args.authentication_nonce = 0xbec00001;
	key_store_args.max_updates_number = 300;
	key_store_args.flags = KEY_STORE_OPEN_FLAGS_CREATE |
			       KEY_STORE_OPEN_FLAGS_SHE |
			       KEY_STORE_OPEN_FLAGS_STRICT_OPERATION;
	key_store_args.min_mac_length = 0x0;

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
			she_close_session(she_session_hdl);
			ASSERT_FALSE(err);
		}
	}

	key_store_hdl = key_store_args.key_store_hdl;

	// SHE OPEN UTILS
	ASSERT_EQUAL(she_open_utils(key_store_hdl, &utils_args), SHE_NO_ERROR);

	// SHE KEY UPDATE
	if (!key_store_load)
		key_update_test(utils_args.utils_handle);

	// MAC GENERATION

	ITEST_LOG("FAST MAC generation for 1s on %d byte blocks: ",
		  sizeof(message));
	generate_mac_args.key_ext = 0x00;
	generate_mac_args.key_id = SHE_KEY_5 | generate_mac_args.key_ext;
	generate_mac_args.mac = mac;
	generate_mac_args.message = message;
	generate_mac_args.message_length = sizeof(message);

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = she_session_hdl;
	for (i = 0U; i < iter; i++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = she_generate_mac(utils_args.utils_handle,
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

	ITEST_LOG("FAST MAC verification for 1s on %d byte blocks: ",
		  sizeof(message));
	verify_mac_args.key_ext = 0x00;
	verify_mac_args.key_id = SHE_KEY_1 | verify_mac_args.key_ext;
	verify_mac_args.mac = mac;
	verify_mac_args.mac_length = SHE_MAC_SIZE;
	verify_mac_args.message = message;
	verify_mac_args.message_length = sizeof(message);
	verify_mac_args.mac_length_encoding = MAC_BYTES_LENGTH;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = she_session_hdl;
	for (i = 0U; i < iter; i++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = she_verify_mac(utils_args.utils_handle,
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

out:
	ASSERT_EQUAL(she_close_utils(utils_args.utils_handle), SHE_NO_ERROR);
	she_close_key_store_service(key_store_hdl);
	ASSERT_EQUAL(she_close_session(she_session_hdl), SHE_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
