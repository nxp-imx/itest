// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS	(3000u)
#define MAC_SIZE	16
#define MAX_PAYLOAD_SIZE 2048
#define NUM_PAYLOAD_SIZE 5

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

int v2x_cmac(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	op_open_utils_args_t utils_args = {0};
	open_svc_mac_args_t mac_args = {0};
	she_err_t err = 0, key_store_load = 0;
	uint8_t mac[SHE_MAC_SIZE] = {0};
	uint8_t message[MAX_PAYLOAD_SIZE] = {0};
	uint32_t payload_size[] = {16, 64, 256, 1024, 2048};
	uint8_t num_payload = NUM_PAYLOAD_SIZE;

	/* Since 2k message size not supported on IMX8DXL */
	if (soc == SOC_IMX8DXL)
		num_payload -= 1;

	ASSERT_EQUAL(randomize(message, sizeof(message)), sizeof(message));

	open_session_args.mu_type = V2X_SHE; // Use SHE1 to run on seco MU

	// SHE OPEN SESSION
	ASSERT_EQUAL(she_open_session(&open_session_args, &she_session_hdl),
		     SHE_NO_ERROR);

	key_store_args.key_store_identifier = 0x1;
	key_store_args.authentication_nonce = 0xbec00001;
	key_store_args.max_updates_number = 300;
	key_store_args.flags = KEY_STORE_OPEN_FLAGS_CREATE |
			       KEY_STORE_OPEN_FLAGS_SHE |
			       KEY_STORE_OPEN_FLAGS_STRICT_OPERATION |
			       KEY_STORE_OPEN_FLAGS_SET_MAC_LEN;
	key_store_args.min_mac_length = 32;
	key_store_args.max_updates_number   = 300;


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

	ASSERT_EQUAL(she_open_mac_service(key_store_hdl, &mac_args), SHE_NO_ERROR);

	// SHE KEY UPDATE
	if (!key_store_load)
		key_update_test(utils_args.utils_handle);

	for (int i = 0; i < num_payload; i++) {
		ITEST_LOG("CMAC aes 128 generation for 1s on %d byte blocks: ",	payload_size[i]);
		err = she_cmac_test(mac_args.mac_serv_hdl, SHE_KEY_5, message,
				    payload_size[i], mac,
				    MAC_OP_FLAGS_MAC_GENERATION,
				    she_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("CMAC aes 128 verification for 1s on %d byte blocks: ", payload_size[i]);
		err = she_cmac_test(mac_args.mac_serv_hdl, SHE_KEY_5, message,
				    payload_size[i], mac,
				    MAC_OP_FLAGS_MAC_VERIFICATION,
				    she_session_hdl);
		if (err)
			goto out;
	}
out:
	ASSERT_EQUAL(she_close_mac_service(mac_args.mac_serv_hdl), SHE_NO_ERROR);
	ASSERT_EQUAL(she_close_utils(utils_args.utils_handle), SHE_NO_ERROR);
	ASSERT_EQUAL(she_close_key_store_service(key_store_hdl), SHE_NO_ERROR);
	ASSERT_EQUAL(she_close_session(she_session_hdl), SHE_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
