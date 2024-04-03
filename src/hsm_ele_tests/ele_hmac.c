// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS	(1000u)

#define MAC_KEY_GROUP	50
#define MAX_PAYLOAD_SIZE 16384
#define NUM_PAYLOAD_SIZE 6

hsm_err_t hmac_test(hsm_hdl_t mac_hdl, uint32_t key_identifier,
		    uint8_t *payload, uint32_t payload_size,
		    uint8_t *mac, uint32_t mac_size,
		    hsm_op_mac_one_go_algo_t algorithm,
		    hsm_op_mac_one_go_flags_t flags, uint32_t session_hdl)
{
	op_mac_one_go_args_t mac_one_go;
	hsm_mac_verification_status_t mac_status;
	timer_perf_t t_perf;
	uint32_t i, iter = NUM_OPERATIONS;
	hsm_err_t err;

	mac_one_go.key_identifier = key_identifier;
	mac_one_go.algorithm = algorithm;
	mac_one_go.flags = flags;
	mac_one_go.payload = payload;
	mac_one_go.mac = mac;
	mac_one_go.payload_size = payload_size;
	mac_one_go.mac_size = mac_size;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (i = 0U; i < iter; i++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_mac_one_go(mac_hdl, &mac_one_go, &mac_status);
		if (err)
			return err;
		/* Stop the timer */
		stop_timer(&t_perf);
		if (flags == HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION)
			ASSERT_EQUAL(mac_status,
				     HSM_MAC_VERIFICATION_STATUS_SUCCESS);
	}

	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);
	return err;
}

int ele_hmac(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	open_svc_key_management_args_t key_mgmt_args;
	open_svc_mac_args_t mac_srv_args;
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err;
	hsm_hdl_t hsm_session_hdl, key_store_hdl, key_mgmt_hdl, mac_hdl;
	uint8_t mac[128] = {0}, test_msg[MAX_PAYLOAD_SIZE];
	uint32_t payload_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint32_t i;
	uint32_t key_hmac_sha256 = 0, key_hmac_sha384 = 0;

	ASSERT_EQUAL(randomize(test_msg, sizeof(test_msg)), sizeof(test_msg));

	open_session_args.session_priority = 0;
	open_session_args.operating_mode = 0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args,
				      &hsm_session_hdl),
		     HSM_NO_ERROR);

	key_store_args.key_store_identifier = 0xABCD;
	key_store_args.authentication_nonce = 0x1234;
	key_store_args.flags = 1;
	err = hsm_open_key_store_service(hsm_session_hdl,
					 &key_store_args,
					 &key_store_hdl);

	if (err == HSM_KEY_STORE_CONFLICT) {
		key_store_args.flags = 0;
		ASSERT_EQUAL(hsm_open_key_store_service(hsm_session_hdl,
							&key_store_args,
							&key_store_hdl),
			     HSM_NO_ERROR);
	} else {
		ASSERT_EQUAL(err, HSM_NO_ERROR);
	}

	memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));

	ASSERT_EQUAL(hsm_open_key_management_service(key_store_hdl,
						     &key_mgmt_args,
						     &key_mgmt_hdl),
		     HSM_NO_ERROR);

	ASSERT_EQUAL(hsm_open_mac_service(key_store_hdl, &mac_srv_args,
					  &mac_hdl),
		     HSM_NO_ERROR);

	/* generate hmac 256bit key */
	key_gen_args.key_identifier = &key_hmac_sha256;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = MAC_KEY_GROUP;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_SIGN_MSG |
				 HSM_KEY_USAGE_VERIFY_MSG;
	key_gen_args.permitted_algo = PERMITTED_ALGO_HMAC_SHA256;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_HMAC_256;
	key_gen_args.key_lifecycle = 0;
	key_gen_args.key_type = HSM_KEY_TYPE_HMAC;
	key_gen_args.out_key = NULL;

	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	/* generate hmac 384bit key */
	key_gen_args.key_identifier = &key_hmac_sha384;
	key_gen_args.permitted_algo = PERMITTED_ALGO_HMAC_SHA384;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_HMAC_384;

	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	for (i = 0; i < NUM_PAYLOAD_SIZE; i++) {
		ITEST_LOG("HMAC_SHA256 generation for 1s on %d byte blocks: ",
			  payload_size[i]);
		err = hmac_test(mac_hdl, key_hmac_sha256, test_msg,
				payload_size[i], mac, 32,
				PERMITTED_ALGO_HMAC_SHA256,
				HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION,
				hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("HMAC_SHA256 verification for 1s on %d byte blocks: ",
			  payload_size[i]);
		err = hmac_test(mac_hdl, key_hmac_sha256, test_msg,
				payload_size[i], mac, 32,
				PERMITTED_ALGO_HMAC_SHA256,
				HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION,
				hsm_session_hdl);
		if (err)
			goto out;
	}

	for (i = 0; i < NUM_PAYLOAD_SIZE; i++) {
		ITEST_LOG("HMAC_SHA384 generation for 1s on %d byte blocks: ",
			  payload_size[i]);
		err = hmac_test(mac_hdl, key_hmac_sha384, test_msg,
				payload_size[i], mac, 48,
				PERMITTED_ALGO_HMAC_SHA384,
				HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION,
				hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("HMAC_SHA384 verification for 1s on %d byte blocks: ",
			  payload_size[i]);
		err = hmac_test(mac_hdl, key_hmac_sha384, test_msg,
				payload_size[i], mac, 48,
				PERMITTED_ALGO_HMAC_SHA384,
				HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION,
				hsm_session_hdl);
		if (err)
			goto out;
	}

out:
	ASSERT_EQUAL(hsm_close_mac_service(mac_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_management_service(key_mgmt_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
