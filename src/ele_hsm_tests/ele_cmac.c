// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define MAC_KEY_GROUP	50
#define MAX_PAYLOAD_SIZE 16384
#define NUM_PAYLOAD_SIZE 6
#define NUM_KEY_SIZE 2

int ele_cmac(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	open_svc_mac_args_t mac_srv_args = {0};
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0;
	hsm_hdl_t mac_hdl = 0;
	uint8_t mac[128] = {0}, test_msg[MAX_PAYLOAD_SIZE] = {0};
	uint32_t payload_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint32_t i = 0, j = 0;
	uint32_t key_id_aes[NUM_KEY_SIZE] = {0};
	uint32_t key_size[] = {128, 256};

	ASSERT_EQUAL(randomize(test_msg, sizeof(test_msg)), sizeof(test_msg));

	open_session_args.mu_type = HSM1;
	err = hsm_open_session(&open_session_args,
			       &hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		goto out;
	}

	err = hsm_open_key_store(hsm_session_hdl,
				 &key_store_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_key_store failed err:0x%x\n", err);
		goto out;
	}

	err = hsm_open_key_management_service(key_store_hdl,
					      &key_mgmt_args,
					      &key_mgmt_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_key_management_service failed err:0x%x\n", err);
		goto out;
	}

	err = hsm_open_mac_service(key_store_hdl, &mac_srv_args,
				   &mac_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_mac_service failed err:0x%x\n", err);
		goto out;
	}

	/* generate aes 128bit key */
	key_gen_args.key_identifier = &key_id_aes[0];
	key_gen_args.out_size = 0;
	key_gen_args.key_group = MAC_KEY_GROUP;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_SIGN_MSG |
				 HSM_KEY_USAGE_VERIFY_MSG;
	key_gen_args.permitted_algo = PERMITTED_ALGO_CMAC;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_128;
	key_gen_args.key_lifecycle = 0;
	key_gen_args.key_type = HSM_KEY_TYPE_AES;
	key_gen_args.out_key = NULL;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_generate_key failed err:0x%x\n", err);
		goto out;
	}

	/* generate aes 256bit key */
	key_gen_args.key_identifier = &key_id_aes[1];
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_256;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_generate_key failed err:0x%x\n", err);
		goto out;
	}

	for (j = 0; j < NUM_KEY_SIZE; j++) {
		for (i = 0; i < NUM_PAYLOAD_SIZE; i++) {
			ITEST_LOG("CMAC aes %d generation for 1s on %d byte blocks: ",
				  key_size[j], payload_size[i]);
			err = cmac_test(mac_hdl, key_id_aes[j], PERMITTED_ALGO_CMAC,
					test_msg, payload_size[i], mac,
					HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION,
					hsm_session_hdl);
			if (err)
				goto out;

			ITEST_LOG("CMAC aes %d verification for 1s on %d byte blocks: ",
				  key_size[j], payload_size[i]);
			err = cmac_test(mac_hdl, key_id_aes[j], PERMITTED_ALGO_CMAC,
					test_msg, payload_size[i], mac,
					HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION,
					hsm_session_hdl);
			if (err)
				goto out;
		}
	}

out:
	hsm_close_mac_service(mac_hdl);
	hsm_close_key_management_service(key_mgmt_hdl);
	hsm_close_key_store_service(key_store_hdl);
	hsm_close_session(hsm_session_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
