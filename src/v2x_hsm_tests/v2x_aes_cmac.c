// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define MAC_KEY_GROUP	50
#define MAX_PAYLOAD_SIZE 2048
#define NUM_PAYLOAD_SIZE 5
#define NUM_KEY_SIZE 3

int v2x_aes_cmac(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	open_svc_mac_args_t mac_srv_args = {0};
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0;
	hsm_hdl_t mac_hdl = 0;
	uint8_t mac[128] = {0}, test_msg[MAX_PAYLOAD_SIZE] = {0};
	uint32_t payload_size[] = {16, 64, 256, 1024, 2048};
	uint32_t i = 0, j = 0, num_payload_size = NUM_PAYLOAD_SIZE;
	uint32_t key_size[] = {128, 192, 256};
	uint32_t key_id_aes[NUM_KEY_SIZE] = {0};

	ASSERT_EQUAL(randomize(test_msg, sizeof(test_msg)), sizeof(test_msg));

	open_session_args.mu_type = V2X_SG0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args,
				      &hsm_session_hdl),
		     HSM_NO_ERROR);

	if (soc == IMX8DXL_DL2 || soc == IMX8DXL_DL3)
		num_payload_size = NUM_PAYLOAD_SIZE - 1;

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

	/* generate aes 128bit key */
	key_gen_args.key_identifier = &key_id_aes[0];
	key_gen_args.out_size = 0;
	key_gen_args.key_group = MAC_KEY_GROUP;
	key_gen_args.key_type = HSM_KEY_TYPE_AES_128;
	key_gen_args.out_key = NULL;
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_info = 0;

	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	/* generate aes 192bit key */
	key_gen_args.key_identifier = &key_id_aes[1];
	key_gen_args.key_type = HSM_KEY_TYPE_AES_192;

	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	/* generate aes 256bit key */
	key_gen_args.key_identifier = &key_id_aes[2];
	key_gen_args.key_type = HSM_KEY_TYPE_AES_256;

	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	for (j = 0; j < NUM_KEY_SIZE; j++) {
		for (i = 0; i < num_payload_size; i++) {
			ITEST_LOG("CMAC aes %d generation for 1s on %d byte blocks: ",
				  key_size[j], payload_size[i]);
			err = cmac_test(mac_hdl, key_id_aes[j],
					HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC,
					test_msg, payload_size[i], mac,
					HSM_OP_MAC_ONE_GO_FLAGS_MAC_GENERATION,
					hsm_session_hdl);
			if (err)
				goto out;

			ITEST_LOG("CMAC aes %d verification for 1s on %d byte blocks: ",
				  key_size[j], payload_size[i]);
			err = cmac_test(mac_hdl, key_id_aes[j],
					HSM_OP_MAC_ONE_GO_ALGO_AES_CMAC,
					test_msg, payload_size[i], mac,
					HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION,
					hsm_session_hdl);
			if (err)
				goto out;
		}
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
