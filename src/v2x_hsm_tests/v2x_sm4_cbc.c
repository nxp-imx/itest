// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define MAX_MSG_SIZE 2048
#define NUM_MSG_SIZE 5
#define IV_SIZE 16

int v2x_sm4_cbc(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_srv_args = {0};
	open_svc_key_management_args_t key_mgmt_srv_args = {0};
	open_svc_cipher_args_t cipher_srv_args = {0};
	op_generate_key_args_t gen_key_args = {0};
	hsm_hdl_t sg0_cipher_hdl = 0;
	hsm_hdl_t sg0_key_mgmt_srv = 0;
	uint32_t key_id = 0;
	uint8_t msg_input[MAX_MSG_SIZE] = {0};
	uint8_t buff_encr[MAX_MSG_SIZE] = {0};
	uint8_t buff_decr[MAX_MSG_SIZE] = {0};
	uint8_t iv[IV_SIZE] = {0};
	uint32_t i = 0, num_msg_size = NUM_MSG_SIZE;
	uint32_t msg_size[] = {16, 64, 256, 1024, 2048};
	hsm_err_t err = 0;

	/* input buffer as random */
	ASSERT_EQUAL(randomize(msg_input, MAX_MSG_SIZE), MAX_MSG_SIZE);
	ASSERT_EQUAL(randomize(iv, IV_SIZE), IV_SIZE);

	/* open session for V2X HSM SG MU */
	open_session_args.mu_type = V2X_SG0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args, &hsm_session_hdl),
		     HSM_NO_ERROR);

	/* set number of nessage sizes based on soc */
	if (soc == SOC_IMX8DXL)
		num_msg_size = NUM_MSG_SIZE - 1;

	key_store_srv_args.key_store_identifier = 1234;
	key_store_srv_args.authentication_nonce = 1234;
	key_store_srv_args.max_updates_number = 12;
	key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	key_store_srv_args.signed_message = NULL;
	key_store_srv_args.signed_msg_size = 0;

	/* open key store service */
	err = hsm_open_key_store_service(hsm_session_hdl, &key_store_srv_args,
					 &key_store_hdl);
	if (err == HSM_KEY_STORE_CONFLICT) {
		/* key store may already exist. */
		key_store_srv_args.flags = 0;
		err = hsm_open_key_store_service(hsm_session_hdl,
						 &key_store_srv_args,
						 &key_store_hdl);
	} else
		ASSERT_EQUAL(err, HSM_NO_ERROR);

	/* open cipher service */
	ASSERT_EQUAL(hsm_open_cipher_service(key_store_hdl, &cipher_srv_args,
					     &sg0_cipher_hdl),
		     HSM_NO_ERROR);

	/* open key management service */
	ASSERT_EQUAL(hsm_open_key_management_service(key_store_hdl,
						     &key_mgmt_srv_args,
						     &sg0_key_mgmt_srv),
		     HSM_NO_ERROR);

	gen_key_args.key_identifier = &key_id;
	gen_key_args.out_size = 0;
	gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	gen_key_args.key_type = HSM_KEY_TYPE_SM4_128;
	gen_key_args.key_group = 1;
	gen_key_args.key_info = 0U;
	gen_key_args.out_key = NULL;

	/* generate SM4_128 key */
	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args),
		     HSM_NO_ERROR);

	for (i = 0; i < num_msg_size; i++) {
		ITEST_LOG("SM4-128-CBC encryption for 1s on %d byte blocks: ",
			  msg_size[i]);
		err = cipher_test(sg0_cipher_hdl, key_id, msg_input, buff_encr,
				  msg_size[i], iv, IV_SIZE,
				  HSM_CIPHER_ONE_GO_ALGO_SM4_CBC,
				  HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT,
				  hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("SM4-128-CBC decryption for 1s on %d byte blocks: ",
			  msg_size[i]);
		err = cipher_test(sg0_cipher_hdl, key_id, buff_encr,
				  buff_decr, msg_size[i], iv, IV_SIZE,
				  HSM_CIPHER_ONE_GO_ALGO_SM4_CBC,
				  HSM_CIPHER_ONE_GO_FLAGS_DECRYPT,
				  hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(msg_input, buff_decr, msg_size[i]), 0);
	}

out:
	ASSERT_EQUAL(hsm_close_cipher_service(sg0_cipher_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
