// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define MAX_MSG_SIZE 2048
#define NUM_MSG_SIZE 5
#define NUM_KEY_SIZE 3
#define IV_SIZE 16

int v2x_aes_cbc(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_srv_args = {0};
	open_svc_key_management_args_t key_mgmt_srv_args = {0};
	open_svc_cipher_args_t cipher_srv_args = {0};
	op_generate_key_args_t gen_key_args = {0};
	hsm_hdl_t sg0_cipher_hdl = 0;
	hsm_hdl_t sg0_key_mgmt_srv = 0;
	uint32_t key_id_aes[NUM_KEY_SIZE] = {0};
	uint32_t key_size[] = {128, 192, 256};
	uint8_t msg_input[MAX_MSG_SIZE] = {0};
	uint8_t buff_encr[MAX_MSG_SIZE] = {0};
	uint8_t buff_decr[MAX_MSG_SIZE] = {0};
	uint8_t iv[IV_SIZE] = {0};
	uint32_t i = 0, j = 0, num_msg_size = NUM_MSG_SIZE;
	uint32_t msg_size[] = {16, 64, 256, 1024, 2048};
	hsm_err_t err = 0;

	// INPUT BUFF AS RANDOM
	ASSERT_EQUAL(randomize(msg_input, MAX_MSG_SIZE), MAX_MSG_SIZE);
	ASSERT_EQUAL(randomize(iv, IV_SIZE), IV_SIZE);

	/* Open session for V2X HSM SG MU */
	open_session_args.mu_type = V2X_SG0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args, &hsm_session_hdl),
		     HSM_NO_ERROR);

	/* set number of nessage sizes based on soc */
	if (soc == IMX8DXL_DL2 || soc == IMX8DXL_DL3)
		num_msg_size = NUM_MSG_SIZE - 1;

	key_store_srv_args.key_store_identifier = 1234;
	key_store_srv_args.authentication_nonce = 1234;
	key_store_srv_args.max_updates_number = 12;
	key_store_srv_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	key_store_srv_args.signed_message = NULL;
	key_store_srv_args.signed_msg_size = 0;
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

	//OPEN CIPHER SG0
	ASSERT_EQUAL(hsm_open_cipher_service(key_store_hdl, &cipher_srv_args,
					     &sg0_cipher_hdl),
		     HSM_NO_ERROR);

	// KEY MGMNT SG0
	ASSERT_EQUAL(hsm_open_key_management_service(key_store_hdl,
						     &key_mgmt_srv_args,
						     &sg0_key_mgmt_srv),
		     HSM_NO_ERROR);

	/* generate aes 128bit key */
	gen_key_args.key_identifier = &key_id_aes[0];
	gen_key_args.out_size = 0;
	gen_key_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	gen_key_args.key_type = HSM_KEY_TYPE_AES_128;
	gen_key_args.key_group = 1;
	gen_key_args.key_info = 0U;
	gen_key_args.out_key = NULL;

	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args),
		     HSM_NO_ERROR);

	/* generate aes 192bit key */
	gen_key_args.key_identifier = &key_id_aes[1];
	gen_key_args.key_type = HSM_KEY_TYPE_AES_192;

	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args),
		     HSM_NO_ERROR);

	/* generate aes 256bit key */
	gen_key_args.key_identifier = &key_id_aes[2];
	gen_key_args.key_type = HSM_KEY_TYPE_AES_256;

	ASSERT_EQUAL(hsm_generate_key(sg0_key_mgmt_srv, &gen_key_args),
		     HSM_NO_ERROR);

	for (j = 0; j < NUM_KEY_SIZE; j ++)
	{
		for (i = 0; i < num_msg_size; i++) {
			ITEST_LOG("AES-%d-CBC encryption for 1s on %d byte blocks: ",
				  key_size[j], msg_size[i]);
			err = cipher_test(sg0_cipher_hdl, key_id_aes[j],
					  msg_input, buff_encr, msg_size[i],
					  iv, IV_SIZE, HSM_CIPHER_ONE_GO_ALGO_AES_CBC,
					  HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT,
					  hsm_session_hdl);
			if (err)
				goto out;

			ITEST_LOG("AES-%d-CBC decryption for 1s on %d byte blocks: ",
				  key_size[j], msg_size[i]);
			err = cipher_test(sg0_cipher_hdl, key_id_aes[j],
					  buff_encr, buff_decr, msg_size[i],
					  iv, IV_SIZE, HSM_CIPHER_ONE_GO_ALGO_AES_CBC,
					  HSM_CIPHER_ONE_GO_FLAGS_DECRYPT,
					  hsm_session_hdl);
			if (err)
				goto out;
			ASSERT_EQUAL(memcmp(msg_input, buff_decr, msg_size[i]), 0);
		}
	}

out:
	ASSERT_EQUAL(hsm_close_cipher_service(sg0_cipher_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
