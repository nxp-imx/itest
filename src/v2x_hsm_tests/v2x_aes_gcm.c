// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define MAX_MSG_SIZE 1024
#define NUM_MSG_SIZE 4
#define NUM_KEY_SIZE 3
#define AUTH_TAG_SIZE 16
#define IV_SIZE 12

int v2x_aes_gcm(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	open_svc_cipher_args_t open_cipher_args = {0};
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0, cipher_hdl = 0;
	uint32_t key_id_aes[NUM_KEY_SIZE] = {0};
	uint32_t key_size[NUM_KEY_SIZE] = {128, 192, 256};
	uint8_t iv[IV_SIZE] = {0};
	uint8_t fixed_iv[4] = {0};
	uint8_t plaintext[MAX_MSG_SIZE] = {0};
	uint8_t ciphertext[MAX_MSG_SIZE + AUTH_TAG_SIZE + IV_SIZE] = {0};
	uint8_t test_msg[MAX_MSG_SIZE] = {0};
	uint32_t block_size[] = {16, 64, 256, 1024};
	uint32_t i = 0, j = 0, num_msg_size = NUM_MSG_SIZE;
	uint8_t aad[16] = {0};

	/* input buffer as random */
	ASSERT_EQUAL(randomize(iv, sizeof(iv)), sizeof(iv));
	ASSERT_EQUAL(randomize(fixed_iv, sizeof(fixed_iv)), sizeof(fixed_iv));
	ASSERT_EQUAL(randomize(plaintext, MAX_MSG_SIZE), MAX_MSG_SIZE);
	ASSERT_EQUAL(randomize(aad, sizeof(aad)), sizeof(aad));

	/* open session for V2X HSM SG MU */
	open_session_args.mu_type = V2X_SG0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args,
				      &hsm_session_hdl),
		     HSM_NO_ERROR);

	/* set number of nessage sizes based on soc */
	if (soc == IMX8DXL_DL2 || soc == IMX8DXL_DL3)
		num_msg_size = NUM_MSG_SIZE - 1;

	key_store_args.key_store_identifier = 0xABCD;
	key_store_args.authentication_nonce = 0x1234;
	key_store_args.flags = 1;

	/* open key store service */
	err = hsm_open_key_store_service(hsm_session_hdl,
					 &key_store_args,
					 &key_store_hdl);

	if (err == HSM_KEY_STORE_CONFLICT) {
		/* key store may already exist */
		key_store_args.flags = 0;
		ASSERT_EQUAL(hsm_open_key_store_service(hsm_session_hdl,
							&key_store_args,
							&key_store_hdl),
			     HSM_NO_ERROR);
	} else {
		ASSERT_EQUAL(err, HSM_NO_ERROR);
	}

	/* open key management service */
	ASSERT_EQUAL(hsm_open_key_management_service(key_store_hdl,
						     &key_mgmt_args,
						     &key_mgmt_hdl),
		     HSM_NO_ERROR);

	open_cipher_args.flags = 0;

	/* open cipher service */
	ASSERT_EQUAL(hsm_open_cipher_service(key_store_hdl, &open_cipher_args,
					     &cipher_hdl),
		     HSM_NO_ERROR);

	/* generate aes 128bit key */
	key_gen_args.key_identifier = &key_id_aes[0];
	key_gen_args.key_type = HSM_KEY_TYPE_AES_128;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = 1;
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_info = 0;
	key_gen_args.out_key = NULL;

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
		for (i = 0; i < num_msg_size; i++) {
			ITEST_LOG("AES-%d-GCM encryption(v2x iv 8bytes) for 1s on %d byte blocks: ",
				  key_size[j], block_size[i]);
			err = auth_test(cipher_hdl, key_id_aes[j], plaintext,
					block_size[i], ciphertext,
					block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
					fixed_iv, sizeof(fixed_iv), aad,
					sizeof(aad), HSM_AUTH_ENC_ALGO_AES_GCM,
					HSM_AUTH_ENC_FLAGS_ENCRYPT |
					HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV,
					hsm_session_hdl);
			if (err)
				goto out;

			ITEST_LOG("AES-%d-GCM decryption(v2x iv 8bytes) for 1s on %d byte blocks: ",
				  key_size[j], block_size[i]);
			err = auth_test(cipher_hdl, key_id_aes[j], ciphertext,
					block_size[i] + AUTH_TAG_SIZE, test_msg,
					block_size[i],
					ciphertext + block_size[i] + AUTH_TAG_SIZE,
					IV_SIZE, aad, sizeof(aad),
					HSM_AUTH_ENC_ALGO_AES_GCM,
					HSM_AUTH_ENC_FLAGS_DECRYPT,
					hsm_session_hdl);
			if (err)
				goto out;
			ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
		}

		for (i = 0; i < num_msg_size; i++) {
			ITEST_LOG("AES-%d-GCM encryption(v2x iv) for 1s on %d byte blocks: ",
				  key_size[j], block_size[i]);
			err = auth_test(cipher_hdl, key_id_aes[j], plaintext,
					block_size[i], ciphertext,
					block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
					NULL, 0, aad, sizeof(aad),
					HSM_AUTH_ENC_ALGO_AES_GCM,
					HSM_AUTH_ENC_FLAGS_ENCRYPT |
					HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV,
					hsm_session_hdl);
			if (err)
				goto out;

			ITEST_LOG("AES-%d-GCM decryption(v2x iv) for 1s on %d byte blocks: ",
					key_size[j], block_size[i]);
			err = auth_test(cipher_hdl, key_id_aes[j], ciphertext,
					block_size[i] + AUTH_TAG_SIZE, test_msg,
					block_size[i],
					ciphertext + block_size[i] + AUTH_TAG_SIZE,
					IV_SIZE, aad, sizeof(aad),
					HSM_AUTH_ENC_ALGO_AES_GCM,
					HSM_AUTH_ENC_FLAGS_DECRYPT,
					hsm_session_hdl);
			if (err)
				goto out;
			ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
		}
	}

out:
	ASSERT_EQUAL(hsm_close_cipher_service(cipher_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_management_service(key_mgmt_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
