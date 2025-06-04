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

int v2x_sm4_ccm(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	open_svc_cipher_args_t open_cipher_args = {0};
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0, cipher_hdl = 0;
	uint32_t key_id = 0;
	uint8_t fixed_iv[4] = {0};
	uint8_t plaintext[MAX_MSG_SIZE] = {0};
	uint8_t ciphertext[MAX_MSG_SIZE + AUTH_TAG_SIZE + IV_SIZE] = {0};
	uint8_t test_msg[MAX_MSG_SIZE] = {0};
	uint32_t block_size[] = {16, 64, 256, 1024};
	uint32_t i = 0, num_msg_size = NUM_MSG_SIZE;
	uint8_t aad[16] = {0};

	/* input buffer as random */
	ASSERT_EQUAL(randomize(fixed_iv, sizeof(fixed_iv)), sizeof(fixed_iv));
	ASSERT_EQUAL(randomize(plaintext, MAX_MSG_SIZE), MAX_MSG_SIZE);
	ASSERT_EQUAL(randomize(aad, sizeof(aad)), sizeof(aad));

	/* open session for V2X HSM SG MU */
	open_session_args.mu_type = V2X_SG0;
	err = hsm_open_session(&open_session_args,
			       &hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		goto out;
	}

	/* set number of nessage sizes based on soc */
	if (soc == IMX8DXL_DL1 || soc == IMX8DXL_DL3)
		num_msg_size = NUM_MSG_SIZE - 1;

	/* open key store service */
	err = hsm_open_key_store(hsm_session_hdl,
				 &key_store_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_key_store failed err:0x%x\n", err);
		goto out;
	}

	/* open key management service */
	err = hsm_open_key_management_service(key_store_hdl,
					      &key_mgmt_args,
					      &key_mgmt_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_key_management_service failed err:0x%x\n", err);
		goto out;
	}

	/* open cipher service */
	err = hsm_open_cipher_service(key_store_hdl, &open_cipher_args,
				      &cipher_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_cipher_service failed err:0x%x\n", err);
		goto out;
	}

	/* generate sm4 128bit key */
	key_gen_args.key_identifier = &key_id;
	key_gen_args.key_type = HSM_KEY_TYPE_SM4_128;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = 1;
	key_gen_args.flags = HSM_OP_KEY_GENERATION_FLAGS_CREATE;
	key_gen_args.key_info = 0;
	key_gen_args.out_key = NULL;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_generate_key failed err:0x%x\n", err);
		goto out;
	}

	for (i = 0; i < num_msg_size; i++) {
		ITEST_LOG("SM4-128-CCM encryption(v2x iv 8bytes) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
				fixed_iv, sizeof(fixed_iv), aad,
				sizeof(aad), HSM_AUTH_ENC_ALGO_SM4_CCM,
				HSM_AUTH_ENC_FLAGS_ENCRYPT |
				HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV,
				hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("SM4-128-CCM decryption(v2x iv 8bytes) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i],
				ciphertext + block_size[i] + AUTH_TAG_SIZE,
				IV_SIZE, aad, sizeof(aad),
				HSM_AUTH_ENC_ALGO_SM4_CCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT,
				hsm_session_hdl);
		if (err)
			goto out;
		err = memcmp(test_msg, plaintext, block_size[i]);
		if (err != 0) {
			printf("Decryption failed\n");
			goto out;
		}
	}

	for (i = 0; i < num_msg_size; i++) {
		ITEST_LOG("SM4-128-CCM encryption(v2x iv) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
				NULL, 0, aad,
				sizeof(aad), HSM_AUTH_ENC_ALGO_SM4_CCM,
				HSM_AUTH_ENC_FLAGS_ENCRYPT |
				HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV,
				hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("SM4-128-CCM decryption(v2x iv) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i],
				ciphertext + block_size[i] + AUTH_TAG_SIZE,
				IV_SIZE, aad, sizeof(aad),
				HSM_AUTH_ENC_ALGO_SM4_CCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT,
				hsm_session_hdl);
		if (err)
			goto out;
		err = memcmp(test_msg, plaintext, block_size[i]);
		if (err != 0) {
			printf("Decryption failed\n");
			goto out;
		}
	}

out:
	if (cipher_hdl)
		hsm_close_cipher_service(cipher_hdl);
	if (key_mgmt_hdl)
		hsm_close_key_management_service(key_mgmt_hdl);
	if (key_store_hdl)
		hsm_close_key_store_service(key_store_hdl);
	hsm_close_session(hsm_session_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
