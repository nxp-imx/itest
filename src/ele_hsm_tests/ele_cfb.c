// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6
#define NUM_KEY_SIZE 3

int ele_cfb(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	open_svc_cipher_args_t open_cipher_args = {0};
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0, cipher_hdl = 0;
	uint32_t key_size[] = {128, 192, 256};
	uint32_t key_id_aes[NUM_KEY_SIZE] = {0};
	uint8_t buff_encr[MAX_MSG_SIZE] = {0};
	uint8_t buff_decr[MAX_MSG_SIZE] = {0};
	uint8_t msg[MAX_MSG_SIZE] = {0};
	uint8_t iv[16] = {0};
	uint32_t block_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint32_t i = 0, j = 0;

	// INPUT BUFF AS RANDOM
	ASSERT_EQUAL(randomize(msg, MAX_MSG_SIZE), MAX_MSG_SIZE);
	ASSERT_EQUAL(randomize(iv, 16), 16);

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

	err = hsm_open_cipher_service(key_store_hdl, &open_cipher_args,
				      &cipher_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_cipher_service failed err:0x%x\n", err);
		goto out;
	}

	/* generate aes 128bit key */
	key_gen_args.key_identifier = &key_id_aes[0];
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_128;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = 1;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
	key_gen_args.permitted_algo = PERMITTED_ALGO_ALL_CIPHER;
	key_gen_args.key_lifecycle = 0;
	key_gen_args.key_type = HSM_KEY_TYPE_AES;
	key_gen_args.out_key = NULL;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_generate_key failed err:0x%x\n", err);
		goto out;
	}

	/* generate aes 192bit key */
	key_gen_args.key_identifier = &key_id_aes[1];
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_192;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_generate_key failed err:0x%x\n", err);
		goto out;
	}

	/* generate aes 256bit key */
	key_gen_args.key_identifier = &key_id_aes[2];
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_256;

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_generate_key failed err:0x%x\n", err);
		goto out;
	}

	for (j = 0; j < NUM_KEY_SIZE; j++) {
		for (i = 0; i < NUM_MSG_SIZE; i++) {
			ITEST_LOG("AES-%d-CFB encryption for 1s on %d byte blocks: ",
				  key_size[j], block_size[i]);
			err = cipher_test(cipher_hdl, key_id_aes[j], msg, buff_encr,
					  block_size[i], iv, 16,
					  HSM_CIPHER_ONE_GO_ALGO_CFB,
					  HSM_CIPHER_ONE_GO_FLAGS_ENCRYPT,
					  hsm_session_hdl);
			if (err)
				goto out;

			ITEST_LOG("AES-%d-CFB decryption for 1s on %d byte blocks: ",
				  key_size[j], block_size[i]);
			err = cipher_test(cipher_hdl, key_id_aes[j], buff_encr,
					  buff_decr, block_size[i], iv, 16,
					  HSM_CIPHER_ONE_GO_ALGO_CFB,
					  HSM_CIPHER_ONE_GO_FLAGS_DECRYPT,
					  hsm_session_hdl);
			if (err)
				goto out;
			err = memcmp(msg, buff_decr, block_size[i]);
			if (err != 0) {
				printf("Decryption failed\n");
				goto out;
			}
		}
	}

out:
	hsm_close_cipher_service(cipher_hdl);
	hsm_close_key_management_service(key_mgmt_hdl);
	hsm_close_key_store_service(key_store_hdl);
	hsm_close_session(hsm_session_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
