// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS (2000u)

#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6
#define AUTH_TAG_SIZE 16

void auth_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier, uint8_t *input,
	       uint32_t input_size, uint8_t *output, uint32_t output_size,
	       uint8_t *iv, uint16_t iv_size, uint8_t *aad, uint16_t aad_size,
	       hsm_op_auth_enc_algo_t algo, hsm_op_auth_enc_flags_t flags);

int ele_ccm(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	open_svc_key_management_args_t key_mgmt_args;
	open_svc_cipher_args_t open_cipher_args;
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err;
	hsm_hdl_t hsm_session_hdl;
	hsm_hdl_t key_store_hdl, key_mgmt_hdl, cipher_hdl;
	uint32_t key_id_aes_128 = 0;
	uint32_t key_id_aes_192 = 0;
	uint32_t key_id_aes_256 = 0;
	uint8_t iv[12];
	uint8_t plaintext[MAX_MSG_SIZE];
	uint8_t ciphertext[MAX_MSG_SIZE + AUTH_TAG_SIZE] = {0};
	uint8_t test_msg[MAX_MSG_SIZE] = {0};
	uint32_t block_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint32_t i;
	uint8_t aad[16];

	// INPUT BUFF AS RANDOM
	ASSERT_EQUAL(randomize(iv, sizeof(iv)), sizeof(iv));
	ASSERT_EQUAL(randomize(plaintext, MAX_MSG_SIZE), MAX_MSG_SIZE);
	ASSERT_EQUAL(randomize(aad, sizeof(aad)), sizeof(aad));

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

	open_cipher_args.flags = 0;
	ASSERT_EQUAL(hsm_open_cipher_service(key_store_hdl, &open_cipher_args,
					     &cipher_hdl),
		     HSM_NO_ERROR);

	/* generate aes 128bit key */
	key_gen_args.key_identifier = &key_id_aes_128;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_128;
	key_gen_args.out_size = 0;
	key_gen_args.key_group = 1;
	key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
	key_gen_args.key_usage = HSM_KEY_USAGE_ENCRYPT | HSM_KEY_USAGE_DECRYPT;
	key_gen_args.permitted_algo = PERMITTED_ALGO_CCM;
	key_gen_args.key_lifecycle = 0;
	key_gen_args.key_type = HSM_KEY_TYPE_AES;
	key_gen_args.out_key = NULL;

	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	/* generate aes 192bit key */
	key_gen_args.key_identifier = &key_id_aes_192;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_192;

	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	/* generate aes 256bit key */
	key_gen_args.key_identifier = &key_id_aes_256;
	key_gen_args.bit_key_sz = HSM_KEY_SIZE_AES_256;

	ASSERT_EQUAL(hsm_generate_key(key_mgmt_hdl, &key_gen_args),
		     HSM_NO_ERROR);

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-128-CCM encryption on %d byte blocks: ",
			  block_size[i]);
		auth_test(cipher_hdl, key_id_aes_128, plaintext, block_size[i],
			  ciphertext, block_size[i] + AUTH_TAG_SIZE, iv,
			  sizeof(iv), aad, sizeof(aad),
			  HSM_AEAD_ALGO_CCM, HSM_AUTH_ENC_FLAGS_ENCRYPT);

		ITEST_LOG("AES-128-CCM decryption on %d byte blocks: ",
			  block_size[i]);
		auth_test(cipher_hdl, key_id_aes_128, ciphertext,
			  block_size[i] + AUTH_TAG_SIZE, test_msg,
			  block_size[i], iv, sizeof(iv), aad, sizeof(aad),
			  HSM_AEAD_ALGO_CCM, HSM_AUTH_ENC_FLAGS_DECRYPT);
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-192-CCM encryption on %d byte blocks: ",
			  block_size[i]);
		auth_test(cipher_hdl, key_id_aes_192, plaintext, block_size[i],
			  ciphertext, block_size[i] + AUTH_TAG_SIZE, iv,
			  sizeof(iv), aad, sizeof(aad),
			  HSM_AEAD_ALGO_CCM, HSM_AUTH_ENC_FLAGS_ENCRYPT);

		ITEST_LOG("AES-192-CCM decryption on %d byte blocks: ",
			  block_size[i]);
		auth_test(cipher_hdl, key_id_aes_192, ciphertext,
			  block_size[i] + AUTH_TAG_SIZE, test_msg,
			  block_size[i], iv, sizeof(iv), aad, sizeof(aad),
			  HSM_AEAD_ALGO_CCM, HSM_AUTH_ENC_FLAGS_DECRYPT);
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-256-CCM encryption on %d byte blocks: ",
			  block_size[i]);
		auth_test(cipher_hdl, key_id_aes_256, plaintext, block_size[i],
			  ciphertext, block_size[i] + AUTH_TAG_SIZE, iv,
			  sizeof(iv), aad, sizeof(aad),
			  HSM_AEAD_ALGO_CCM, HSM_AUTH_ENC_FLAGS_ENCRYPT);

		ITEST_LOG("AES-256-CCM decryption on %d byte blocks: ",
			  block_size[i]);
		auth_test(cipher_hdl, key_id_aes_256, ciphertext,
			  block_size[i] + AUTH_TAG_SIZE, test_msg,
			  block_size[i], iv, sizeof(iv), aad, sizeof(aad),
			  HSM_AEAD_ALGO_CCM, HSM_AUTH_ENC_FLAGS_DECRYPT);
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	ASSERT_EQUAL(hsm_close_cipher_service(cipher_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_management_service(key_mgmt_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	return TRUE_TEST;
}
