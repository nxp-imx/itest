// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2024 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS (2000u)

#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6
#define AUTH_TAG_SIZE 16
#define IV_SIZE 12

hsm_err_t auth_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		    uint8_t *input, uint32_t input_size, uint8_t *output,
		    uint32_t output_size, uint8_t *iv, uint16_t iv_size,
		    uint8_t *aad, uint16_t aad_size,
		    hsm_op_auth_enc_algo_t algo, hsm_op_auth_enc_flags_t flags,
		    uint32_t session_hdl)
{
	op_auth_enc_args_t auth_enc_args = {0};
	uint32_t j, iter = NUM_OPERATIONS;
	timer_perf_t t_perf;
	hsm_err_t err;

	auth_enc_args.key_identifier = key_identifier;
	auth_enc_args.iv_size = iv_size;
	auth_enc_args.iv = iv;
	auth_enc_args.ae_algo = algo;
	auth_enc_args.flags = flags;
	auth_enc_args.aad_size = aad_size;
	auth_enc_args.aad = aad;
	auth_enc_args.input_size = input_size;
	auth_enc_args.input = input;
	auth_enc_args.output_size = output_size;
	auth_enc_args.output = output;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (j = 0; j < iter; j++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_auth_enc(cipher_hdl, &auth_enc_args);

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

int ele_gcm(void)
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
	uint8_t iv[IV_SIZE];
	uint8_t fixed_iv[4];
	uint8_t plaintext[MAX_MSG_SIZE];
	uint8_t ciphertext[MAX_MSG_SIZE + AUTH_TAG_SIZE + IV_SIZE] = {0};
	uint8_t test_msg[MAX_MSG_SIZE] = {0};
	uint32_t block_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint32_t i;
	uint8_t aad[16];

	// INPUT BUFF AS RANDOM
	ASSERT_EQUAL(randomize(iv, sizeof(iv)), sizeof(iv));
	ASSERT_EQUAL(randomize(fixed_iv, sizeof(fixed_iv)), sizeof(fixed_iv));
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
	key_gen_args.permitted_algo = PERMITTED_ALGO_GCM;
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
		ITEST_LOG("AES-128-GCM encryption for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_128, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE,
				iv, sizeof(iv), aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_ENCRYPT, hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-128-GCM decryption for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_128, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i], iv, sizeof(iv), aad, sizeof(aad),
				ALGO_GCM, HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-128-GCM encryption(ele iv 8bytes) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_128, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
				fixed_iv, sizeof(fixed_iv), aad, sizeof(aad),
				ALGO_GCM, HSM_AUTH_ENC_FLAGS_ENCRYPT |
				HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV,
				hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-128-GCM decryption(ele iv 8bytes) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_128, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i],
				ciphertext + block_size[i] + AUTH_TAG_SIZE,
				IV_SIZE, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-128-GCM encryption(ele iv) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_128, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
				NULL, 0, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_ENCRYPT |
				HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV, hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-128-GCM decryption(ele iv) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_128, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i],
				ciphertext + block_size[i] + AUTH_TAG_SIZE,
				IV_SIZE, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-192-GCM encryption for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_192, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE, iv, sizeof(iv),
				aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_ENCRYPT, hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-192-GCM decryption for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_192, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i], iv, sizeof(iv), aad, sizeof(aad),
				ALGO_GCM, HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-192-GCM encryption(ele iv 8bytes) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_192, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
				fixed_iv, sizeof(fixed_iv), aad, sizeof(aad),
				ALGO_GCM, HSM_AUTH_ENC_FLAGS_ENCRYPT |
				HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV,
				hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-192-GCM decryption(ele iv 8bytes) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_192, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i],
				ciphertext + block_size[i] + AUTH_TAG_SIZE,
				IV_SIZE, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-192-GCM encryption(ele iv) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_192, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
				NULL, 0, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_ENCRYPT |
				HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV, hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-192-GCM decryption(ele iv) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_192, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i],
				ciphertext + block_size[i] + AUTH_TAG_SIZE,
				IV_SIZE, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-256-GCM encryption for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_256, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE, iv,
				sizeof(iv), aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_ENCRYPT, hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-256-GCM decryption for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_256, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i], iv, sizeof(iv), aad,
				sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-256-GCM encryption(ele iv 8bytes) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_256, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
				fixed_iv, sizeof(fixed_iv), aad, sizeof(aad),
				ALGO_GCM, HSM_AUTH_ENC_FLAGS_ENCRYPT |
				HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV,
				hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-256-GCM decryption(ele iv 8bytes) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_256, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i],
				ciphertext + block_size[i] + AUTH_TAG_SIZE,
				IV_SIZE, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
	}

	for (i = 0; i < NUM_MSG_SIZE; i++) {
		ITEST_LOG("AES-256-GCM encryption(ele iv) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_256, plaintext,
				block_size[i], ciphertext,
				block_size[i] + AUTH_TAG_SIZE + IV_SIZE,
				NULL, 0, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_ENCRYPT |
				HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV, hsm_session_hdl);
		if (err)
			goto out;

		ITEST_LOG("AES-256-GCM decryption(ele iv) for 1s on %d byte blocks: ",
			  block_size[i]);
		err = auth_test(cipher_hdl, key_id_aes_256, ciphertext,
				block_size[i] + AUTH_TAG_SIZE, test_msg,
				block_size[i],
				ciphertext + block_size[i] + AUTH_TAG_SIZE,
				IV_SIZE, aad, sizeof(aad), ALGO_GCM,
				HSM_AUTH_ENC_FLAGS_DECRYPT, hsm_session_hdl);
		if (err)
			goto out;
		ASSERT_EQUAL(memcmp(test_msg, plaintext, block_size[i]), 0);
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
