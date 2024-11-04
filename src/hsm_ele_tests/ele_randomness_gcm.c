// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

#define MSG_SIZE 128
#define AUTH_TAG_SIZE 16
#define IV_SIZE 12

hsm_err_t auth_random_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
			   uint8_t *input, uint32_t input_size,
			   uint8_t *output, uint32_t output_size, uint8_t *iv,
			   uint16_t iv_size, uint8_t *aad, uint16_t aad_size,
			   hsm_op_auth_enc_algo_t algo,
			   hsm_op_auth_enc_flags_t flags)
{
	op_auth_enc_args_t auth_enc_args = {0};
	hsm_err_t err = 0;

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

	err = hsm_auth_enc(cipher_hdl, &auth_enc_args);

	return err;
}

int ele_randomness_gcm(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_store_args_t key_store_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	open_svc_cipher_args_t open_cipher_args = {0};
	op_generate_key_args_t key_gen_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t hsm_session_hdl = 0;
	hsm_hdl_t key_store_hdl = 0, key_mgmt_hdl = 0;
	hsm_hdl_t cipher_hdl1 = 0, cipher_hdl2 = 0;
	uint32_t key_id_aes_128 = 0;
	uint8_t iv1[IV_SIZE] = {0}, iv2[IV_SIZE] = {0};
	uint8_t fixed_iv[4] = {0};
	uint8_t plaintext[MSG_SIZE] = {0};
	uint8_t ciphertext[MSG_SIZE + AUTH_TAG_SIZE + IV_SIZE] = {0};
	uint8_t aad[16] = {0};
	uint32_t num_matching_bytes = 0;
	uint64_t counter_val1 = 0, counter_val2 = 0;
	uint32_t idx = 0;

	// INPUT BUFF AS RANDOM
	ASSERT_EQUAL(randomize(fixed_iv, sizeof(fixed_iv)), sizeof(fixed_iv));
	ASSERT_EQUAL(randomize(plaintext, sizeof(plaintext)), sizeof(plaintext));
	ASSERT_EQUAL(randomize(aad, sizeof(aad)), sizeof(aad));

	memset(iv1, 0, sizeof(iv1));
	memset(iv2, 0, sizeof(iv2));

	open_session_args.mu_type = HSM1;
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
					     &cipher_hdl1),
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

	// TEST FORMAT OF IV FOR FULL GENERATION MODE

	// AUTH ENC KEY AES128 -> ENCRYPT
	ITEST_LOG("AES-128-GCM encryption(ele iv) on 128 byte blocks\n");
	err = auth_random_test(cipher_hdl1, key_id_aes_128, plaintext,
			       sizeof(plaintext), ciphertext,
			       sizeof(ciphertext), NULL, 0, aad, sizeof(aad),
			       ALGO_GCM, HSM_AUTH_ENC_FLAGS_ENCRYPT |
			       HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV);
	if (err)
		goto out;

	// EXTRACT GENERATED IV
	memcpy(iv1, &ciphertext[sizeof(ciphertext)-sizeof(iv1)], sizeof(iv1));

	// AUTH ENC KEY AES128 -> ENCRYPT (exact same input)
	ITEST_LOG("AES-128-GCM encryption(ele iv) on 128 byte blocks\n");
	err = auth_random_test(cipher_hdl1, key_id_aes_128, plaintext,
			       sizeof(plaintext), ciphertext,
			       sizeof(ciphertext), NULL, 0, aad, sizeof(aad),
			       ALGO_GCM, HSM_AUTH_ENC_FLAGS_ENCRYPT |
			       HSM_AUTH_ENC_FLAGS_GENERATE_FULL_IV);
	if (err)
		goto out;

	// EXTRACT GENERATED IV
	memcpy(iv2, &ciphertext[sizeof(ciphertext)-sizeof(iv1)], sizeof(iv1));

	// WEAK RANDOMNESS TEST - NO MORE THAN 3 BYTES IDENTICAL
	num_matching_bytes = 0;
	for (idx = 0; idx < sizeof(iv1); idx++) {
		if (iv1[idx] == iv2[idx])
			num_matching_bytes++;
	}
	ASSERT_TRUE((num_matching_bytes < 4));

	// TEST FORMAT OF IV FOR COUNTER MODE

	// AUTH ENC KEY AES128 -> ENCRYPT
	ITEST_LOG("AES-128-GCM encryption(ele iv 8bytes) on 128 byte blocks\n");
	err = auth_random_test(cipher_hdl1, key_id_aes_128, plaintext,
			       sizeof(plaintext), ciphertext,
			       sizeof(ciphertext), fixed_iv, sizeof(fixed_iv),
			       aad, sizeof(aad), ALGO_GCM,
			       HSM_AUTH_ENC_FLAGS_ENCRYPT |
			       HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV);
	if (err)
		goto out;

	// EXTRACT GENERATED IV
	memcpy(iv1, &ciphertext[sizeof(ciphertext)-sizeof(iv1)], sizeof(iv1));
	// VERIFY FIXED PART
	ASSERT_EQUAL(memcmp(iv1, fixed_iv, sizeof(fixed_iv)), 0);
	// EXTRACT COUNTER
	counter_val1 = *(uint64_t *)(&(iv1[4]));

	// AUTH ENC KEY AES128 -> ENCRYPT (exact same input)
	ITEST_LOG("AES-128-GCM encryption(ele iv 8bytes) on 128 byte blocks\n");
	err = auth_random_test(cipher_hdl1, key_id_aes_128, plaintext,
			       sizeof(plaintext), ciphertext,
			       sizeof(ciphertext), fixed_iv, sizeof(fixed_iv),
			       aad, sizeof(aad), ALGO_GCM,
			       HSM_AUTH_ENC_FLAGS_ENCRYPT |
			       HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV);
	if (err)
		goto out;

	// EXTRACT GENERATED IV
	memcpy(iv2, &ciphertext[sizeof(ciphertext)-sizeof(iv2)], sizeof(iv2));
	// VERIFY FIXED PART
	ASSERT_EQUAL(memcmp(iv2, fixed_iv, sizeof(fixed_iv)), 0);
	// EXTRACT COUNTER
	counter_val2 = *(uint64_t *)(&(iv2[4]));

	// VERIFY COUNTER WAS INCREMENTED
	ASSERT_EQUAL(counter_val2, counter_val1 + 1);

	// VERIFY CANNOT SCREW UP COUNTER BY OPENING KEY STORE SECOND TIME
	key_store_args.key_store_identifier = 0xABCD;
	key_store_args.authentication_nonce = 0x1234;
	key_store_args.flags = 0;
	ASSERT_EQUAL(hsm_open_key_store_service(hsm_session_hdl, &key_store_args,
						&key_store_hdl),
		     HSM_KEY_STORE_CONFLICT);

	// OPEN SECOND CIPHER SERVICE TO VERIFY COUNTER INCREMENTS ACROSS SERVICES
	open_cipher_args.flags = 0;
	ASSERT_EQUAL(hsm_open_cipher_service(key_store_hdl, &open_cipher_args,
					     &cipher_hdl2),
		     HSM_NO_ERROR);

	// VERIFY INCREMENTED COUNTER ON NEW SERVICE
	ITEST_LOG("AES-128-GCM encryption(ele iv 8bytes) on 128 byte blocks\n");
	err = auth_random_test(cipher_hdl2, key_id_aes_128, plaintext,
			       sizeof(plaintext), ciphertext,
			       sizeof(ciphertext), fixed_iv, sizeof(fixed_iv),
			       aad, sizeof(aad), ALGO_GCM,
			       HSM_AUTH_ENC_FLAGS_ENCRYPT |
			       HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV);
	if (err) {
		ASSERT_EQUAL(hsm_close_cipher_service(cipher_hdl2), HSM_NO_ERROR);
		goto out;
	}

	// EXTRACT GENERATED IV
	memcpy(iv1, &ciphertext[sizeof(ciphertext)-sizeof(iv1)], sizeof(iv1));
	// VERIFY FIXED PART
	ASSERT_EQUAL(memcmp(iv1, fixed_iv, sizeof(fixed_iv)), 0);
	// EXTRACT COUNTER
	counter_val1 = *(uint64_t *)(&(iv1[4]));

	// VERIFY COUNTER WAS INCREMENTED
	ASSERT_EQUAL(counter_val1, counter_val2 + 1);

	// VERIFY KEEPS INCREMENTING ON ORIGINAL CIPHER SERVICE
	ITEST_LOG("AES-128-GCM encryption(ele iv 8bytes) on 128 byte blocks\n");
	err = auth_random_test(cipher_hdl1, key_id_aes_128, plaintext,
			       sizeof(plaintext), ciphertext,
			       sizeof(ciphertext), fixed_iv, sizeof(fixed_iv),
			       aad, sizeof(aad), ALGO_GCM,
			       HSM_AUTH_ENC_FLAGS_ENCRYPT |
			       HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV);
	if (err)
		goto out;

	// EXTRACT GENERATED IV
	memcpy(iv2, &ciphertext[sizeof(ciphertext)-sizeof(iv2)], sizeof(iv2));
	// VERIFY FIXED PART
	ASSERT_EQUAL(memcmp(iv2, fixed_iv, sizeof(fixed_iv)), 0);
	// EXTRACT COUNTER
	counter_val2 = *(uint64_t *)(&(iv2[4]));

	// VERIFY COUNTER WAS INCREMENTED
	ASSERT_EQUAL(counter_val2, counter_val1 + 1);

	ASSERT_EQUAL(hsm_close_cipher_service(cipher_hdl2), HSM_NO_ERROR);
out:
	ASSERT_EQUAL(hsm_close_cipher_service(cipher_hdl1), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_management_service(key_mgmt_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_key_store_service(key_store_hdl), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);

	return TRUE_TEST;
}
