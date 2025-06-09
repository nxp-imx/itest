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

int ele_randomness_gcm(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	open_svc_cipher_args_t open_cipher_args = {0};
	op_generate_key_args_t key_gen_args = {0};
	open_svc_key_store_args_t key_store_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0;
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
	randomize(fixed_iv, sizeof(fixed_iv));
	randomize(plaintext, sizeof(plaintext));
	randomize(aad, sizeof(aad));

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
				      &cipher_hdl1);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_cipher_service failed err:0x%x\n", err);
		goto out;
	}

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

	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err != HSM_NO_ERROR) {
		printf("hsm_generate_key failed err:0x%x\n", err);
		goto out;
	}

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
	if (num_matching_bytes >= 4) {
		printf("WEAK RANDOMNESS TEST failed\n");
		err = -1;
		goto out;
	}

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
	err = memcmp(iv1, fixed_iv, sizeof(fixed_iv));
	if (err != 0)
		goto out;

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
	err = memcmp(iv2, fixed_iv, sizeof(fixed_iv));
	if (err != 0)
		goto out;
	// EXTRACT COUNTER
	counter_val2 = *(uint64_t *)(&(iv2[4]));

	// VERIFY COUNTER WAS INCREMENTED
	if (counter_val2 != counter_val1 + 1) {
		err = -1;
		goto out;
	}

	// VERIFY CANNOT SCREW UP COUNTER BY OPENING KEY STORE SECOND TIME
	key_store_args.key_store_identifier = 0xABCD;
	key_store_args.authentication_nonce = 0x1234;
	key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_LOAD;
	err = hsm_open_key_store_service(hsm_session_hdl,
					 &key_store_args,
					 &key_store_hdl);
	if (err != HSM_KEY_STORE_CONFLICT) {
		printf("hsm_open_key_store failed err:0x%x\n", err);
		goto out;
	}

	// OPEN SECOND CIPHER SERVICE TO VERIFY COUNTER INCREMENTS ACROSS SERVICES
	open_cipher_args.flags = 0;
	err = hsm_open_cipher_service(key_store_hdl, &open_cipher_args,
				      &cipher_hdl2);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_cipher_service failed err:0x%x\n", err);
		goto out;
	}

	// VERIFY INCREMENTED COUNTER ON NEW SERVICE
	ITEST_LOG("AES-128-GCM encryption(ele iv 8bytes) on 128 byte blocks\n");
	err = auth_random_test(cipher_hdl2, key_id_aes_128, plaintext,
			       sizeof(plaintext), ciphertext,
			       sizeof(ciphertext), fixed_iv, sizeof(fixed_iv),
			       aad, sizeof(aad), ALGO_GCM,
			       HSM_AUTH_ENC_FLAGS_ENCRYPT |
			       HSM_AUTH_ENC_FLAGS_GENERATE_COUNTER_IV);
	if (err) {
		hsm_close_cipher_service(cipher_hdl2);
		goto out;
	}

	// EXTRACT GENERATED IV
	memcpy(iv1, &ciphertext[sizeof(ciphertext)-sizeof(iv1)], sizeof(iv1));
	// VERIFY FIXED PART
	err = memcmp(iv1, fixed_iv, sizeof(fixed_iv));
	if (err != 0) {
		err = -1;
		goto out;
	}
	// EXTRACT COUNTER
	counter_val1 = *(uint64_t *)(&(iv1[4]));

	// VERIFY COUNTER WAS INCREMENTED
	if (counter_val1 != counter_val2 + 1) {
		err = -1;
		goto out;
	}

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
	err = memcmp(iv2, fixed_iv, sizeof(fixed_iv));
	if (err != 0) {
		err = -1;
		goto out;
	}
	// EXTRACT COUNTER
	counter_val2 = *(uint64_t *)(&(iv2[4]));

	// VERIFY COUNTER WAS INCREMENTED
	if (counter_val2 != counter_val1 + 1) {
		err = -1;
		goto out;
	}

	err = hsm_close_cipher_service(cipher_hdl2);
	if (err != HSM_NO_ERROR) {
		printf("hsm_close_cipher_service failed err:0x%x\n", err);
		goto out;
	}

out:
	hsm_close_cipher_service(cipher_hdl1);
	hsm_close_key_management_service(key_mgmt_hdl);
	hsm_close_key_store_service(key_store_hdl);
	hsm_close_session(hsm_session_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
