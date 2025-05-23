// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2023-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS	100

#define NB_ALGO	4
#define MAX_PUB_KEY_SIZE (0x84)
#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6

static hsm_signature_scheme_id_t scheme_id[NB_ALGO] = {
	HSM_SIGNATURE_SCHEME_ECDSA_SHA224,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA256,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA384,
	HSM_SIGNATURE_SCHEME_ECDSA_SHA512,
};

static uint16_t size_pub_key[NB_ALGO] = {
	0x38,
	0x40,
	0x60,
	0x84,
};

static hsm_bit_key_sz_t bit_key_sz[NB_ALGO] = {
	HSM_KEY_SIZE_ECC_NIST_224,
	HSM_KEY_SIZE_ECC_NIST_256,
	HSM_KEY_SIZE_ECC_NIST_384,
	HSM_KEY_SIZE_ECC_NIST_521,
};

static hsm_permitted_algo_t permitted_algo[NB_ALGO] = {
	PERMITTED_ALGO_ECDSA_SHA224,
	PERMITTED_ALGO_ECDSA_SHA256,
	PERMITTED_ALGO_ECDSA_SHA384,
	PERMITTED_ALGO_ECDSA_SHA512,
};

static char *algo[NB_ALGO] = {
	"ECDSA_NIST_SHA_224",
	"ECDSA_NIST_SHA_256",
	"ECDSA_NIST_SHA_384",
	"ECDSA_NIST_SHA_512",
};

int ecdsa_nist_sign_verify(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};
	op_generate_sign_args_t sig_gen_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	op_generate_key_args_t key_gen_args = {0};
	open_svc_sign_gen_args_t open_sig_gen_args = {0};
	open_svc_sign_ver_args_t open_sig_ver_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0;
	hsm_hdl_t sig_gen_hdl = 0, sig_ver_hdl = 0;
	uint8_t pub_key[NB_ALGO][MAX_PUB_KEY_SIZE] = {0};
	uint8_t sign_out_0[MAX_PUB_KEY_SIZE] = {0};
	uint32_t key_id[NB_ALGO] = {0};
	hsm_verification_status_t verify_status = 0;
	timer_perf_t t_perf = {0};
	uint32_t i = 0, j = 0, k = 0, iter = NUM_OPERATIONS, num_algo = NB_ALGO;
	uint8_t msg_0[MAX_MSG_SIZE] = {0};
	uint32_t msg_size[] = {16, 64, 256, 1024, 8192, 16384};
	op_pub_key_recovery_args_t args = {0};

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

	// INPUT BUFF AS RANDOM
	ASSERT_EQUAL(randomize(msg_0, MAX_MSG_SIZE), MAX_MSG_SIZE);

	err = hsm_open_key_management_service(key_store_hdl,
					      &key_mgmt_args,
					      &key_mgmt_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_key_management_service failed err:0x%x\n", err);
		goto out;
	}

	err = hsm_open_signature_generation_service(key_store_hdl,
						    &open_sig_gen_args,
						    &sig_gen_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_signature_generation_service failed err:0x%x\n", err);
		goto out;
	}

	err = hsm_open_signature_verification_service(hsm_session_hdl,
						      &open_sig_ver_args,
						      &sig_ver_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_signature_verification_service failed err:0x%x\n", err);
		goto out;
	}

	for (j = 0; j < num_algo; j++) {
		key_gen_args.key_identifier = &key_id[j];
		key_gen_args.out_size = size_pub_key[j];
		key_gen_args.key_group = 3;
		key_gen_args.key_lifetime = HSM_SE_KEY_STORAGE_VOLATILE;
		key_gen_args.key_usage = HSM_KEY_USAGE_SIGN_MSG |
					 HSM_KEY_USAGE_VERIFY_MSG;
		key_gen_args.permitted_algo = permitted_algo[j];
		key_gen_args.bit_key_sz = bit_key_sz[j];
		key_gen_args.key_lifecycle = 0;
		key_gen_args.key_type = HSM_KEY_TYPE_ECC_NIST;
		key_gen_args.out_key = pub_key[j];

		err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
		if (err != HSM_NO_ERROR) {
			printf("hsm_generate_key failed err:0x%x\n", err);
			goto out;
		}

		for (k = 0; k < NUM_MSG_SIZE; k++) {
			ITEST_LOG("%s signing for 1s on %d byte size blocks: ",
				  algo[j], msg_size[k]);
			sig_gen_args.key_identifier = key_id[j];
			sig_gen_args.message = msg_0;
			sig_gen_args.signature = sign_out_0;
			sig_gen_args.signature_size = size_pub_key[j];
			sig_gen_args.message_size = msg_size[k];
			sig_gen_args.scheme_id = scheme_id[j];
			sig_gen_args.salt_len = 0;
			sig_gen_args.exp_signature_size = size_pub_key[j];
			sig_gen_args.flags = HSM_OP_GENERATE_SIGN_FLAGS_INPUT_MESSAGE;
			memset(&t_perf, 0, sizeof(t_perf));
			t_perf.session_hdl = hsm_session_hdl;

			for (i = 0U; i < iter; i++) {
				/* Start the timer */
				start_timer(&t_perf);
				err = hsm_generate_signature(sig_gen_hdl,
							     &sig_gen_args);
				if (err) {
					printf("hsm_generate_signature failed err:0x%x\n", err);
					goto out;
				}
				/* Stop the timer */
				stop_timer(&t_perf);
			}

			/* Finalize time to get stats */
			finalize_timer(&t_perf, iter);
			print_perf(&t_perf, iter);

			args.key_identifier = key_id[j];
			args.out_key_size = size_pub_key[j];
			args.out_key = pub_key[j];

			err = hsm_pub_key_recovery(key_store_hdl, &args);
			if (err != HSM_NO_ERROR) {
				printf("hsm_pub_key_recovery failed err:0x%x\n", err);
				goto out;
			}

			ITEST_LOG("%s verification for 1s on %d byte size blocks: ",
				  algo[j], msg_size[k]);
			sig_ver_args.key = pub_key[j];
			sig_ver_args.message = msg_0;
			sig_ver_args.signature = sign_out_0;
			sig_ver_args.key_size = size_pub_key[j];
			sig_ver_args.signature_size = size_pub_key[j];
			sig_ver_args.message_size = msg_size[k];
			sig_ver_args.verification_status = HSM_VERIFICATION_STATUS_SUCCESS;
			sig_ver_args.scheme_id = scheme_id[j];
			sig_ver_args.salt_len = 0;
			sig_ver_args.key_sz = bit_key_sz[j];
			sig_ver_args.pkey_type = HSM_PUBKEY_TYPE_ECC_NIST;
			sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;
			memset(&t_perf, 0, sizeof(t_perf));
			t_perf.session_hdl = hsm_session_hdl;

			for (i = 0U; i < iter; i++) {
				/* Start the timer */
				start_timer(&t_perf);
				err = hsm_verify_signature(sig_ver_hdl,
							   &sig_ver_args,
							   &verify_status);
				if (err) {
					printf("hsm_verify_signature failed err:0x%x\n", err);
					goto out;
				}

				if (verify_status != HSM_VERIFICATION_STATUS_SUCCESS) {
					printf("Sign Verification unsuccessful err:0x%x\n",
						err);
					goto out;
				}

				/* Stop the timer */
				stop_timer(&t_perf);
			}

			/* Finalize time to get stats */
			finalize_timer(&t_perf, iter);
			print_perf(&t_perf, iter);
		}
	}

out:
	hsm_close_signature_generation_service(sig_gen_hdl);
	hsm_close_signature_verification_service(sig_ver_hdl);
	hsm_close_key_management_service(key_mgmt_hdl);
	hsm_close_key_store_service(key_store_hdl);
	hsm_close_session(hsm_session_hdl);

	if (err)
		return FALSE_TEST;

	return TRUE_TEST;
}
