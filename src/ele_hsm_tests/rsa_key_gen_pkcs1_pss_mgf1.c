// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"

/* Number of iterations */
#define NUM_OPERATIONS	3
#define NB_KEY_SIZE 3
#define MAX_PUB_KEY_SIZE 0x200
#define KEY_GROUP 1
#define KEY_LIFE_CYCLE 0

static uint16_t size_pub_key[NB_KEY_SIZE] = {
	0x100,
	0x180,
	0x200,
};

static hsm_bit_key_sz_t bit_key_sz[NB_KEY_SIZE] = {
	HSM_KEY_SIZE_RSA_2048,
	HSM_KEY_SIZE_RSA_3072,
	HSM_KEY_SIZE_RSA_4096,
};

int rsa_key_gen_pkcs1_pss_mgf1(void)
{
	open_session_args_t open_session_args = {0};
	open_svc_key_management_args_t key_mgmt_args = {0};

	hsm_err_t err = 0;
	hsm_hdl_t key_mgmt_hdl = 0;
	uint8_t pub_key[MAX_PUB_KEY_SIZE] = {0};
	uint32_t key_id[NB_KEY_SIZE] = {0};
	uint32_t i = 0, j = 0, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};

	/* open session for ELE HSM MU */
	open_session_args.mu_type = HSM1;
	err = hsm_open_session(&open_session_args,
			&hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		goto out;
	}

	for (i = 0; i < NB_KEY_SIZE; i++) {
		/* reset timer */
		memset(&t_perf, 0, sizeof(t_perf));
		t_perf.session_hdl = hsm_session_hdl;
		ITEST_LOG("Generating %d bits RSA Key for 50sec: ", bit_key_sz[i]);
		for (j = 0; j < iter; j++) {
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

			key_id[i] = 0;
			/* calculate performance for generate key */
			err = hsm_generate_key_perf(key_mgmt_hdl, key_id[i],
					size_pub_key[i], KEY_GROUP,
					HSM_KEY_TYPE_RSA, pub_key,
					HSM_SE_KEY_STORAGE_VOLATILE,
					HSM_KEY_USAGE_SIGN_MSG |
					HSM_KEY_USAGE_VERIFY_MSG,
					PERMITTED_ALGO_RSA_PKCS1_PSS_MGF1_SHA_ANY,
					bit_key_sz[i],
					KEY_LIFE_CYCLE, &t_perf);
			if (err)
				goto out;

			/* close key management service */
			err = hsm_close_key_management_service(key_mgmt_hdl);
			if (err != HSM_NO_ERROR) {
				printf("hsm_close_key_management_service failed err:0x%x\n", err);
				goto out;
			}

			key_mgmt_hdl = 0;
			memset(&key_mgmt_args, 0, sizeof(key_mgmt_args));

			/* close key store service */

			err = hsm_close_key_store_service(key_store_hdl);
			if (err != HSM_NO_ERROR) {
				printf("hsm_close_key_store failed err:0x%x\n", err);
				goto out;
			}
			key_store_hdl = 0;
		}
		/* Finalize time to get stats */
		finalize_timer_rsa(&t_perf, iter);
		print_perf_rsa(&t_perf, iter);
	}

out:
	if (key_mgmt_hdl)
		hsm_close_key_management_service(key_mgmt_hdl);

	if (key_store_hdl)
		hsm_close_key_store_service(key_store_hdl);
	hsm_close_session(hsm_session_hdl);

	if (err)
		return -1;

	return TRUE_TEST;
}
