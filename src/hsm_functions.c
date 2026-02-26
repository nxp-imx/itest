// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2025-2026 NXP
 */

#include "itest.h"
#include "hsm/hsm_functions.h"

/* Number of iterations */
#define NUM_OPERATIONS  (2000u)
#define MAC_SIZE        16

hsm_hdl_t hsm_session_hdl, hsm_session_hdl2, key_store_hdl;

uint16_t get_soc(void)
{
	hsm_hdl_t hsm_session_hdl = 0;
	open_session_args_t open_session_args = {0};
	char soc_val[MAX_SOC_VAL];
	int err = 0;

	FILE *file = fopen("/sys/devices/soc0/soc_id", "r");

	if (file == NULL) {
		perror("Error opening the /sys/devices/soc0/soc_id file");
		return 1;
	}

	if (fgets(soc_val, MAX_SOC_VAL, file) == NULL) {
		perror("Error reading the /sys/devices/soc0/soc_id file");
		if (fclose(file) != 0)
			perror("Error closing /sys/devices/soc0/soc_id file");
		return 1;
	}

	if (fclose(file) != 0)
		printf("Error closing /sys/devices/soc0/soc_id file");

	soc_val[strcspn(soc_val, "\t\n")] = 0;

	if (strcmp(soc_val, "i.MX943") == 0)
		soc = SOC_IMX943;
#ifndef PSA_COMPLIANT
	else if (strcmp(soc_val, "i.MX8DXL") == 0)
		soc = SOC_IMX8DXL;
#endif
	else if (strcmp(soc_val, "i.MX91") == 0)
		soc = SOC_IMX91;
	else if (strcmp(soc_val, "i.MX93") == 0)
		soc = SOC_IMX93;
	else if (strcmp(soc_val, "i.MX8ULP") == 0)
		soc = SOC_IMX8ULP;
	else if (strcmp(soc_val, "i.MX95") == 0)
		soc = SOC_IMX95;
	else if (strcmp(soc_val, "i.MX952") == 0)
		soc = SOC_IMX952;
	else {
		perror("Undefined SOC\n");
		return 1;
	}


#ifdef PSA_COMPLIANT
	open_session_args.mu_type = HSM1;
#else
	/* Open session for SV0 channel on V2X HSM */
	open_session_args.mu_type = V2X_SV0;
#endif
	err = hsm_open_session(&open_session_args, &hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_open_session failed err:0x%x\n", err);
		return 1;
	}

	soc_rev = se_get_soc_rev();
	board_type = se_get_board_type();

	err = hsm_close_session(hsm_session_hdl);
	if (err != HSM_NO_ERROR) {
		printf("hsm_close_session failed err:0x%x\n", err);
		return 1;
	}
	return soc;
}

void print_help(void)
{
#ifdef PSA_COMPLIANT
	ITEST_LOG("\nitest Help Menu:\n\n");
	ITEST_LOG("$ ./itest [OPTION] <argument>\n\n");
#else
	ITEST_LOG("\nitest_v2x_hsm Help Menu:\n\n");
	ITEST_LOG("$ ./itest_v2x_hsm [OPTION] <argument>\n\n");
#endif
	ITEST_LOG("OPTIONS:\n");
	ITEST_LOG("  -h : Print this help\n");
	ITEST_LOG("  -v : Print test suite version\n");
	ITEST_LOG("  -l : List all tests\n");
	ITEST_LOG("  -t < test_name > : Run test test_name\n");
}

hsm_err_t cipher_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		      uint8_t *input, uint8_t *output, uint32_t block_size,
		      uint8_t *iv, uint16_t iv_size,
		      hsm_op_cipher_one_go_algo_t algo,
		      hsm_op_cipher_one_go_flags_t flags,
		      uint32_t session_hdl)
{
	op_cipher_one_go_args_t cipher_args = {0};
	uint32_t j, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};
	hsm_err_t err = 0;

	cipher_args.key_identifier = key_identifier;
	cipher_args.iv = iv;
	cipher_args.iv_size = iv_size;
	cipher_args.cipher_algo = algo;
	cipher_args.flags = flags;
	cipher_args.input = input;
	cipher_args.output = output;
	cipher_args.input_size = block_size;
	cipher_args.output_size = block_size;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (j = 0; j < iter; j++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_cipher_one_go(cipher_hdl, &cipher_args);
		if (err) {
			printf("hsm_cipher_one_go failed err:0x%x\n", err);
			return err;
		}
		/* Stop the timer */
		stop_timer(&t_perf);
	}
	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);

	return err;
}

hsm_err_t cmac_test(hsm_hdl_t mac_hdl, uint32_t key_identifier,
		    hsm_op_mac_one_go_algo_t algo, uint8_t *payload,
		    uint32_t payload_size, uint8_t *mac,
		    hsm_op_mac_one_go_flags_t flags, uint32_t session_hdl)
{
	op_mac_one_go_args_t mac_one_go = {0};
	hsm_mac_verification_status_t mac_status = 0;
	timer_perf_t t_perf = {0};
	uint32_t i = 0, iter = NUM_OPERATIONS;
	hsm_err_t err = 0;

	mac_one_go.key_identifier = key_identifier;
	mac_one_go.algorithm = algo;
	mac_one_go.flags = flags;
	mac_one_go.payload = payload;
	mac_one_go.mac = mac;
	mac_one_go.payload_size = payload_size;
	mac_one_go.mac_size = MAC_SIZE;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (i = 0U; i < iter; i++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_mac_one_go(mac_hdl, &mac_one_go, &mac_status);
		if (err) {
			printf("hsm_mac_one_go failed err:0x%x\n", err);
			return err;
		}
		/* Stop the timer */
		stop_timer(&t_perf);
		if (flags == HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION) {
			if (mac_status != HSM_MAC_VERIFICATION_STATUS_SUCCESS)
				return 1;
		}
	}
	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);
	return err;
}

hsm_err_t auth_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		    uint8_t *input, uint32_t input_size, uint8_t *output,
		    uint32_t output_size, uint8_t *iv, uint16_t iv_size,
		    uint8_t *aad, uint16_t aad_size,
		    hsm_op_auth_enc_algo_t algo, hsm_op_auth_enc_flags_t flags,
		    uint32_t session_hdl)
{
	op_auth_enc_args_t auth_enc_args = {0};
	uint32_t j = 0, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};
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

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (j = 0; j < iter; j++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_auth_enc(cipher_hdl, &auth_enc_args);
		if (err) {
			printf("hsm_auth_enc failed err:0x%x\n", err);
			return err;
		}
		/* Stop the timer */
		stop_timer(&t_perf);
	}
	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);

	return err;
}

#ifdef PSA_COMPLIANT
hsm_err_t auth_test_new(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
			uint8_t *input, uint32_t input_size, uint8_t *output,
			uint32_t output_size, uint8_t *iv_in, uint16_t iv_size,
			uint8_t *iv_out, uint8_t *aad, uint16_t aad_size,
			hsm_op_auth_enc_algo_t algo,
			hsm_op_auth_enc_new_flags_t flags,
			uint16_t tag_size, uint8_t *tag, uint32_t session_hdl)
{
	op_auth_enc_new_args_t args = {0};
	uint32_t j = 0, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};
	hsm_err_t err = 0;

	args.key_id = key_identifier;
	args.iv_size = iv_size;
	args.iv_in = iv_in;
	args.iv_out = iv_out;
	args.ae_algo = algo;
	args.flags = flags;
	args.aad_size = aad_size;
	args.aad = aad;
	args.input_size = input_size;
	args.input = input;
	args.output_size = output_size;
	args.output = output;
	args.tag_size = tag_size;
	args.tag = tag;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;
	for (j = 0; j < iter; j++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_auth_enc_new(cipher_hdl, &args);
		if (err) {
			printf("hsm_auth_enc_new failed err:0x%x\n", err);
			return err;
		}
		/* Stop the timer */
		stop_timer(&t_perf);
	}
	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);

	return err;
}
#endif

hsm_err_t hsm_generate_key_perf(hsm_hdl_t key_mgmt_hdl, uint32_t key_id,
				uint16_t out_size, hsm_key_group_t key_group,
				hsm_key_type_t key_type, uint8_t *out_key,
#ifdef PSA_COMPLIANT
				hsm_key_lifetime_t key_lifetime,
				hsm_key_usage_t key_usage,
				hsm_permitted_algo_t permitted_algo,
				hsm_bit_key_sz_t bit_key_sz,
				hsm_key_lifecycle_t key_lifecycle,
#else
				hsm_key_info_t key_info,
#endif
				timer_perf_t *t_perf)
{
	op_generate_key_args_t key_gen_args = {0};
	hsm_err_t err = 0;

	key_gen_args.key_identifier = &key_id;
	key_gen_args.out_size = out_size;
	key_gen_args.key_group = key_group;
	key_gen_args.out_key = out_key;
	key_gen_args.key_type = key_type;
#ifdef PSA_COMPLIANT
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
#else
	key_gen_args.key_info = key_info;
#endif
	/* Start the timer */
	start_timer(t_perf);
	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);
	if (err) {
		printf("hsm_generate_key failed err:0x%x\n", err);
		return err;
	}
	/* Stop the timer */
	stop_timer(t_perf);

	return err;
}

hsm_err_t hsm_open_key_store(hsm_hdl_t hsm_session_hdl, hsm_hdl_t *key_store_hdl)
{
	hsm_err_t err = 0;
	open_svc_key_store_args_t key_store_args = {0};

	key_store_args.key_store_identifier = 0xABCD;
	key_store_args.authentication_nonce = 0x1234;
	key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_CREATE;
	err = hsm_open_key_store_service(hsm_session_hdl,
					 &key_store_args,
					 key_store_hdl);
	if (err != HSM_NO_ERROR) {
		if (err == HSM_KEY_STORE_CONFLICT) {
			key_store_args.flags = HSM_SVC_KEY_STORE_FLAGS_LOAD;
			err = hsm_open_key_store_service(hsm_session_hdl,
							 &key_store_args,
							 key_store_hdl);
			if (err != HSM_NO_ERROR)
				printf("%s failed err:0x%x\n", __func__, err);
		} else {
			printf("%s failed err:0x%x\n", __func__, err);
		}
	}

	return err;
}

hsm_err_t hsm_generate_key_request(hsm_hdl_t key_mgmt_hdl, uint32_t *key_id,
				   uint16_t out_size, hsm_key_group_t key_group,
				   hsm_key_type_t key_type, hsm_op_key_gen_flags_t flags,
#ifdef PSA_COMPLIANT
				   hsm_key_lifetime_t key_lifetime,
				   hsm_key_usage_t key_usage,
				   hsm_permitted_algo_t permitted_algo,
				   hsm_bit_key_sz_t bit_key_sz,
				   hsm_key_lifecycle_t key_lifecycle,
#else
				   hsm_key_info_t key_info,
#endif
				   uint8_t *out_key)
{
	op_generate_key_args_t key_gen_args = {0};
	hsm_err_t err = 0;

	key_gen_args.key_identifier = key_id;
	key_gen_args.out_size = out_size;
	key_gen_args.key_group = key_group;
	key_gen_args.out_key = out_key;
	key_gen_args.key_type = key_type;
	key_gen_args.flags = flags;
#ifdef PSA_COMPLIANT
	key_gen_args.bit_key_sz = bit_key_sz;
	key_gen_args.key_lifecycle = key_lifecycle;
	key_gen_args.key_lifetime = key_lifetime;
	key_gen_args.key_usage = key_usage;
	key_gen_args.permitted_algo = permitted_algo;
#else
	key_gen_args.key_info = key_info;
#endif
	err = hsm_generate_key(key_mgmt_hdl, &key_gen_args);

	return err;
}

hsm_err_t hmac_test(hsm_hdl_t mac_hdl, uint32_t key_identifier,
		    uint8_t *payload, uint32_t payload_size,
		    uint8_t *mac, uint16_t mac_size,
		    hsm_op_mac_one_go_algo_t algorithm,
		    hsm_op_mac_one_go_flags_t flags, uint32_t session_hdl)
{
	op_mac_one_go_args_t mac_one_go = {0};
	hsm_mac_verification_status_t mac_status = 0;
	timer_perf_t t_perf = {0};
	uint32_t i = 0, iter = NUM_OPERATIONS;
	hsm_err_t err = 0;

	mac_one_go.key_identifier = key_identifier;
	mac_one_go.algorithm = algorithm;
	mac_one_go.flags = flags;
	mac_one_go.payload = payload;
	mac_one_go.mac = mac;
	mac_one_go.payload_size = payload_size;
	mac_one_go.mac_size = mac_size;

	memset(&t_perf, 0, sizeof(t_perf));
	t_perf.session_hdl = session_hdl;

	for (i = 0U; i < iter; i++) {
		/* Start the timer */
		start_timer(&t_perf);
		err = hsm_mac_one_go(mac_hdl, &mac_one_go, &mac_status);
		if (err) {
			printf("hsm_mac_one_go failed err:0x%x\n", err);
			return err;
		}
		/* Stop the timer */
		stop_timer(&t_perf);
		if (flags == HSM_OP_MAC_ONE_GO_FLAGS_MAC_VERIFICATION) {
			if (mac_status != HSM_MAC_VERIFICATION_STATUS_SUCCESS) {
				printf("MAC Verification failed\n");
				err = 1;
				break;
			}
		}
	}

	/* Finalize time to get stats */
	finalize_timer(&t_perf, iter);
	print_perf(&t_perf, iter);
	return err;
}

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

void print_perf_rsa(timer_perf_t *timer, uint32_t nb_iter)
{
	double lib_request_t_per_op = timer->lib_request_t/nb_iter;
	double lib_response_t_per_op = timer->lib_response_t/nb_iter;
	double fw_t_per_op = timer->fw_t/nb_iter;

	ITEST_LOG("%lu ops (%.2lfsec/op)\n", timer->op_sec,
			timer->t_per_op * 0.000001);
	ITEST_LOG("%20s %12s %23s\n", "SE LIB -> Kernel",
#ifdef PSA_COMPLIANT
			"ELE FW",
#else
			"V2X FW",
#endif
			"Kernel -> SE LIB");
	ITEST_LOG("%14.2lfus", lib_request_t_per_op);
	ITEST_LOG("%16.2lfsec", fw_t_per_op * 0.000001);
	ITEST_LOG("%17.2lfus\n\n", lib_response_t_per_op);
}
