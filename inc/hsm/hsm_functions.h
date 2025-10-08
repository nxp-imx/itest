/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2025 NXP
 */

#ifndef HSM_FUNCTIONS_H
#define HSM_FUNCTIONS_H

#include "hsm_api.h"
#include "common/global_info.h"
#include "common/perf.h"

extern hsm_hdl_t hsm_session_hdl, hsm_session_hdl2, key_store_hdl;

#define HSM_PUB_KEY_SIZE_RSA_2048 0x100
#define HSM_PUB_KEY_SIZE_RSA_3072 0x180
#define HSM_PUB_KEY_SIZE_RSA_4096 0x200

/*========OPEN KEY STORE========*/
hsm_err_t hsm_open_key_store(hsm_hdl_t hsm_session_hdl,
			     hsm_hdl_t *key_store_hdl);
/*=====GENERATE KEY REQUEST======*/
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
				   uint8_t *out_key);
/*=====GENERATE KEY PERF======*/
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
				timer_perf_t *t_perf);
/*===========CIPHER============*/
hsm_err_t cipher_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		      uint8_t *input, uint8_t *output, uint32_t block_size,
		      uint8_t *iv, uint16_t iv_size,
		      hsm_op_cipher_one_go_algo_t algo,
		      hsm_op_cipher_one_go_flags_t flags, uint32_t session_hdl);
/*===========AUTH TEST============*/
hsm_err_t auth_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
		    uint8_t *input, uint32_t input_size, uint8_t *output,
		    uint32_t output_size, uint8_t *iv, uint16_t iv_size,
		    uint8_t *aad, uint16_t aad_size,
		    hsm_op_auth_enc_algo_t algo,
		    hsm_op_auth_enc_flags_t flags, uint32_t session_hdl);
hsm_err_t auth_random_test(hsm_hdl_t cipher_hdl, uint32_t key_identifier,
			   uint8_t *input, uint32_t input_size,
			   uint8_t *output, uint32_t output_size, uint8_t *iv,
			   uint16_t iv_size, uint8_t *aad, uint16_t aad_size,
			   hsm_op_auth_enc_algo_t algo,
			   hsm_op_auth_enc_flags_t flags);
/*===========CMAC============*/
hsm_err_t cmac_test(hsm_hdl_t mac_hdl, uint32_t key_identifier,
		    hsm_op_mac_one_go_algo_t algo, uint8_t *payload,
		    uint32_t payload_size, uint8_t *mac,
		    hsm_op_mac_one_go_flags_t flags, uint32_t session_hdl);
/*===========HMAC============*/
hsm_err_t hmac_test(hsm_hdl_t mac_hdl, uint32_t key_identifier,
		    uint8_t *payload, uint32_t payload_size,
		    uint8_t *mac, uint32_t mac_size,
		    hsm_op_mac_one_go_algo_t algorithm,
		    hsm_op_mac_one_go_flags_t flags, uint32_t session_hdl);
/* PERFORMANCE RSA */
void finalize_timer_rsa(timer_perf_t *timer, uint32_t nb_iter);
void print_perf_rsa(timer_perf_t *timer, uint32_t nb_iter);
#endif
