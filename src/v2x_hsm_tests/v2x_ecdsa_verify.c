// SPDX-License-Identifier: BSD-3-Clause
/*
 * Copyright 2024-2025 NXP
 */

#include <stdio.h>
#include <stdlib.h>
#include "itest.h"
#include <openssl/ec.h>
#include <openssl/evp.h>

/* Number of iterations */
#define NUM_OPERATIONS  (1000u)

#define NB_ALGO 3
#define MAX_MSG_SIZE 16384
#define NUM_MSG_SIZE 6
#define MAX_PUB_KEY_SIZE (0x84)
#define MAX_DER_SIGN (MAX_PUB_KEY_SIZE + 10)
#define EVP_SUCCESS 1
#define SEQUENCE_LENGTH_INDEX 1
#define MAX_LENGTH_SHORT_FORM 127

#define MIN(a, b) ((a) < (b) ? (a) : (b))

static hsm_signature_scheme_id_t scheme_id[NB_ALGO] = {
	HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256,
	HSM_SIGNATURE_SCHEME_ECDSA_NIST_P384_SHA_384,
	HSM_SIGNATURE_SCHEME_ECDSA_NIST_P521_SHA_512,
};

static char *openssl_algo[NB_ALGO] = {
	"prime256v1",
	"secp384r1",
	"secp521r1",
};

static uint16_t size_pub_key[NB_ALGO] = {
	0x40,
	0x60,
	0x84,
};

static char *algo[NB_ALGO] = {
	"ECDSA_NIST_SHA_256",
	"ECDSA_NIST_SHA_384",
	"ECDSA_NIST_SHA_512",
};

static const EVP_MD * (*EVP_hash[NB_ALGO])(void) = {
	EVP_sha256,
	EVP_sha384,
	EVP_sha512,
};

void parse_der_to_raw(uint8_t *sign, int len_component_der,
		      int len_component_raw, int raw_component_start_index,
		      int len_component_index)
{
	int leading_zero = 0, add_leading_zero = 0;
	int der_component_start_index = 0;

	/* Check if leading zero is removed in der component */
	if (len_component_der < len_component_raw) {
		add_leading_zero = 1;
		/**
		 * Add 0x00 byte in the starting index of component for fixed
		 * size raw signature
		 */
		sign[raw_component_start_index] = 0;

	/* Check if leading zero is added in case of negative value in der */
	} else if (len_component_der > len_component_raw)
		leading_zero = 1;

	/* Format: 0x30|b1|0x02|b2|r|0x02|b3|s */

	/* Calculate start index for r or s in the DER encoded signature */
	der_component_start_index = len_component_index + leading_zero + 1;

	/* Calculate start index for r or s in the raw signature */
	raw_component_start_index += add_leading_zero;

	/* Convert DER format to raw signature */
	memcpy(sign + raw_component_start_index,
	       sign + der_component_start_index,
	       MIN(len_component_der, len_component_raw));
}

void decode_signature(int pub_key_len, uint8_t *sign)
{
	if (!sign) {
		ITEST_LOG("Invalid signature\n");
		return;
	}

	int long_form = 0, len_r_encoded = 0, len_s_encoded = 0;
	int len_r_index = 0, len_s_index = 0;
	int len_component_raw = pub_key_len/2;
	int raw_r_start_index = 0, raw_s_start_index = len_component_raw;

	/* check condition for long form */
	if (sign[SEQUENCE_LENGTH_INDEX] > MAX_LENGTH_SHORT_FORM)
		long_form = 1;

	/* Format: 0x30|b1|0x02|b2|r|0x02|b3|s */

	/* calculate index for b2 having length for r component */
	len_r_index = long_form + 3;

	/* calculate length for r component */
	len_r_encoded = sign[len_r_index];

	/* calculate index for b3 having length for s component */
	len_s_index = long_form + 3 + len_r_encoded + 2;

	/* calculate length for s component */
	len_s_encoded = sign[len_s_index];

	/* convert der encoded signature to raw format */
	parse_der_to_raw(sign, len_r_encoded, len_component_raw, raw_r_start_index, len_r_index);
	parse_der_to_raw(sign, len_s_encoded, len_component_raw, raw_s_start_index, len_s_index);

	/* Size of signature is public key size + 1 with last byte 0x00 in v2x*/
	sign[pub_key_len] = 0;
}

int v2x_ecdsa_verify(void)
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *mdctx = 0;
	size_t sign_len = 0;
	uint8_t msg[MAX_MSG_SIZE] = {0};
	uint32_t msg_size[] = {16, 64, 256, 1024, 8192, 16384};
	uint8_t sign[MAX_DER_SIGN] = {0};
	unsigned char out_pubkey[MAX_PUB_KEY_SIZE + 1] = {0};
	size_t out_pubkey_len = 0;
	uint32_t i = 0, j = 0, k = 0, iter = NUM_OPERATIONS;
	timer_perf_t t_perf = {0};

	hsm_hdl_t sig_ver_hdl = 0;
	hsm_err_t err = 0;
	open_session_args_t open_session_args = {0};
	open_svc_sign_ver_args_t open_sig_ver_args = {0};
	op_verify_sign_args_t sig_ver_args = {0};
	hsm_verification_status_t verify_status = 0;

	/* Open session for V2X HSM MU */
	open_session_args.mu_type = V2X_SV0;
	ASSERT_EQUAL(hsm_open_session(&open_session_args, &hsm_session_hdl),
		     HSM_NO_ERROR);

	ASSERT_EQUAL(hsm_open_signature_verification_service(hsm_session_hdl,
				&open_sig_ver_args,
				&sig_ver_hdl),
		     HSM_NO_ERROR);

	ASSERT_EQUAL(randomize(msg, MAX_MSG_SIZE), MAX_MSG_SIZE);

	for (i = 0; i < NB_ALGO; i++) {
		pkey = EVP_EC_gen(openssl_algo[i]);
		ASSERT_NOT_EQUAL(pkey, NULL)

		for (k = 0; k < NUM_MSG_SIZE; k++) {
			mdctx = EVP_MD_CTX_new();

			ASSERT_NOT_EQUAL(mdctx, NULL);

			ASSERT_EQUAL(EVP_DigestSignInit(mdctx, NULL,
							EVP_hash[i](), NULL,
							pkey),
				     EVP_SUCCESS);

			ASSERT_EQUAL(EVP_DigestSignUpdate(mdctx, msg,
							  msg_size[k]),
				     EVP_SUCCESS);

			ASSERT_EQUAL(EVP_DigestSignFinal(mdctx, NULL,
							 &sign_len),
				     EVP_SUCCESS);

			ASSERT_EQUAL(EVP_DigestSignFinal(mdctx, sign,
							 &sign_len),
				     EVP_SUCCESS);

			decode_signature(size_pub_key[i], sign);

			if (!EVP_PKEY_get_octet_string_param(pkey, "pub",
							    out_pubkey,
							    sizeof(out_pubkey),
							    &out_pubkey_len)) {
				ITEST_LOG("Public key fetch failed\n");
				goto out;
			}

			ITEST_LOG("%s verification for 1s on %d byte size blocks: ",
				  algo[i], msg_size[k]);
			sig_ver_args.key = out_pubkey+1;
			sig_ver_args.message = msg;
			sig_ver_args.signature = sign;
			sig_ver_args.key_size = size_pub_key[i];
			sig_ver_args.signature_size = size_pub_key[i] + 1;
			sig_ver_args.message_size = msg_size[k];
			sig_ver_args.scheme_id = scheme_id[i];
			sig_ver_args.flags = HSM_OP_VERIFY_SIGN_FLAGS_INPUT_MESSAGE;

			memset(&t_perf, 0, sizeof(t_perf));
			t_perf.session_hdl = hsm_session_hdl;

			for (j = 0; j < iter; j++) {
				/* Start the timer */
				start_timer(&t_perf);
				err = hsm_verify_signature(sig_ver_hdl,
							   &sig_ver_args,
							   &verify_status);
				if (err)
					goto out;

				ASSERT_EQUAL(verify_status,
					     HSM_VERIFICATION_STATUS_SUCCESS);

				/* Stop the timer */
				stop_timer(&t_perf);
			}

			/* Finalize time to get stats */
			finalize_timer(&t_perf, iter);
			print_perf(&t_perf, iter);
		}
	}

out:
	ASSERT_EQUAL(hsm_close_signature_verification_service(sig_ver_hdl),
		     HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(hsm_session_hdl), HSM_NO_ERROR);

	if (err)
		ASSERT_FALSE(err);
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return TRUE_TEST;
}
