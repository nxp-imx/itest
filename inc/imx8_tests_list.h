/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023-2025 NXP
 */

#ifndef IMX8_TESTS_LIST_H
#define IMX8_TESTS_LIST_H

#include "itest.h"

/*==========Tests list===========*/
#ifdef PSA_COMPLIANT
int ele_rng_srv_001(void);
int ele_rng_perf(void);
int ele_cbc(void);
int ele_ecb(void);
int ecdsa_nist_sign_verify(void);
int ele_cmac(void);
int ele_hmac(void);
int ecdsa_brainpool_sign_verify(void);
int ele_gcm(void);
int ele_ccm(void);
int ele_randomness_gcm(void);
int ele_cfb(void);
int ele_ctr(void);
int ele_ofb(void);
int ele_hash_sha2(void);
int ele_hash_sha3(void);
int rsa_key_gen_pkcs1_v15(void);
int rsa_key_gen_pkcs1_pss_mgf1(void);
#elif defined(V2X_SHE_MU)
int v2x_fast_mac(void);
int v2x_fast_mac_mubuff_v2(void);
int v2x_cmac(void);
#else
/* V2X HSM tests */
int v2x_ecdsa_verify(void);
int v2x_ecdsa_nist_sign_verify(void);
int v2x_hash(void);
int v2x_ecdsa_verify_brainpool(void);
int v2x_ecdsa_brainpool_sign_verify(void);
int v2x_hash_SM3(void);
int v2x_sm2_sign_verify(void);
int v2x_sm4_cbc(void);
int v2x_sm4_ecb(void);
int v2x_aes_cbc(void);
int v2x_aes_ecb(void);
int v2x_aes_cmac(void);
int v2x_aes_gcm(void);
int v2x_sm4_ccm(void);
int v2x_sm2_eces(void);
#endif

testsuite imx8_ts[] = {
/*==============================================================================================*/
/*============================================== SE ===========================================*/
/*==============================================================================================*/
#ifdef PSA_COMPLIANT
{ele_rng_srv_001, "ele_rng_srv_001", 7, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93,
					 SOC_REV_A0, SOC_REV_A1, SOC_REV_B0,
					 SOC_IMX943}},
{ele_rng_perf, "ele_rng_perf", 7, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93,
				   SOC_REV_A0, SOC_REV_A1, SOC_REV_B0,
				   SOC_IMX943}},
{ele_cbc, "ele_cbc", 7, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93, SOC_REV_A0,
			 SOC_REV_A1, SOC_REV_B0, SOC_IMX943}},
{ele_ecb, "ele_ecb", 7, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93, SOC_REV_A0,
			 SOC_REV_A1, SOC_REV_B0, SOC_IMX943}},
{ecdsa_nist_sign_verify, "ecdsa_nist_sign_verify", 7, {SOC_IMX8ULP, SOC_IMX91,
						       SOC_IMX93, SOC_REV_A0,
						       SOC_REV_A1, SOC_REV_B0,
						       SOC_IMX943}},
{ele_cmac, "ele_cmac", 7, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93, SOC_REV_A0,
			   SOC_REV_A1, SOC_REV_B0, SOC_IMX943}},
{ele_hmac, "ele_hmac", 5, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93, SOC_IMX943, SOC_REV_B0}},
{ecdsa_brainpool_sign_verify, "ecdsa_brainpool_sign_verify", 7, {SOC_IMX8ULP, SOC_IMX91,
								 SOC_IMX93, SOC_REV_A0,
								 SOC_REV_A1, SOC_REV_B0,
								 SOC_IMX943}},
{ele_gcm, "ele_gcm", 4, {SOC_IMX91, SOC_IMX93,
			 SOC_REV_A0, SOC_REV_A1}},
{ele_ccm, "ele_ccm", 5, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93,
			 SOC_REV_A0, SOC_REV_A1}},
{ele_randomness_gcm, "ele_randomness_gcm", 4, {SOC_IMX91, SOC_IMX93,
					       SOC_REV_A0, SOC_REV_A1}},
{ele_cfb, "ele_cfb", 7, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93, SOC_REV_A0,
			 SOC_REV_A1, SOC_REV_B0, SOC_IMX943}},
{ele_ctr, "ele_ctr", 7, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93, SOC_REV_A0,
			 SOC_REV_A1, SOC_REV_B0, SOC_IMX943}},
{ele_ofb, "ele_ofb", 6, {SOC_IMX91, SOC_IMX93, SOC_REV_A0, SOC_REV_A1,
			 SOC_REV_B0, SOC_IMX943}},
{ele_hash_sha2, "ele_hash_sha2", 7, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93, SOC_REV_A0,
				     SOC_REV_A1, SOC_REV_B0, SOC_IMX943}},
{ele_hash_sha3, "ele_hash_sha3", 6, {SOC_IMX91, SOC_IMX93, SOC_REV_A0, SOC_REV_A1,
				     SOC_REV_B0, SOC_IMX943}},
{rsa_key_gen_pkcs1_v15, "rsa_key_gen_pkcs1_v15", 6, {SOC_IMX91, SOC_IMX93, SOC_REV_A0,
						     SOC_REV_A1, SOC_REV_B0, SOC_IMX943}},
{rsa_key_gen_pkcs1_pss_mgf1, "rsa_key_gen_pkcs1_pss_mgf1", 6, {SOC_IMX91, SOC_IMX93,
							       SOC_REV_A0, SOC_REV_A1,
							       SOC_REV_B0, SOC_IMX943}},
#elif defined(V2X_SHE_MU)
{v2x_fast_mac, "v2x_fast_mac", 5, {SOC_REV_A0, SOC_REV_A1, SOC_REV_B0,
				   IMX8DXL_DL3, SOC_IMX943}},
{v2x_fast_mac_mubuff_v2, "v2x_fast_mac_mubuff_v2", 4, {SOC_REV_A0, SOC_REV_A1,
						       SOC_REV_B0, SOC_IMX943}},
{v2x_cmac, "v2x_cmac", 5, {SOC_REV_A0, SOC_REV_A1, SOC_REV_B0, IMX8DXL_DL3,
			   SOC_IMX943}},
#else
/* V2X HSM tests */
{v2x_ecdsa_verify, "v2x_ecdsa_verify", 2, {SOC_REV_A0, SOC_REV_A1}},
{v2x_ecdsa_nist_sign_verify, "v2x_ecdsa_nist_sign_verify", 4, {IMX8DXL_DL2,
							       IMX8DXL_DL3,
							       SOC_IMX943,
							       SOC_REV_B0}},
{v2x_hash, "v2x_hash", 6, {SOC_REV_A0, SOC_REV_A1, SOC_REV_B0, IMX8DXL_DL2,
			   IMX8DXL_DL3, SOC_IMX943}},
{v2x_ecdsa_verify_brainpool, "v2x_ecdsa_verify_brainpool", 2, {SOC_REV_A0, SOC_REV_A1}},
{v2x_ecdsa_brainpool_sign_verify, "v2x_ecdsa_brainpool_sign_verify", 4, {IMX8DXL_DL2,
									 IMX8DXL_DL3,
									 SOC_IMX943,
									 SOC_REV_B0}},
{v2x_hash_SM3, "v2x_hash_SM3", 5, {SOC_REV_A0, SOC_REV_A1, SOC_REV_B0, IMX8DXL_DL3, SOC_IMX943}},
{v2x_sm2_sign_verify, "v2x_sm2_sign_verify", 3, {IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
{v2x_sm4_cbc, "v2x_sm4_cbc", 3, {IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
{v2x_sm4_ecb, "v2x_sm4_ecb", 3, {IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
{v2x_aes_cbc, "v2x_aes_cbc", 4, {IMX8DXL_DL2, IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
{v2x_aes_ecb, "v2x_aes_ecb", 4, {IMX8DXL_DL2, IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
{v2x_aes_cmac, "v2x_aes_cmac", 4, {IMX8DXL_DL2, IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
{v2x_aes_gcm, "v2x_aes_gcm", 4, {IMX8DXL_DL2, IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
{v2x_sm4_ccm, "v2x_sm4_ccm", 3, {IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
{v2x_sm2_eces, "v2x_sm2_eces", 3, {IMX8DXL_DL3, SOC_IMX943, SOC_REV_B0}},
#endif
{NULL, NULL, 5, {SOC_IMX8ULP, SOC_IMX91, SOC_IMX93, SOC_IMX95, SOC_IMX943}},
};
#endif
