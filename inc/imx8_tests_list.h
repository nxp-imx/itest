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
int ele_hash(void);
#elif defined(V2X_SHE_MU)
int v2x_fast_mac(void);
int v2x_fast_mac_mubuff_v2(void);
int v2x_cmac(void);
#else
/* V2X HSM tests */
int v2x_ecdsa_verify(void);
int v2x_hash(void);
int v2x_ecdsa_verify_brainpool(void);
int v2x_hash_SM3(void);
int v2x_sm2_sign_verify(void);
int v2x_sm4_cbc(void);
int v2x_sm4_ecb(void);
int v2x_aes_cbc(void);
int v2x_aes_ecb(void);
int v2x_aes_cmac(void);
int v2x_aes_gcm(void);
#endif

testsuite imx8_ts[] = {
/*==============================================================================================*/
/*============================================== SE ===========================================*/
/*==============================================================================================*/
#ifdef PSA_COMPLIANT
{ele_rng_srv_001, "ele_rng_srv_001", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_rng_perf, "ele_rng_perf", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_cbc, "ele_cbc", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_ecb, "ele_ecb", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ecdsa_nist_sign_verify, "ecdsa_nist_sign_verify", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_cmac, "ele_cmac", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_hmac,	 "ele_hmac", SOC_IMX8ULP | SOC_IMX93},
{ecdsa_brainpool_sign_verify, "ecdsa_brainpool_sign_verify", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_gcm, "ele_gcm", SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_ccm, "ele_ccm", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_randomness_gcm, "ele_randomness_gcm", SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_cfb, "ele_cfb", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_ctr, "ele_ctr", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_ofb, "ele_ofb", SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
{ele_hash, "ele_hash", SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
#elif defined(V2X_SHE_MU)
{v2x_fast_mac, "v2x_fast_mac", SOC_IMX95 | SOC_IMX8DXL | SOC_IMX943},
{v2x_fast_mac_mubuff_v2, "v2x_fast_mac_mubuff_v2", SOC_IMX95 | SOC_IMX943},
{v2x_cmac, "v2x_cmac", SOC_IMX95 | SOC_IMX8DXL | SOC_IMX943},
#else
/* V2X HSM tests */
{v2x_ecdsa_verify, "v2x_ecdsa_verify", SOC_IMX95 | SOC_IMX8DXL | SOC_IMX943},
{v2x_hash, "v2x_hash", SOC_IMX95 | SOC_IMX8DXL | SOC_IMX943},
{v2x_ecdsa_verify_brainpool, "v2x_ecdsa_verify_brainpool", SOC_IMX95 | SOC_IMX8DXL | SOC_IMX943},
{v2x_hash_SM3, "v2x_hash_SM3", SOC_IMX95 | SOC_IMX8DXL | SOC_IMX943},
{v2x_sm2_sign_verify, "v2x_sm2_sign_verify", SOC_IMX8DXL | SOC_IMX943},
{v2x_sm4_cbc, "v2x_sm4_cbc", SOC_IMX8DXL | SOC_IMX943},
{v2x_sm4_ecb, "v2x_sm4_ecb", SOC_IMX8DXL | SOC_IMX943},
{v2x_aes_cbc, "v2x_aes_cbc", SOC_IMX8DXL | SOC_IMX943},
{v2x_aes_ecb, "v2x_aes_ecb", SOC_IMX8DXL | SOC_IMX943},
{v2x_aes_cmac, "v2x_aes_cmac", SOC_IMX8DXL | SOC_IMX943},
{v2x_aes_gcm, "v2x_aes_gcm", SOC_IMX8DXL | SOC_IMX943},
#endif
{NULL, NULL, SOC_IMX8ULP | SOC_IMX93 | SOC_IMX95 | SOC_IMX943},
};
#endif
