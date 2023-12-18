/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Copyright 2023 NXP
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
#else
int v2x_fast_mac(void);
#endif

testsuite imx8_ts[] = {
/*==============================================================================================*/
/*============================================== ELE ===========================================*/
/*==============================================================================================*/
#ifdef PSA_COMPLIANT
{ele_rng_srv_001, "ele_rng_srv_001", MX8ULP_A2 | MX93_A1 | MX95},
{ele_rng_perf, "ele_rng_perf", MX8ULP_A2 | MX93_A1 | MX95},
{ele_cbc, "ele_cbc", MX8ULP_A2 | MX93_A1 | MX95},
{ele_ecb, "ele_ecb", MX8ULP_A2 | MX93_A1 | MX95},
{ecdsa_nist_sign_verify, "ecdsa_nist_sign_verify", MX8ULP_A2 | MX93_A1 | MX95},
{ele_cmac, "ele_cmac", MX8ULP_A2 | MX93_A1 | MX95},
{ele_hmac,	 "ele_hmac", MX8ULP_A2 | MX93_A1 | MX95},
{ecdsa_brainpool_sign_verify, "ecdsa_brainpool_sign_verify", MX8ULP_A2 | MX93_A1 | MX95},
{ele_gcm, "ele_gcm", MX8ULP_A2 | MX93_A1 | MX95},
{ele_ccm, "ele_ccm", MX8ULP_A2 | MX93_A1 | MX95},
{ele_randomness_gcm, "ele_randomness_gcm", MX8ULP_A2 | MX93_A1 | MX95},
{ele_cfb, "ele_cfb", MX8ULP_A2 | MX93_A1 | MX95},
{ele_ctr, "ele_ctr", MX8ULP_A2 | MX93_A1 | MX95},
{ele_ofb, "ele_ofb", MX8ULP_A2 | MX93_A1 | MX95},
{ele_hash, "ele_hash", MX8ULP_A2 | MX93_A1 | MX95},
#else
{v2x_fast_mac, "v2x_fast_mac", MX95},
#endif
{NULL, NULL, MX8ULP_A2 | MX93_A1 | MX95},
};
#endif
