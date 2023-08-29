#ifndef IMX8_TESTS_LIST_H
#define IMX8_TESTS_LIST_H

#include "itest.h"

/*==========Tests list===========*/
int ele_rng_srv_001(void);
int ele_rng_perf(void);
int ele_cbc(void);
int ele_ecb(void);
int ele_sign_verify(void);
int ele_cmac(void);
int ele_hmac(void);
int ecdsa_brainpool_sign_verify(void);
int ele_gcm(void);
int ele_ccm(void);
int ele_randomness_gcm(void);

testsuite imx8_ts[] = {
/*==============================================================================================*/
/*============================================== ELE ===========================================*/
/*==============================================================================================*/
{ele_rng_srv_001, "ele_rng_srv_001", MX8ULP_A2 | MX93_A1},
{ele_rng_perf, "ele_rng_perf", MX8ULP_A2 | MX93_A1},
{ele_cbc, "ele_cbc", MX8ULP_A2 | MX93_A1},
{ele_ecb, "ele_ecb", MX8ULP_A2 | MX93_A1},
{ele_sign_verify, "ele_sign_verify", MX8ULP_A2 | MX93_A1},
{ele_cmac, "ele_cmac", MX8ULP_A2 | MX93_A1},
{ele_hmac,	 "ele_hmac", MX8ULP_A2 | MX93_A1},
{ecdsa_brainpool_sign_verify, "ecdsa_brainpool_sign_verify", MX8ULP_A2 | MX93_A1},
{ele_gcm, "ele_gcm", MX8ULP_A2 | MX93_A1},
{ele_ccm, "ele_ccm", MX8ULP_A2 | MX93_A1},
{ele_randomness_gcm, "ele_randomness_gcm", MX8ULP_A2 | MX93_A1},

{NULL, NULL, MX8ULP_A2 | MX93_A1},
};
#endif
