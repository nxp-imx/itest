#ifndef IMX8_TESTS_LIST_H
#define IMX8_TESTS_LIST_H

#include "itest.h"

/*==========Tests list===========*/
int ele_rng_srv_001(void);
int ele_rng_perf(void);

testsuite imx8_ts[] = {
/*==============================================================================================*/
/*============================================== ELE ===========================================*/
/*==============================================================================================*/
	{ele_rng_srv_001,	"ele_rng_srv_001",	MX8ULP_A2 | MX93_A1},
	{ele_rng_perf,		"ele_rng_perf",		MX8ULP_A2 | MX93_A1},

	{NULL, NULL, MX8ULP_A2 | MX93_A1},
};
#endif
