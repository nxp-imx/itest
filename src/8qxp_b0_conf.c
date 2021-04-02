#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "itest.h"

testsuite qxp_b0_ts[] = {
    {openssl_sanity,                         "openssl_sanity",                         QXP_B0},
    
    {NULL, NULL, QXP_C0},
};

const char *lava_get_test_suite_qxp_b0 ="\n";

const char *lava_test_qxp_b0 ="\n";

const char *lava_dl_flash_bootimg_qxp_b0 ="\n";
