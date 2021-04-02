#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "itest.h"

testsuite qxp_c0_ts[] = {
    {seco_ks_import_export_001,              "seco_ks_import_export_001",              QXP_C0},
    {seco_ks_import_export_001_part2,        "seco_ks_import_export_001_part2",        QXP_C0},
    {seco_ks_bad_auth_001,                   "seco_ks_bad_auth_001",                   QXP_C0},
    //{openssl_sanity,                         "openssl_sanity",                         QXP_C0},
    
    {NULL, NULL, QXP_C0},
};

const char *lava_get_test_suite_qxp_c0 ="\n";

const char *lava_test_qxp_c0 ="\n";

const char *lava_dl_flash_bootimg_qxp_c0 ="\n";
