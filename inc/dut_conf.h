#ifndef DXL_CONF_H
#define DXL_CONF_H
#include "itest.h"

// DXL A1 CONF
extern const char *lava_test_dxl;
extern const char *lava_get_test_suite_dxl;
extern const char *lava_dl_flash_bootimg_dxl;
extern testsuite dxl_ts[];

// QXP C0 CONF
extern const char *lava_test_qxp_c0;
extern const char *lava_get_test_suite_qxp_c0;
extern const char *lava_dl_flash_bootimg_qxp_c0;
extern testsuite qxp_c0_ts[];

// QXP B0 CONF
extern const char *lava_test_qxp_b0;
extern const char *lava_get_test_suite_qxp_b0;
extern const char *lava_dl_flash_bootimg_qxp_b0;
extern testsuite qxp_b0_ts[];

// DBG CONF
extern const char *lava_test_dbg;
extern const char *lava_get_test_suite_dbg;
extern const char *lava_dl_flash_bootimg_dbg;
extern testsuite dbg_ts[];


#endif
