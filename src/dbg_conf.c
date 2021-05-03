#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "itest.h"

testsuite dbg_ts[] = {
    {v2x_ping_all_mu,                        "v2x_ping_all_mu",                        DXL_A1},
    {v2x_heap_walk_sv0,                      "v2x_heap_walk_sv0",                      DXL_A1},
    {v2x_heap_walk_sv1,                      "v2x_heap_walk_sv1",                      DXL_A1},
    {v2x_heap_walk_sg0,                      "v2x_heap_walk_sg0",                      DXL_A1},
    {v2x_heap_walk_sg1,                      "v2x_heap_walk_sg1",                      DXL_A1},
    {v2x_heap_walk_v2xs,                     "v2x_heap_walk_v2xs",                     DXL_A1},
    {v2x_disable_cg,                         "v2x_disable_cg",                         DXL_A1},
    {v2x_enable_cg,                          "v2x_enable_cg",                          DXL_A1},
    {v2x_call_stack_v2xp,                    "v2x_call_stack_v2xp",                    DXL_A1},
    {v2x_call_stack_v2xs,                    "v2x_call_stack_v2xs",                    DXL_A1},
    {v2x_sched_stat_v2xp,                    "v2x_sched_stat_v2xp",                    DXL_A1},
    {v2x_sched_stat_v2xs,                    "v2x_sched_stat_v2xs",                    DXL_A1},

    {NULL, NULL, DXL_A1},
};
const char *lava_get_test_suite_dbg ="\n";

const char *lava_test_dbg ="\n";

const char *lava_dl_flash_dbg ="\n";