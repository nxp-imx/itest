#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "test_api.h"

#define QXP 0x1
#define QM  0x2
#define DXL 0x4

int v2x_chunk_swap_001(void);
int v2x_rng_srv_001(void);
int v2x_ks_import_export_001(void);
int v2x_ks_import_export_001_part2(void);
int v2x_ks_bad_auth_001(void);
int v2x_ks_no_update_001(void);
int v2x_ks_no_update_001_part2(void);
int v2x_ks_update_001(void);
int v2x_ks_update_001_part2(void);
int v2x_pub_key_recovery_001(void);
int v2x_pub_key_recovery_001_part2(void);
int v2x_cipher_aes_ecb_cbc_001(void);
int v2x_pub_key_decompression_001(void);
int v2x_cipher_ccm_perf(void);
int v2x_auth_enc_test(void);
int v2x_butterfly_key_exp_001(void);
int v2x_sign_gen_verify_perf(void);

typedef struct{
    int (*tc_ptr)(void);
    char *name;
    int target;
} testsuite;

typedef struct{
    int cur_test;
    int nb_fails;
} contex;

testsuite dxl_ts[] = {
    {v2x_chunk_swap_001,             "v2x_chunk_swap_001",             DXL},
    {v2x_rng_srv_001,                "v2x_rng_srv_001",                DXL},
    {v2x_ks_import_export_001,       "v2x_ks_import_export_001",       DXL},
    {v2x_ks_import_export_001_part2, "v2x_ks_import_export_001_part2", DXL},
    {v2x_ks_bad_auth_001,            "v2x_ks_bad_auth_001",            DXL},
    {v2x_ks_no_update_001,           "v2x_ks_no_update_001",           DXL},
    {v2x_ks_no_update_001_part2,     "v2x_ks_no_update_001_part2",     DXL},
    {v2x_ks_update_001,              "v2x_ks_update_001",              DXL},
    {v2x_ks_update_001_part2,        "v2x_ks_update_001_part2",        DXL},
    {v2x_pub_key_recovery_001,       "v2x_pub_key_recovery_001",       DXL},
    {v2x_pub_key_recovery_001_part2, "v2x_pub_key_recovery_001_part2", DXL},
    {v2x_cipher_aes_ecb_cbc_001,     "v2x_cipher_aes_ecb_cbc_001",     DXL},
    {v2x_auth_enc_test,              "v2x_auth_enc_test",              DXL},
    {v2x_pub_key_decompression_001,  "v2x_pub_key_decompression_001",  DXL},
    {v2x_butterfly_key_exp_001,      "v2x_butterfly_key_exp_001",      DXL},
    {v2x_cipher_ccm_perf,            "v2x_cipher_ccm_perf",            DXL},
    {v2x_sign_gen_verify_perf,       "v2x_sign_gen_verify_perf",       DXL},
    {NULL, NULL},
};

char *lava_get_test_suite =\
    "\n\
device_type: fsl-imx8dxl-evk-linux\n\
tags:\n\
- lifecycle-nxp-open\n\
- daas_mougins\n\
- stec\n\
job_name: IMX8_DXL - v2x_fw_test\n\
metadata:\n\
  submitter: bamboo\n\
timeouts:\n\
  job:\n\
    minutes: 240\n\
  action:\n\
    minutes: 60\n\
  connection:\n\
    minutes: 2\n\
priority: medium\n\
visibility: public\n\
context:\n\
  arch: arm64\n\
  extra_kernel_args: quiet loglevel=3\n\
  kernel_start_message: Welcome to Buildroot\n\
actions:\n\
- deploy:\n\
    namespace: console\n\
    timeout:\n\
      minutes: 3\n\
    to: tftp\n\
    kernel:\n\
      url: https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/Image/Image\n\
      type: image\n\
    ramdisk:\n\
      url: https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/rootfs.cpio.gz/rootfs.cpio.gz\n\
      compression: gz\n\
    modules:\n\
      url: https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/modules_lite.tar.bz2/modules_lite.tar.bz2\n\
      compression: bz2\n\
    dtb:\n\
      url: https://bamboo1.sw.nxp.com/browse/IM-LBLKFA2/latest/artifact/shared/dtb/imx8dxl-evk.dtb\n\
    os: oe\n\
- boot:\n\
    namespace: console\n\
    method: u-boot\n\
    failure_retry: 2\n\
    commands: nfs\n\
    auto_login:\n\
      login_prompt: \"(.*) login:\"\n\
      username: root\n\
    prompts:\n\
    - \"root@(.*):~#\"\n\
    timeout:\n\
      minutes: 2\n\
- test:\n\
    namespace: console\n\
    connection-namespace: console\n\
    timeout:\n\
      minutes: 2\n\
      skip: true\n\
    definitions:\n\
    - from: inline\n\
      name: Get_v2x_fw_test\n\
      path: inline/run_tests.yaml\n\
      repository:\n\
        metadata:\n\
          name: Get_v2x_fw_test\n\
          description: Download and flash test suite\n\
          format: Lava-Test Test Definition 1.0\n\
        run:\n\
          steps:\n\
          - modprobe g_ether\n\
          - busybox udhcpc -i usb0\n\
          - ip addr\n\
          - mount /dev/mmcblk1p2 /mnt/\n\
          - cd /mnt/opt\n\
          - lava-test-case get_test_suite --shell wget -t 2 --timeout=30 --no-check-certificate -q -O v2x_fw_test %s\n\
          - chmod +x v2x_fw_test\n\
          - sync\n\
\n\
";

char *lava_test =\
    "\n\
- boot:\n\
    namespace: console\n\
    method: u-boot\n\
    failure_retry: 2\n\
    commands: nfs\n\
    auto_login:\n\
      login_prompt: \"(.*) login:\"\n\
      username: root\n\
    prompts:\n\
    - \"root@(.*):~#\"\n\
    timeout:\n\
      minutes: 2\n\
- test:\n\
    namespace: console\n\
    connection-namespace: console\n\
    timeout:\n\
      minutes: 2\n\
      skip: true\n\
    definitions:\n\
    - from: inline\n\
      name: %s\n\
      path: inline/run_tests.yaml\n\
      repository:\n\
        metadata:\n\
          name: %s\n\
          description: test %s\n\
          format: Lava-Test Test Definition 1.0\n\
        run:\n\
          steps:\n\
          - modprobe g_ether\n\
          - busybox udhcpc -i usb0\n\
          - ip addr\n\
          - mount /dev/mmcblk1p2 /mnt/\n\
          - cd /mnt/opt\n\
          - cp -r v2x_hsm /etc/\n\
          - rm -rf v2x_hsm\n\
          - lava-test-case v2x_fw_test --shell ./v2x_fw_test -t %s\n\
          - cp -r /etc/v2x_hsm /mnt/opt\n\
          - sync \n\
";

void gen_lava_test(testsuite *ts, char *addr_ts){

    int i;

    printf(lava_get_test_suite, addr_ts);
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        printf(lava_test, ts[i].name, ts[i].name, ts[i].name, ts[i].name);
    }
}

void print_test_suite(testsuite *ts){
    int i;
        
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        printf("test %d: %s\n", i, ts[i].name);
    }
}

int main(int argc, char *argv[]){
        
    int i = 0;
    int status = 0;
    testsuite *ts = dxl_ts;
    char *test_name = NULL;
    int c;
        
    opterr = 0;

    while ((c = getopt (argc, argv, "lvg:t:")) != -1) {
        switch (c)
        {
        case 't':
            test_name = optarg;
            printf("testsuite %s\n", test_name);
            break;
        case 'v':
            printf("testsuite v1.0\n");
            return 1;
        case 'l':
            print_test_suite(ts);
            return 1;
        case 'g':
            gen_lava_test(ts, optarg);
            return 1;
        case '?':
            if ((optopt == 't') || (optopt == 'g')){
                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
            }
            else{
                fprintf (stderr,
                         "Unknown option character -%c.\n",
                         optopt);
                return 0;
            }
        default:
            abort();
        }
    }
    printf("Test Suite 1.0\n");
    printf("testsuite %s\n", test_name);
    if (test_name == NULL){
        printf("no test in param...\n");
        print_test_suite(ts);
        return 0;
    }
    for ( i = 0; ts[i].tc_ptr != NULL; i++){
        if (!strcmp(ts[i].name, test_name)){
            printf("%s: ", ts[i].name);
            status = ts[i].tc_ptr();
            if (!status){
                printf("FAIL\n");
            }
            else
                printf("PASS\n");
        }
    }
    printf("end of tests\n");
    return !status;
}


