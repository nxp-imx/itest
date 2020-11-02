#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "itest.h"

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
    {v2x_parallel_sign_gen_ver_001,  "v2x_parallel_sign_gen_ver_001",  DXL},
    {v2x_cipher_ccm_perf,            "v2x_cipher_ccm_perf",            DXL},
    {v2x_sign_gen_verify_perf,       "v2x_sign_gen_verify_perf",       DXL},
    {v2x_perf_sig_ver_nistp256,      "v2x_perf_sig_ver_nistp256",      DXL},
    {v2x_perf_sig_ver_nistp384,      "v2x_perf_sig_ver_nistp384",      DXL},
    {v2x_perf_sig_ver_sm2,           "v2x_perf_sig_ver_sm2",           DXL},
    {NULL, NULL, DXL},
};

const char *lava_get_test_suite_dxl =\
    "\n\
device_type: fsl-imx8dxl-evk-linux\n\
tags:\n\
- lifecycle-nxp-open\n\
- daas_mougins\n\
- stec\n\
job_name: IMX8_DXL - itest\n\
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
      url: %s\n\
      type: image\n\
    ramdisk:\n\
      url: %s\n\
      compression: gz\n\
    modules:\n\
      url: %s\n\
      compression: bz2\n\
    dtb:\n\
      url: %s\n\
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
      name: Get_itest\n\
      path: inline/run_tests.yaml\n\
      repository:\n\
        metadata:\n\
          name: Get_itest\n\
          description: Download and flash test suite\n\
          format: Lava-Test Test Definition 1.0\n\
        run:\n\
          steps:\n\
          - modprobe g_ether\n\
          - busybox udhcpc -i usb0\n\
          - ip addr\n\
          - mount /dev/mmcblk1p2 /mnt/\n\
          - cd /mnt/opt\n\
          - bash -c 'rm -rf v2x_test'\n\
          - mkdir v2x_test\n\
          - cd v2x_test\n\
          - lava-test-case get_test_suite --shell wget -t 2 --timeout=30 --no-check-certificate -q -O itest %s\n\
          - chmod +x itest\n\
          - sync\n\
\n\
";

const char *lava_test_dxl =\
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
          - cd /mnt/opt/v2x_test\n\
          - bash -c 'cp -r v2x_hsm /etc/ 2>/dev/null || :'\n\
          - bash -c 'rm -rf v2x_hsm 2>/dev/null || :'\n\
          - lava-test-case itest --shell ./itest -t %s\n\
          - bash -c 'cp -r /etc/v2x_hsm /mnt/opt 2>/dev/null || :'\n\
          - sync \n\
";

const char *lava_dl_flash_bootimg_dxl =\
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
    - \"'\"root@(.*):~#\"'\"\n\
    timeout:\n\
      minutes: 2\n\
\n\
- test:\n\
    namespace: console\n\
    connection-namespace: console\n\
    timeout:\n\
      minutes: 2\n\
      skip: true\n\
    definitions:\n\
    - from: inline\n\
      name: Deploy_bootimage\n\
      path: inline/run_tests.yaml\n\
      repository:\n\
        metadata:\n\
          name: Deploy_bootimage\n\
          description: Download and flash a new bootimage\n\
          format: Lava-Test Test Definition 1.0\n\
        run:\n\
          steps:\n\
          - modprobe g_ether\n\
          - busybox udhcpc -i usb0\n\
          - ip addr\n\
          - lava-test-case retrieve_bootimg --shell wget -t 2 --timeout=30 --no-check-certificate -q -O bootimg.bin %s\n\
          - lava-test-case test_bootimg_size --shell [[ $(wc -c < bootimg.bin) -gt 900000 ]]\n\
          - lava-test-case flash_bootimg dd if=bootimg.bin of=/dev/mmcblk1 bs=1 seek=32k conv=notrunc,sync,noerror\n\
          - sync\n\
";
