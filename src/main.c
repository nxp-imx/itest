#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include "test_api.h"

#define QXP 0x1
#define QM  0x2
#define DXL 0x4

int sm2_key_gen_001(void);
int v2x_rng_srv_001(void);
int v2x_ks_import_export_001(void);
int v2x_ks_import_export_001_part2(void);
int v2x_ks_bad_auth_001(void);
int v2x_ks_no_update_001(void);
int v2x_ks_no_update_001_part2(void);
int v2x_pub_key_recovery_001(void);
int v2x_pub_key_recovery_001_part2(void);

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
        {sm2_key_gen_001, "sm2_key_gen_001",   DXL},
	{v2x_rng_srv_001, "v2x_rng_srv_001",   DXL},
	{v2x_ks_import_export_001, "v2x_ks_import_export_001", DXL},
	{v2x_ks_import_export_001_part2, "v2x_ks_import_export_001_part2", DXL},
	{v2x_ks_bad_auth_001, "v2x_ks_bad_auth_001", DXL},
	{v2x_ks_no_update_001, "v2x_ks_no_update_001", DXL},
	{v2x_ks_no_update_001_part2, "v2x_ks_no_update_001_part2", DXL},
	{v2x_pub_key_recovery_001, "v2x_pub_key_recovery_001", DXL},
	{v2x_pub_key_recovery_001_part2, "v2x_pub_key_recovery_001_part2", DXL},
        {NULL, NULL},
};

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

        while ((c = getopt (argc, argv, "lvt:")) != -1)
                switch (c)
                {
                case 't':
                        test_name = optarg;
			break;
		case 'v':
			printf("testsuite v0.0\n");
                        return 0;
		case 'l':
			print_test_suite(ts);
                        return 0;
                case '?':
                        if (optopt == 't'){
                                fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                                fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                        }
                        else
                                fprintf (stderr,
                                         "Unknown option character -%c.\n",
                                         optopt);
			return 1;
                default:
                        abort();
                }
        printf("Test Suite 0.0\n");
        if (test_name == NULL){
		printf("no test in param...\n");
		return 0;
	}
        for ( i = 0; ts[i].tc_ptr != NULL; i++){
                if(!strcmp(ts[i].name, test_name)){
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
        return 0;
}


