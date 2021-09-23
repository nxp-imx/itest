#include <openssl/obj_mac.h>
#include "test_vectors/common.h"
#include "ijson_utils.h"
#include "itest.h"

int hexstr_to_char(const char* hexstr, char *out, int buff_out_len)
{
	if (hexstr == NULL) {
		return 0;
	}
    int len = strlen(hexstr);
    if(len % 2 != 0)
        return 0;
    int final_len = len / 2;
	if (buff_out_len < final_len)
		return 0;
    for (int i=0, j=0; j<final_len; i+=2, j++)
        out[j] = (hexstr[i] % 32 + 9) % 25 * 16 + (hexstr[i+1] % 32 + 9) % 25;
    out[final_len] = '\0';
    return final_len;
}

int key_hexstr2char(const char* hexstr, char *out, int buff_out_len) {
	// remove 0x04 first byte of the signature
	return hexstr_to_char(hexstr+2, out, buff_out_len);
}

// ASN conversion to raw r-s
int sign_hexstr2char(const char* hexstr, char *out, int buff_out_len) {
	char tmp_sign[MAX_SIG_SIZE + 2056]; 
	int tmp_sign_size = hexstr_to_char(hexstr, tmp_sign, buff_out_len);
	int r_size = tmp_sign[3];
	int pld_size = tmp_sign[1];
	char *s_ptr = tmp_sign+4+r_size;
	int s_size = s_ptr[1];
	int pad = r_size % 2;
	int total_size = r_size - pad;

	if ((tmp_sign_size == 0) || (tmp_sign[0] != 0x30) || (tmp_sign[1] > tmp_sign_size) || (tmp_sign[1] > buff_out_len) 
		|| ((r_size + s_size + 7) > buff_out_len) || ((r_size + s_size + 6) != tmp_sign_size) || ((pld_size + 2) != tmp_sign_size)
		|| (tmp_sign[2] != 0x02) || (s_ptr[0] != 0x02)) {
		return 0;
	}

	s_ptr += 2;

	memcpy(out, tmp_sign+4+pad, r_size-pad);
	out += r_size-pad;
	pad = s_size % 2;
	memcpy(out, s_ptr+pad, s_size-pad);

	return total_size + s_size-pad;
}

#define VALID 0x1U
#define INVALID 0x0U
static int handle_tests(struct json_object *test, test_data_verify_t *current_tv, int *expected) {

	int sign_size;
	char *expect_str = NULL;
	
	*expected = INVALID;
	current_tv->message_length = hexstr_to_char(
		json_object_get_string(json_object_object_get(test,"msg")), 
		(char *)current_tv->message,
		MAX_MSG_SIZE);
	sign_size = sign_hexstr2char(
		json_object_get_string(json_object_object_get(test,"sig")), 
		(char *)current_tv->signature,
		MAX_MSG_SIZE);
	if (sign_size != 64) {
		return 0;
	}
	expect_str = (char *) json_object_get_string(json_object_object_get(test,"result"));
	if (expect_str != NULL) {
		// don't test acceptable test
		if (strcmp("acceptable", expect_str) == 0) {
			return 0;
		}
		*expected = (strcmp("valid", expect_str) == 0) ? VALID : INVALID;
	}
	return sign_size;
}
static int nb_tests_ = 0;
static int nb_fails = 0;
static int handle_testcases(struct json_object *testcases) {

	struct json_object *tests = NULL;
	struct json_object *test = NULL;
	struct json_object *key_obj = NULL;
	int nb_tests = 0, i, expected, result;
	test_data_verify_t current_tv;

	open_session_args_t args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    op_verify_sign_args_t sig_ver_args;    
    hsm_hdl_t sv0_sess, sv0_sig_ver_serv;
    hsm_verification_status_t status;

	if (json_object_object_get_ex(testcases, "tests", &tests))
	{
		nb_tests = json_object_array_length(tests);
	}

	if (json_object_object_get_ex(testcases, "key", &key_obj))
	{
		key_hexstr2char(
			json_object_get_string(json_object_object_get(key_obj,"uncompressed")), 
			(char *)current_tv.public_key,
			MAX_KEY_SIZE);
	}

    /* Open session on SV0*/
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode =
        HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv0_sess), HSM_NO_ERROR);

    /* Open signature verification service */
    sig_ver_srv_args.flags = 0;
    ASSERT_EQUAL(hsm_open_signature_verification_service(sv0_sess,
        &sig_ver_srv_args, &sv0_sig_ver_serv), HSM_NO_ERROR);

	for (i = 0; i < nb_tests; i++) {
		test = json_object_array_get_idx(tests, i );
		sig_ver_args.signature_size = 1 + handle_tests(test, &current_tv, &expected); /* Add 1 byte for Ry */
		if (sig_ver_args.signature_size == 65) {
			/* Fill struct data */
			sig_ver_args.key = current_tv.public_key;
			sig_ver_args.message = current_tv.message;
			sig_ver_args.signature = current_tv.signature;
			sig_ver_args.key_size = 64;
			sig_ver_args.message_size = current_tv.message_length;
			sig_ver_args.scheme_id = HSM_SIGNATURE_SCHEME_ECDSA_NIST_P256_SHA_256;
			sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
			/*if (icrypto_verify_signature(NID_X9_62_prime256v1, (unsigned char *) sig_ver_args.key, 0x40, NULL,\
												0, (unsigned char *) sig_ver_args.message, sig_ver_args.message_size, "sha256",\
												(unsigned char *) sig_ver_args.signature, 0x40) != expected) {
													printf("testcase %s Fail, expected:%d, comment: %s\n", json_object_get_string(json_object_object_get(test,"tcId")), expected,
													json_object_get_string(json_object_object_get(test,"comment")));
													nb_fails++;
												}
			nb_tests_++;
			*/
			/* Call sig ver API */
			ASSERT_EQUAL_W(hsm_verify_signature(sv0_sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
			result = status == HSM_VERIFICATION_STATUS_SUCCESS ? VALID : INVALID;
			if (result != expected) {
				printf("testcase %s Fail, expected:%d, comment: %s\n", json_object_get_string(json_object_object_get(test,"tcId")), expected,
				json_object_get_string(json_object_object_get(test,"comment")));
				nb_fails++;
			}
			nb_tests_++;
		}
	}
	/* Close service and session */
	ASSERT_EQUAL(hsm_close_signature_verification_service(sv0_sig_ver_serv), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
	return 0;
}

static int handle_testgroup(struct json_object *testgroups) {

	struct json_object *testcases = NULL;
	int i, nb_testgroups;

	nb_testgroups = json_object_array_length(testgroups);
	printf("Number of testGroups: %ld\n", json_object_array_length(testgroups));
	for (i = 0; i < nb_testgroups; i++) {
		testcases = json_object_array_get_idx(testgroups, i );
		handle_testcases(testcases);
	}
	printf("end of tests: %d/%d tests fails\n", nb_fails, nb_tests_);
	return 0;
}

static int parse_tv(struct json_object *new_obj) {
	
	//char algo[256];
	struct json_object *testgroups = NULL;

	if (json_object_object_get_ex(new_obj, "algorithm", &testgroups))
    {
        printf("Algo: %s\n", json_object_get_string(json_object_object_get(new_obj, "algorithm")));

    }
	if (json_object_object_get_ex(new_obj, "testGroups", &testgroups))
    {
		handle_testgroup(testgroups);
	}

	return 0;
}

int run_wycheproof_json(char *f_in) {
	parse_file(f_in, parse_tv);
	return 0;
}
