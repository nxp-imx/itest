#include <openssl/obj_mac.h>
#include "test_vectors/common.h"
#include "ijson_utils.h"
#include "crypto_utils/ecc_sign.h"
#include "itest.h"

typedef struct {
	int nb_tests;
	int nb_fails;
	int expected_result;
	hsm_signature_scheme_id_t curve;
	uint8_t size_pubk;
    uint8_t message[MAX_MSG_SIZE];
    uint32_t message_length;
    uint8_t public_key[MAX_KEY_SIZE];
    uint8_t signature[MAX_SIG_SIZE];
} wycheproof_sign_json_t;

#define VALID 0x1U
#define INVALID 0x0U

static wycheproof_sign_json_t sign_verify_ctx;

#define NB_ALGO_WY 4

static hsm_signature_scheme_id_t curve2seco_libs(const char *in_c, uint8_t *pub_key) {
	const char curve_list[4][255] = {
		"secp224r1",
		"secp256r1",
		"secp384r1",
		"secp521r1",
	};
	const hsm_signature_scheme_id_t seco_libs_list[4] = {
		HSM_SIGNATURE_SCHEME_ECDSA_SHA224,
		HSM_SIGNATURE_SCHEME_ECDSA_SHA256,
		HSM_SIGNATURE_SCHEME_ECDSA_SHA384,
		HSM_SIGNATURE_SCHEME_ECDSA_SHA512,
	};
	const uint8_t size_pubkey[4] = {
		0x38,
		0x40,
		0x60,
		0x84,
	};
	int i;
	*pub_key = 0;

	for (i = 0; i < NB_ALGO_WY; i++) {
		if (!strcmp(curve_list[i], in_c)) {
			//ITEST_LOG("curve %s\n", curve_list[i]);
			*pub_key = size_pubkey[i];
			return seco_libs_list[i];
		}
	}
	return HSM_SIGNATURE_SCHEME_ECDSA_SHA256;
}

#if 0
static int curve2openssl(const char *in_c, uint8_t *pub_key, char *dgst) {
	const char curve_list[5][255] = {
		"secp256r1",
		"secp384r1",
		"secp521r1",
		"brainpoolP256r1",
		"brainpoolP384r1"
	};
	const char dgst_list[5][255] = {
		"sha256",
		"sha384",
		"sha512",
		"sha256",
		"sha384"
	};
	const int seco_libs_list[5] = {
		NID_X9_62_prime256v1,
		NID_secp384r1,
		NID_secp521r1,
		NID_brainpoolP256r1,
		NID_brainpoolP384r1,
	};
	const uint8_t size_pubkey[5] = {
		0x40,
		0x60,
		0x84,
		0x40,
		0x60,		
	};
	int i;
	*pub_key = 0;

	for (i = 0; i < NB_ALGO_WY; i++) {
		if (!strcmp(curve_list[i], in_c)) {
			//ITEST_LOG("curve %s\n", curve_list[i]);
			*pub_key = size_pubkey[i];
			memcpy(dgst, dgst_list, 10);
			return seco_libs_list[i];
		}
	}
	return NID_X9_62_prime256v1;
}
#endif

static void print_hex(uint8_t *in, int len) {
	int j;
	for (j = 0; j < len; j++) {
		ITEST_LOG("%02x", in[j]);
	}
	ITEST_LOG("\n");
}

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
	char *r_ptr = tmp_sign + 4;
	char *s_ptr = r_ptr + r_size;
	int s_size = s_ptr[1];
	int pad = r_size % 2;
	int total_size = r_size - pad;

	switch (sign_verify_ctx.curve)
    {
	case HSM_SIGNATURE_SCHEME_ECDSA_SHA224:
		total_size = 0x38;
		break;
	case HSM_SIGNATURE_SCHEME_ECDSA_SHA256:
		total_size = 0x40;
		break;
	case HSM_SIGNATURE_SCHEME_ECDSA_SHA384:
		total_size = 0x60;
		break;
	case HSM_SIGNATURE_SCHEME_ECDSA_SHA512:
		total_size = 0x84;
		break;
	default:
		total_size = 0;
		break;
    }

	if (sign_verify_ctx.curve == HSM_SIGNATURE_SCHEME_ECDSA_SHA512) {
		r_size = tmp_sign[4];
		r_ptr = tmp_sign + 5;
		s_ptr = r_ptr + r_size;
		s_size = s_ptr[1];
		pad = r_size % 2;
		pld_size = r_size + s_size + 7;

		if ((tmp_sign_size == 0) || (tmp_sign[0] != 0x30) || (tmp_sign[1] > tmp_sign_size) || (tmp_sign[1] > buff_out_len) 
			|| ((r_size + s_size + 7) > buff_out_len) || ((r_size + s_size + 7) != tmp_sign_size) || ((pld_size) != tmp_sign_size)
			|| (tmp_sign[3] != 0x02) || (s_ptr[0] != 0x02)) {
			return 0;
		}
	}

	else if ((tmp_sign_size == 0) || (tmp_sign[0] != 0x30) || (tmp_sign[1] > tmp_sign_size) || (tmp_sign[1] > buff_out_len) 
		|| ((r_size + s_size + 7) > buff_out_len) || ((r_size + s_size + 6) != tmp_sign_size) || ((pld_size + 2) != tmp_sign_size)
		|| (tmp_sign[2] != 0x02) || (s_ptr[0] != 0x02)) {
		return 0;
	}

	s_ptr += 2;
	if (total_size != 0) {
		memset(out,0,total_size);
		pad = (total_size/2) - r_size;
		if (pad < 0) {
			memcpy(out, r_ptr - pad, r_size);
		}
		else {
			memcpy(out + pad, r_ptr, r_size);
		}
		pad = (total_size / 2) - s_size;
		if (pad < 0) {
			memcpy(out + (total_size/2), r_ptr + 2 + r_size - pad, s_size);
		}
		else {
			memcpy(out + (total_size/2) + pad, r_ptr + 2 + r_size, s_size);
		}
		return total_size;
	}

	total_size = r_size + pad;
	memcpy(out, tmp_sign+4+pad, r_size-pad);
	out += r_size-pad;
	pad = s_size % 2;
	memcpy(out, s_ptr+pad, s_size-pad);

	return total_size + s_size-pad;
}

static int handle_tests(struct json_object *test) {

	int sign_size = 0;
	char *expect_str = NULL;
	
	sign_verify_ctx.expected_result = INVALID;
	sign_verify_ctx.message_length = hexstr_to_char(
		json_object_get_string(json_object_object_get(test,"msg")), 
		(char *)sign_verify_ctx.message,
		MAX_MSG_SIZE);
	sign_size = sign_hexstr2char(
		json_object_get_string(json_object_object_get(test,"sig")), 
		(char *)sign_verify_ctx.signature,
		MAX_SIG_SIZE);
	expect_str = (char *) json_object_get_string(json_object_object_get(test,"result"));
	if (expect_str != NULL) {
		// don't test acceptable test
		if (strcmp("acceptable", expect_str) == 0) {
			return 0;
		}
		sign_verify_ctx.expected_result = (strcmp("valid", expect_str) == 0) ? VALID : INVALID;
	}
	return sign_size;
}

#if 1
static int handle_testcases(struct json_object *testcases) {

	struct json_object *tests = NULL;
	struct json_object *test = NULL;
	struct json_object *key_obj = NULL;
	int nb_tests_case = 0, i, result;
	open_session_args_t args;
    open_svc_sign_ver_args_t sig_ver_srv_args;
    op_verify_sign_args_t sig_ver_args;    
    hsm_hdl_t sv0_sess, sv0_sig_ver_serv;
    hsm_verification_status_t status;

	if (json_object_object_get_ex(testcases, "tests", &tests))
	{
		nb_tests_case = json_object_array_length(tests);
	}

	if (json_object_object_get_ex(testcases, "key", &key_obj))
	{
		key_hexstr2char(
			json_object_get_string(json_object_object_get(key_obj,"uncompressed")), 
			(char *)sign_verify_ctx.public_key,
			MAX_KEY_SIZE);
		sign_verify_ctx.curve = curve2seco_libs(
			json_object_get_string(json_object_object_get(key_obj,"curve")), &sign_verify_ctx.size_pubk);
		//ITEST_LOG("size pk: %d\n", sign_verify_ctx.size_pubk);
	}

    /* Open session on SV0*/
    args.session_priority = HSM_OPEN_SESSION_PRIORITY_HIGH;
    args.operating_mode =
        HSM_OPEN_SESSION_LOW_LATENCY_MASK | HSM_OPEN_SESSION_NO_KEY_STORE_MASK;
    ASSERT_EQUAL(hsm_open_session(&args, &sv0_sess), HSM_NO_ERROR);

    /* Open signature verification service */
    ASSERT_EQUAL(hsm_open_signature_verification_service(sv0_sess,
        &sig_ver_srv_args, &sv0_sig_ver_serv), HSM_NO_ERROR);

	for (i = 0; i < nb_tests_case; i++) {
		test = json_object_array_get_idx(tests, i );
		sig_ver_args.signature_size = 1 + handle_tests(test); /* Add 1 byte for Ry */
		//ITEST_LOG("sign size: %d\n", sig_ver_args.signature_size);
		if (sig_ver_args.signature_size == sign_verify_ctx.size_pubk + 1) {
			/* Fill struct data */
			sig_ver_args.key = sign_verify_ctx.public_key;
			sig_ver_args.message = sign_verify_ctx.message;
			sig_ver_args.signature = sign_verify_ctx.signature;
			sig_ver_args.key_size = sign_verify_ctx.size_pubk;
			sig_ver_args.message_size = sign_verify_ctx.message_length;
			sig_ver_args.scheme_id = sign_verify_ctx.curve;
			sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
			
			/* Call sig ver API */
			ASSERT_EQUAL_W(hsm_verify_signature(sv0_sig_ver_serv, &sig_ver_args, &status), HSM_NO_ERROR);
			result = status == HSM_VERIFICATION_STATUS_SUCCESS ? VALID : INVALID;
			if (result != sign_verify_ctx.expected_result) {
				ITEST_LOG("testcase %s Fail, expected:%d, comment: %s\n", json_object_get_string(json_object_object_get(test,"tcId")), sign_verify_ctx.expected_result,
				json_object_get_string(json_object_object_get(test,"comment")));
				ITEST_LOG("pubk: ");
				print_hex(sign_verify_ctx.public_key, sign_verify_ctx.size_pubk);
				ITEST_LOG("sign: ");
				print_hex(sign_verify_ctx.signature, sig_ver_args.signature_size);
				ITEST_LOG("msg: ");
				print_hex(sign_verify_ctx.message, sign_verify_ctx.message_length);	
				sign_verify_ctx.nb_fails++;
			}
			sign_verify_ctx.nb_tests++;
		}
	}
	/* Close service and session */
	ASSERT_EQUAL(hsm_close_signature_verification_service(sv0_sig_ver_serv), HSM_NO_ERROR);
	ASSERT_EQUAL(hsm_close_session(sv0_sess), HSM_NO_ERROR);
	return 0;
}
#else
static int handle_testcases(struct json_object *testcases) {

	struct json_object *tests = NULL;
	struct json_object *test = NULL;
	struct json_object *key_obj = NULL;
	int nb_tests_case = 0, i;
    op_verify_sign_args_t sig_ver_args;    
	int curve;
	char dgst[15];

	if (json_object_object_get_ex(testcases, "tests", &tests))
	{
		nb_tests_case = json_object_array_length(tests);
	}

	if (json_object_object_get_ex(testcases, "key", &key_obj))
	{
		key_hexstr2char(
			json_object_get_string(json_object_object_get(key_obj,"uncompressed")), 
			(char *)sign_verify_ctx.public_key,
			MAX_KEY_SIZE);
		sign_verify_ctx.curve = curve2seco_libs(
			json_object_get_string(json_object_object_get(key_obj,"curve")), &sign_verify_ctx.size_pubk);
		curve = curve2openssl(
			json_object_get_string(json_object_object_get(key_obj,"curve")), &sign_verify_ctx.size_pubk, dgst);
		ITEST_LOG("size pk: %d\n", sign_verify_ctx.size_pubk);
		for (int j = 0; j < sign_verify_ctx.size_pubk; j++) {
			ITEST_LOG("%02x", sign_verify_ctx.public_key[j]);
		}
		ITEST_LOG("\n");
	}

	for (i = 0; i < nb_tests_case; i++) {
		test = json_object_array_get_idx(tests, i );
		sig_ver_args.signature_size = handle_tests(test); /* Add 1 byte for Ry */
		ITEST_LOG("sign size: %d\n", sig_ver_args.signature_size);
		for (int j = 0; j < sig_ver_args.signature_size; j++) {
			ITEST_LOG("%02x", sign_verify_ctx.signature[j]);
		}
		ITEST_LOG("\n");
		if (sig_ver_args.signature_size == sign_verify_ctx.size_pubk) {
			/* Fill struct data */
			sig_ver_args.key = sign_verify_ctx.public_key;
			sig_ver_args.message = sign_verify_ctx.message;
			sig_ver_args.signature = sign_verify_ctx.signature;
			sig_ver_args.key_size = sign_verify_ctx.size_pubk;
			sig_ver_args.message_size = sign_verify_ctx.message_length;
			sig_ver_args.scheme_id = sign_verify_ctx.curve;
			sig_ver_args.flags = HSM_OP_PREPARE_SIGN_INPUT_MESSAGE;
			if (icrypto_verify_signature(curve, (unsigned char *) sig_ver_args.key, (int)sign_verify_ctx.size_pubk, NULL,\
												0, (unsigned char *) sig_ver_args.message, sig_ver_args.message_size, dgst,\
												(unsigned char *) sig_ver_args.signature, (int)sig_ver_args.signature_size) != sign_verify_ctx.expected_result) {
													ITEST_LOG("testcase %s Fail, expected:%d, comment: %s\n", json_object_get_string(json_object_object_get(test,"tcId")), sign_verify_ctx.expected_result,
													json_object_get_string(json_object_object_get(test,"comment")));
													sign_verify_ctx.nb_fails++;;
												}
			sign_verify_ctx.nb_tests++;
		}
	}

	return 0;
}
#endif

static int handle_testgroup(struct json_object *testgroups) {

	struct json_object *testcases = NULL;
	int i, nb_testgroups;

	nb_testgroups = json_object_array_length(testgroups);
	ITEST_LOG("Number of testGroups: %ld\n", json_object_array_length(testgroups));
	for (i = 0; i < nb_testgroups; i++) {
		testcases = json_object_array_get_idx(testgroups, i );
		handle_testcases(testcases);
	}
	ITEST_LOG("end of tests: %d/%d tests fails\n", sign_verify_ctx.nb_fails, sign_verify_ctx.nb_tests);
	return 0;
}

static int parse_tv(struct json_object *new_obj) {
	
	struct json_object *testgroups = NULL;
	sign_verify_ctx.expected_result = INVALID;
	sign_verify_ctx.nb_fails = 0;
	sign_verify_ctx.nb_tests = 0;
	sign_verify_ctx.curve = HSM_SIGNATURE_SCHEME_ECDSA_SHA256;

	if (json_object_object_get_ex(new_obj, "algorithm", &testgroups))
    {
        ITEST_LOG("Algo: %s\n", json_object_get_string(json_object_object_get(new_obj, "algorithm")));

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
