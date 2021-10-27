#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include "itest.h"
#include "crypto_utils/dgst.h"

static EC_KEY *EC_KEY_bin2key(int curve, unsigned char *inpub, int size_pub, unsigned char *inpriv, int size_priv) {
    
    EC_KEY * eckey = EC_KEY_new_by_curve_name(curve);
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    BIGNUM *pk = NULL; 

    if (inpub != NULL) {
        x = BN_bin2bn(inpub, size_pub/2, NULL);
        y = BN_bin2bn(&inpub[size_pub/2], size_pub/2, NULL);
        if (EC_KEY_set_public_key_affine_coordinates(eckey, x, y) != 1) {
            ITEST_LOG("Fail to convert the pub key...\n");
            return NULL;
        }
    }
    if (inpriv != NULL) {
        pk = BN_bin2bn(inpriv, size_priv, NULL);
        if (EC_KEY_set_private_key(eckey, pk) != 1) {
            ITEST_LOG("Fail to convert the priv key...\n");
            return NULL;
        }
    }
    if (x != NULL)
        BN_free(x);
    if (y != NULL)
        BN_free(y);
    if (pk != NULL)
        BN_free(pk);
    
    return eckey;
}

static int EC_KEY_key2bin(EC_KEY *eckey, unsigned char *outpub, int *size_pub, unsigned char *outpriv, int *size_priv, int curve) {

    const BIGNUM *priv;
    const EC_POINT *pubk;
    BIGNUM *x = NULL;
    BIGNUM *y = NULL;
    const EC_GROUP *group;
    BN_CTX *bn_ctx;

    if (eckey == NULL || ((size_pub == NULL) && (outpub != NULL)) || ((size_priv == NULL) && (outpriv != NULL))) {
        ITEST_LOG("EC_KEY_key2bin bad param...\n");
        return 0;
    }

    bn_ctx = BN_CTX_new();
    group = EC_KEY_get0_group(eckey);
    priv = EC_KEY_get0_private_key(eckey);
    pubk = EC_KEY_get0_public_key(eckey);
    x = BN_new();
    y = BN_new();

    if (group == NULL || priv == NULL || pubk == NULL || bn_ctx == NULL || x ==NULL || y == NULL) {
        ITEST_LOG("EC_KEY_key2bin Fail to convert the key...\n");
        return 0;       
    }

    if (EC_POINT_get_affine_coordinates(group, pubk, x, y, bn_ctx) != 1) {
        ITEST_LOG("EC_KEY_key2bin Fail to convert the pub key...\n");
        return 0;     
    }

    switch (curve)
    {
        case NID_X9_62_prime256v1:
        case NID_brainpoolP256r1:
            *size_priv = 0x20;
            break;
        case NID_secp384r1:
        case NID_brainpoolP384r1:
            *size_priv = 0x30;
            break;
        case NID_secp521r1:
            *size_priv = 0x42;
            break;
        default:
            *size_priv = 0;
            break;
    }

    if (size_priv == 0)
        *size_priv = BN_bn2bin(priv, outpriv);
    else
        *size_priv = BN_bn2binpad(priv, outpriv, *size_priv);
    ITEST_LOG("BN_bn2bin priv key size = %d...\n", *size_priv);
    *size_pub = 0;
    *size_pub += BN_bn2binpad(x, outpub, *size_priv);
    *size_pub += BN_bn2binpad(y, &outpub[*size_pub], *size_priv);

    BN_free(x);
    BN_free(y);
    BN_CTX_free(bn_ctx);

    return 1;
}

int icrypto_generate_key_pair(int curve, unsigned char *outpub, int *size_pub, unsigned char *outpriv, int *size_priv) {

    EC_KEY *eckey;
    int ret = 0;

    if (size_pub == NULL || outpub == NULL || size_priv == NULL || outpriv == NULL) {
        ITEST_LOG("icrypto_generate_key_pair bad param...\n");
        return ret;        
    }
    eckey = EC_KEY_new_by_curve_name(curve);
    if (eckey == NULL) {
        ITEST_LOG("Bad curve...\n");
        return ret;
    }

    if (EC_KEY_generate_key(eckey) == 0) {
        ITEST_LOG("Fail to generate the key...\n");
        return ret;
    }

    ret = EC_KEY_key2bin(eckey, outpub, size_pub, outpriv, size_priv, curve);
    if (eckey != NULL)
        EC_KEY_free(eckey);
    return ret;
}

// if dgst is null -> input as digest
int icrypto_generate_signature(int curve, unsigned char *privk, int size_privk, unsigned char *in, int size, char *dgst, unsigned char *out_sign, int *sign_size) {

    int ret = 0;
    unsigned char tmp_hash[512];
    unsigned int hash_size;
    EC_KEY *eckey = NULL;
    ECDSA_SIG *sig_buff = NULL;
    const BIGNUM *pr = NULL;
    const BIGNUM *ps = NULL;

    do {
        // TODO: plug sm2 on the sign gen
        if (curve == NID_sm2) {
            ret = 0;
            break;
        }
        if (privk == NULL || size_privk == 0 || in == NULL || out_sign == NULL) {
            ITEST_LOG("icrypto_generate_signature bad param...\n");
            break;            
        }

        eckey = EC_KEY_bin2key(curve, NULL, 0, privk, size_privk);
        if (eckey == NULL) {
            ITEST_LOG("icrypto_generate_signature Fail to generate signature...\n");
            break;      
        }

        if (dgst != NULL) {
            hash_size = icrypto_hash_one_go(in, tmp_hash, dgst, size);
            if (hash_size == 0) {
                ITEST_LOG("icrypto_generate_signature Fail to generate the HASH...\n");
                break;
            }
            size = hash_size;
            in = tmp_hash;
        }

        sig_buff = ECDSA_do_sign(tmp_hash, size, eckey);
        if (sig_buff == NULL) {
            ITEST_LOG("Fail to generate the signature...\n");
            break; 
        }

        ECDSA_SIG_get0(sig_buff, &pr, &ps);
        *sign_size = 0;
        *sign_size += BN_bn2binpad(pr, out_sign, size_privk);
        *sign_size += BN_bn2binpad(ps, &out_sign[*sign_size], size_privk);

        ret = 1;

    } while (0);

    if (eckey != NULL)
        EC_KEY_free(eckey);
    if (sig_buff != NULL)
        ECDSA_SIG_free(sig_buff);
    
    return ret;
}

int icrypto_verify_signature(int curve, unsigned char *pubk, int size_pubk, unsigned char *privk,\
                     int size_privk, unsigned char *in, int size, char *dgst, unsigned char *sign, int sign_size) {

    int ret = 0;
    unsigned char tmp_hash[512];
    unsigned int hash_size;
    EC_KEY *eckey = NULL;
    ECDSA_SIG *sig_buff = NULL;
    BIGNUM *pr = NULL;
    BIGNUM *ps = NULL;

    do {
        // TODO: plug sm2 on the verify
        if (curve == NID_sm2) {
            ret = 1;
            break;
        }
        if ((privk == NULL && pubk == NULL) || (privk != NULL && size_privk == 0) ||\
            (pubk != NULL && size_pubk == 0) || in == NULL || sign == NULL || sign_size == 0) {
            ITEST_LOG("icrypto_verify_signature bad param...\n");
            break;            
        }

        eckey = EC_KEY_bin2key(curve, pubk, size_pubk, privk, size_privk);
        if (eckey == NULL) {
            ITEST_LOG("icrypto_verify_signature Fail to generate signature...\n");
            break;      
        }

        if (dgst != NULL) {
            hash_size = icrypto_hash_one_go(in, tmp_hash, dgst, size);
            if (hash_size == 0) {
                ITEST_LOG("icrypto_verify_signature Fail to generate the HASH...\n");
                break;
            }
            size = hash_size;
            in = tmp_hash;
        }

        sig_buff = ECDSA_SIG_new();
        if (sig_buff == NULL) {
            ITEST_LOG("icrypto_verify_signature Fail to alloc a ECDSA_SIG object...\n");
            break;
        }
        pr = BN_bin2bn(sign, sign_size/2, NULL);
        ps = BN_bin2bn(&sign[sign_size/2], sign_size/2, NULL);
        ret = ECDSA_SIG_set0(sig_buff, pr, ps);

        if (ret != 1) {
            ITEST_LOG("icrypto_verify_signature Fail to convert the signature...\n");
            break;
        }
        ret = 0;
        // it's time to verify
        ret = ECDSA_do_verify(in, size, sig_buff, eckey);
        // check if an error occured in verify
        if ((ret != 1) && (ret != 0))
            // return invalid signature in this case
            ret = 0;

    } while (0);

    if (eckey != NULL)
        EC_KEY_free(eckey);
    if (sig_buff != NULL)
        ECDSA_SIG_free(sig_buff);

    return ret;
}

int icrypto_ECDH_compute_key(unsigned char *ecdh_secret, int ecdh_secret_size, unsigned char *remote_pubk, int pubk_size, int curve, unsigned char *privk, int size_privk) {
    const EC_GROUP *curve_group = NULL;
    EC_POINT *remote_point = NULL;
    BN_CTX *bn_ctx = NULL;
    EC_KEY *privk_ec = NULL;
    int ret = 0;
    unsigned char tmp[700];

    do {

        bn_ctx = BN_CTX_new();
        ASSERT_TRUE_HIGH_API((bn_ctx != NULL));

        privk_ec = EC_KEY_bin2key(curve, NULL, 0, privk, size_privk);
        ASSERT_TRUE_HIGH_API((privk_ec != NULL));

        curve_group = EC_KEY_get0_group(privk_ec);
        ASSERT_TRUE_HIGH_API((curve_group != NULL));

        remote_point = EC_POINT_new(curve_group);
        ASSERT_TRUE_HIGH_API((remote_point != NULL));

        memcpy(tmp+1, remote_pubk, pubk_size);
        tmp[0] = 0x04;

        ASSERT_EQUAL_HIGH_API(EC_POINT_oct2point(curve_group, remote_point, tmp, pubk_size+1, bn_ctx), 1);
        ASSERT_EQUAL_HIGH_API(ECDH_compute_key(ecdh_secret, ecdh_secret_size, remote_point, privk_ec, NULL), pubk_size/2);

        ret = 1;
    } while (0);

    if (privk_ec != NULL)
        EC_KEY_free(privk_ec);
    if (remote_point != NULL)
        EC_POINT_free(remote_point);
    if (bn_ctx != NULL)
        BN_CTX_free(bn_ctx);

    return ret;
}

