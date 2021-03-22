#include <stdio.h>
#include <openssl/evp.h>
#include "itest.h"


int hash_one_go(char *in, unsigned char *out, char *dgst_type, int size)
{
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;

    OpenSSL_add_all_digests();

    if(!dgst_type) {
            ITEST_LOG("Usage: mdtest digestname\n");
            return 0;
    }

    md = EVP_get_digestbyname(dgst_type);

    if(!md) {
            ITEST_LOG("Unknown message digest %s\n", dgst_type);
            return 0;
    }

    mdctx = EVP_MD_CTX_create();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, in, size);
    EVP_DigestFinal_ex(mdctx, out, &md_len);
    EVP_MD_CTX_destroy(mdctx);

    /* Call this once before exit. */
    EVP_cleanup();
    return md_len;
}