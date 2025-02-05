/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>
#include "ext_dat.h"

static void *v2i_ALT_PUB_KEY(const struct v3_ext_method *method,
                             struct v3_ext_ctx *ctx,
                             STACK_OF(CONF_VALUE) *values)
{
    X509_PUBKEY* ext = NULL;
    X509_PUBKEY* alt_key = NULL;
    BIO *key_bio = NULL;
    EVP_PKEY *key = NULL;
    CONF_VALUE *key_file = NULL;

    /* we need exactly one value, specifying the private key file */
    if (sk_CONF_VALUE_num(values) != 1) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OPTION);
        goto out;
    }
    key_file = sk_CONF_VALUE_value(values, 0);
    if (strncmp("file", key_file->name, 4)) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OPTION);
        goto out;
    }
    if (!(key_bio = BIO_new_file(key_file->value, "rb"))) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_BIO_LIB);
        goto out;
    }
    if ((alt_key = X509_PUBKEY_new()) == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }
    if ((key = PEM_read_bio_PUBKEY(key_bio, NULL, NULL, NULL)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, X509_R_PUBLIC_KEY_DECODE_ERROR);
        goto out;
    }
    if(!X509_PUBKEY_set(&alt_key, key)) {
        goto out;
    }

    ext = alt_key;
    alt_key = NULL;

out:
    if (key_bio) {
        BIO_free(key_bio);
    }
    if (key) {
        EVP_PKEY_free(key);
    }
    if (alt_key) {
        X509_PUBKEY_free(alt_key);
    }
    return ext;
}

static int i2r_ALT_PUB_KEY(X509V3_EXT_METHOD *method,
                           X509_PUBKEY *pubkey, BIO *out,
                           int indent)
{
    int ret = 0;
    EVP_PKEY* pkey = X509_PUBKEY_get(pubkey);
    ASN1_OBJECT *xpoid;
    X509_PUBKEY_get0_param(&xpoid, NULL, NULL, NULL, pubkey);

    if (BIO_printf(out, "%*sPublic Key Algorithm: ", indent, "") <= 0)
        goto out;
    if (i2a_ASN1_OBJECT(out, xpoid) <= 0)
        goto out;
    if (BIO_puts(out, "\n") <= 0)
        goto out;

    if (pkey == NULL) {
        BIO_printf(out, "%*sUnable to load Public Key\n", indent + 4, "");
        ERR_print_errors(out);
    } else if (EVP_PKEY_print_public(out, pkey, indent + 4, NULL) <= 0) {
        BIO_printf(out, "%*sFailed to print public key information\n", indent, "");
        goto out;
    }

    ret = 1;
out:
    EVP_PKEY_free(pkey);

    return ret;
}

const X509V3_EXT_METHOD ossl_v3_alt_pub_key = {
    NID_subject_alt_public_key_info, 0, ASN1_ITEM_ref(X509_PUBKEY),
    0, 0, 0, 0,
    0, 0, 0,
    (X509V3_EXT_V2I)v2i_ALT_PUB_KEY,
    (X509V3_EXT_I2R)i2r_ALT_PUB_KEY,
    0,
    NULL
};

EVP_PKEY* X509_get_alt_pub_key(const X509 *x)
{
    int i;
    X509_EXTENSION *ext;
    X509_PUBKEY *alt_key;
    EVP_PKEY *pkey;

    /* get the hybrid signature extension */
    if ((i = X509_get_ext_by_NID(x, NID_subject_alt_public_key_info, -1)) < 0) {
        return NULL;
    }
    if ((ext = X509_get_ext(x, i)) == NULL) {
        return NULL;
    }
    if ((alt_key = X509V3_EXT_d2i(ext)) == NULL) {
        return NULL;
    }

    pkey = X509_PUBKEY_get(alt_key);

    X509_PUBKEY_free(alt_key);

    return pkey;
}
