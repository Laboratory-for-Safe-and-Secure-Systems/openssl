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
#include "crypto/x509.h"
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "ext_dat.h"

static void *v2i_ALT_SIG(const struct v3_ext_method *method,
                         struct v3_ext_ctx *ctx,
                         STACK_OF(CONF_VALUE) *values)
{
    BIO *key_bio = NULL;
    EVP_PKEY* private_key = NULL;
    CONF_VALUE *key_file = NULL;
    ASN1_BIT_STRING *sig = NULL;
    int sig_size = 0;

    /* we need exactly one value, specifying the private key file */
    if (sk_CONF_VALUE_num(values) != 1) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OPTION);
        goto err;
    }
    key_file = sk_CONF_VALUE_value(values, 0);
    if (strncmp("file", key_file->name, 4)) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_INVALID_OPTION);
        goto err;
    }
    if (!(key_bio = BIO_new_file(key_file->value, "rb"))) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_BIO_LIB);
        goto err;
    }
    if ((private_key = PEM_read_bio_PrivateKey(key_bio, NULL, NULL, NULL)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_BIO_LIB);
        goto err;
    }
    if ((sig = ASN1_BIT_STRING_new()) == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /* Create an BITSTRING with no real data for testing the extension size */
    if ((sig_size = EVP_PKEY_get_size(private_key)) <= 0) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE);
        goto err;
    }
    if (ASN1_BIT_STRING_set(sig, NULL, sig_size) <= 0) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    memset(sig->data, 0, sig->length);

    if (ctx->flags & CTX_TEST) {
        EVP_PKEY_free(private_key);
    }
    else {
        if (ctx->subject_cert == NULL) {
            ERR_raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE);
            goto err;
        }

        /* Store the private key for later signing */
        ctx->subject_cert->hybrid_sig_private_key = private_key;
    }

    BIO_free(key_bio);

    return sig;

 err:
    if (key_bio) {
        BIO_free(key_bio);
    }
    if (private_key) {
        EVP_PKEY_free(private_key);
    }
    if (sig) {
        ASN1_BIT_STRING_free(sig);
    }
    return NULL;
}

static int i2r_ALT_SIG_ALG(X509V3_EXT_METHOD *method,
                           X509_ALGOR *sigalg, BIO *out,
                           int indent)
{
    if (BIO_indent(out, indent, indent) <= 0)
        return 0;

    return i2a_ASN1_OBJECT(out, sigalg->algorithm);
}

static int i2r_ALT_SIG_VAL(X509V3_EXT_METHOD *method,
                           ASN1_BIT_STRING *bits, BIO *out,
                           int indent)
{
    return X509_signature_dump(out, bits, indent);
}

const X509V3_EXT_METHOD ossl_v3_alt_sig_alg = {
    NID_alt_signature_algorithm, 0, ASN1_ITEM_ref(X509_ALGOR),
    0, 0, 0, 0,
    0, 0, 0, 0,
    (X509V3_EXT_I2R)i2r_ALT_SIG_ALG,
    0,
    NULL
};

const X509V3_EXT_METHOD ossl_v3_alt_sig_val = {
    NID_alt_signature_value, 0, ASN1_ITEM_ref(ASN1_BIT_STRING),
    0, 0, 0, 0,
    0, 0, 0,
    (X509V3_EXT_V2I)v2i_ALT_SIG,
    (X509V3_EXT_I2R)i2r_ALT_SIG_VAL,
    0,
    NULL
};

//----------------------------------------------------

typedef X509_CINF X509_CINF_PRETBS;
ASN1_SEQUENCE_enc(X509_CINF_PRETBS, enc, 0) = {
    ASN1_EXP_OPT(X509_CINF, version, ASN1_INTEGER, 0),
    ASN1_EMBED(X509_CINF, serialNumber, ASN1_INTEGER),
    ASN1_OPT(X509_CINF, signature, X509_ALGOR),  // Changed from ASN1_SIMPLE to ASN1_OPT
    ASN1_SIMPLE(X509_CINF, issuer, X509_NAME),
    ASN1_EMBED(X509_CINF, validity, X509_VAL),
    ASN1_SIMPLE(X509_CINF, subject, X509_NAME),
    ASN1_SIMPLE(X509_CINF, key, X509_PUBKEY),
    ASN1_IMP_OPT(X509_CINF, issuerUID, ASN1_BIT_STRING, 1),
    ASN1_IMP_OPT(X509_CINF, subjectUID, ASN1_BIT_STRING, 2),
    ASN1_EXP_SEQUENCE_OF_OPT(X509_CINF, extensions, X509_EXTENSION, 3)
} ASN1_SEQUENCE_END_enc(X509_CINF, X509_CINF_PRETBS)

DECLARE_ASN1_ITEM(X509_CINF_PRETBS);

/* Function to create a preTBS certificate */
static X509_CINF *create_preTBS_X509(X509 *orig_cert)
{
    X509_EXTENSION *pubkey_ext = NULL;
    X509_EXTENSION *alg_ext = NULL;
    X509_EXTENSION *val_ext = NULL;

    X509_CINF *preTbs = NULL;
    X509_CINF *ret = NULL;

    unsigned char *buf = NULL;

    if (!orig_cert)
        return NULL;

    /* Encode the X509_CINF structure into a DER buffer */
    int len = i2d_X509_CINF(&orig_cert->cert_info, &buf);
    if (len <= 0)
        return NULL;

    /* Create a new X509_CINF object by decoding the DER buffer */
    const unsigned char *p = buf;
    if (!(preTbs = d2i_X509_CINF(NULL, &p, len)))
        goto out;

    /* Find and remove alt signature extension */
    int ext_index = X509v3_get_ext_by_NID(preTbs->extensions, NID_alt_signature_value, -1);
    if (ext_index >= 0) {
        /* Remove the extension at the found index */
        val_ext = X509v3_delete_ext(preTbs->extensions, ext_index);
        X509_EXTENSION_free(val_ext);
        val_ext = NULL;
    }

    /* Make sure that the altSignatureAlgorithm extension is the last one and the
     * subjectAltPublicKeyInfo extension the penultimate in the preTBS. */
    ext_index = X509v3_get_ext_by_NID(preTbs->extensions, NID_alt_signature_algorithm, -1);
    if (ext_index >= 0) {
        alg_ext = X509v3_delete_ext(preTbs->extensions, ext_index);
    }
    ext_index = X509v3_get_ext_by_NID(preTbs->extensions, NID_subject_alt_public_key_info, -1);
    if (ext_index >= 0) {
        pubkey_ext = X509v3_delete_ext(preTbs->extensions, ext_index);
    }
    if (pubkey_ext) {
        if (!X509v3_add_ext(&preTbs->extensions, pubkey_ext, -1)) {
            goto out;
        }
        pubkey_ext = NULL;
    }
    if (alg_ext) {
        if (!X509v3_add_ext(&preTbs->extensions, alg_ext, -1)) {
            goto out;
        }
        alg_ext = NULL;
    }

    /* Properly reset the X509_ALGOR so it is not encoded */
    X509_ALGOR_free(preTbs->signature);
    preTbs->signature = NULL;

    preTbs->enc.modified = 1; /* Mark the certificate as modified */

    ret = preTbs;

out:
    if (buf) {
        OPENSSL_free(buf);
    }
    if (pubkey_ext) {
        X509_EXTENSION_free(pubkey_ext);
    }
    if (alg_ext) {
        X509_EXTENSION_free(alg_ext);
    }
    return ret;
}

int X509_alt_sig_sign(X509 *x, EVP_MD_CTX* ctx)
{
    int ret = 0;
    int i;

    X509_EXTENSION* alg_ext = NULL;
    X509_EXTENSION* val_ext = NULL;

    X509_ALGOR *sigalg = NULL;
    X509_ALGOR *sigalg_backup = NULL;
    ASN1_BIT_STRING *sig = NULL;

    ASN1_OCTET_STRING *sigalg_raw = NULL;
    ASN1_OCTET_STRING *sig_raw = NULL;

    EVP_PKEY* private_key = x->hybrid_sig_private_key;
    EVP_PKEY_CTX *pkey_ctx = NULL;

    X509_CINF *preTbs = NULL;

    unsigned char *buf = NULL;
    int buf_len = 0;

    i = X509_get_ext_by_NID(x, NID_alt_signature_value, -1);
    if ((i >= 0 && private_key == NULL) || (i < 0 && private_key != NULL)) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE);
        goto out;
    }
    else if ((i < 0 && private_key == NULL))
        return 1;

    if (!(sig = ASN1_BIT_STRING_new())) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }

    if (!(sig_raw = ASN1_OCTET_STRING_new())) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }

    if (!(sigalg = X509_ALGOR_new())) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }

    if (!(sigalg_raw = ASN1_OCTET_STRING_new())) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }

    /* Remove the already existing AltSignatureValue extension, as it
     * must be the last extension. */
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_value, -1)) < 0) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_MISSING_VALUE);
        goto out;
    }

    if ((val_ext = X509_delete_ext(x, i)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    /* Set the signature algorithm of the X509_CINF data to a real value (not needed
     * anyways) and sign it with the private key. These two steps are a workaround to
     * make sure the preTbs generation works properly and we obtain the X509_ALGOR
     * object. */
    sigalg_backup = x->cert_info.signature;
    if (X509_ALGOR_set0(x->cert_info.signature, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, NULL) <= 0) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }
    if ((pkey_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }
    EVP_MD_CTX_set_pkey_ctx(ctx, pkey_ctx);
    if (ASN1_item_sign(ASN1_ITEM_rptr(X509_CINF_PRETBS), sigalg, NULL, sig, &x->cert_info,
                       private_key, EVP_MD_CTX_get0_md(ctx)) <= 0) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    buf_len = i2d_X509_ALGOR(sigalg, &buf);
    if (buf_len <= 0) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }

    if (!ASN1_OCTET_STRING_set(sigalg_raw, buf, buf_len)) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }
    OPENSSL_free(buf);
    buf = NULL;

    if (!(alg_ext = X509_EXTENSION_create_by_NID(NULL, NID_alt_signature_algorithm, 0, sigalg_raw))) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    if (!X509_add_ext(x, alg_ext, -1)) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    /* Create the preTBS certificate */
    if ((preTbs = create_preTBS_X509(x)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    /* Sign the preTBS data */
    if (ASN1_item_sign(ASN1_ITEM_rptr(X509_CINF_PRETBS), sigalg, NULL, sig, preTbs,
                       private_key, NULL) <= 0) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    /* Store the new signature in the extension */
    buf_len = i2d_ASN1_BIT_STRING(sig, &buf);
    if (buf_len <= 0) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }

    if (!ASN1_OCTET_STRING_set(sig_raw, buf, buf_len)) {
        ERR_raise(ERR_LIB_X509V3, ERR_R_MALLOC_FAILURE);
        goto out;
    }
    OPENSSL_free(buf);
    buf = NULL;

    if (!X509_EXTENSION_set_data(val_ext, sig_raw)) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    if (!X509_add_ext(x, val_ext, -1)) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    x->cert_info.signature = sigalg_backup;
    x->cert_info.enc.modified = 1;
    ret = 1;

out:
    if (sigalg) {
        X509_ALGOR_free(sigalg);
    }
    if (sigalg_raw) {
        ASN1_OCTET_STRING_free(sigalg_raw);
    }
    if (alg_ext) {
        X509_EXTENSION_free(alg_ext);
    }
    if (sig) {
        ASN1_BIT_STRING_free(sig);
    }
    if (sig_raw) {
        ASN1_OCTET_STRING_free(sig_raw);
    }
    if (preTbs) {
        X509_CINF_free(preTbs);
    }
    if (pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (private_key) {
        EVP_PKEY_free(private_key);
        x->hybrid_sig_private_key = NULL;
    }
    if (buf) {
        OPENSSL_free(buf);
    }
    return ret;
}

static int X509_alt_sig_verify(X509 *x, EVP_PKEY* public_key)
{
    int ret = 0;
    int i;

    X509_EXTENSION* alg_ext = NULL;
    X509_EXTENSION* val_ext = NULL;

    X509_ALGOR *sigalg = NULL;
    ASN1_BIT_STRING *sig = NULL;

    X509_CINF *preTbs = NULL;

    /* get the alt signature algorithm */
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_algorithm, -1)) < 0) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_NOT_FOUND);
        goto out;
    }
    if ((alg_ext = X509_get_ext(x, i)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }
    if ((sigalg = X509V3_EXT_d2i(alg_ext)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    /* get the alt signature value */
    if ((i = X509_get_ext_by_NID(x, NID_alt_signature_value, -1)) < 0) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_NOT_FOUND);
        goto out;
    }
    if ((val_ext = X509_get_ext(x, i)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }
    if ((sig = X509V3_EXT_d2i(val_ext)) == NULL) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    /* generate preTBS certificate */
    preTbs = create_preTBS_X509(x);
    if (!preTbs) {
        ERR_raise(ERR_LIB_X509V3, X509V3_R_EXTENSION_VALUE_ERROR);
        goto out;
    }

    /* verify the alt signature */
    if (ASN1_item_verify(ASN1_ITEM_rptr(X509_CINF_PRETBS), sigalg, sig, preTbs, public_key) != 1) {
        ERR_raise(ERR_LIB_X509V3, X509_R_CERTIFICATE_VERIFICATION_FAILED);
        goto out;
    }

    ret = 1;
out:
    if (sigalg)
        X509_ALGOR_free(sigalg);
    if (sig)
        ASN1_BIT_STRING_free(sig);
    if (preTbs)
        X509_CINF_free(preTbs);

    return ret;
}

static int alt_sig_validate_path_internal(X509_STORE_CTX *ctx,
                                          STACK_OF(X509) *chain)
{
    EVP_PKEY* public_key = NULL;
    int i = 0;
    X509 *x = sk_X509_value(chain, i);
    int need_pubkey = 0; // if one certificate has an alt key, all others upwards in the chain need one as well

    /*
     * Walk up the chain. Verify each alt signature with the alt key of the parent.
     */
    for (; i < sk_X509_num(chain) - 1; i++) {
        X509* parent = sk_X509_value(chain, i + 1);
        public_key = X509_get_alt_pub_key(parent);
        if (!public_key) {
            if (need_pubkey) {
                ctx->error = X509_R_CERTIFICATE_VERIFICATION_FAILED;
                ctx->error_depth = i;
                ctx->current_cert = x;
                if (ctx->verify_cb(0, ctx) == 0)
                    goto error_out;
            }
            // we do not have a alt key, but we do not need one. Continue checking the chain
            continue;
        }
        else {
            // this certificate has an alt key -> all parent certificates need to have one as well
            need_pubkey = 1;
        }
        if (X509_alt_sig_verify(x, public_key) == 0) {
            ctx->error = X509_R_CERTIFICATE_VERIFICATION_FAILED;
            ctx->error_depth = i;
            ctx->current_cert = x;
            if (ctx->verify_cb(0, ctx) == 0)
                goto error_out;
        }
        x = parent;
        EVP_PKEY_free(public_key);
    }

    // Check self signed alt signature of the root certificate.
    public_key = X509_get_alt_pub_key(x);
    if (!public_key) {
        if (need_pubkey) {
            ctx->error = X509_R_CERTIFICATE_VERIFICATION_FAILED;
            ctx->error_depth = i;
            ctx->current_cert = x;
            if (ctx->verify_cb(0, ctx) == 0)
                goto error_out;
        }
        return 1; // we do not need a alt key -> all is good
    }

    i = X509_alt_sig_verify(x, public_key);

    EVP_PKEY_free(public_key);

    return i;

error_out:
    if (public_key)
        EVP_PKEY_free(public_key);

    return 0;
}

/*
 * Verify the alternative signatures for a certificate chain.
 */
int X509_alt_sig_validate_path(X509_STORE_CTX *ctx) {
    if (ctx->chain == NULL
            || sk_X509_num(ctx->chain) == 0
            || ctx->verify_cb == NULL) {
        ctx->error = X509_V_ERR_UNSPECIFIED;
        return 0;
    }
    return alt_sig_validate_path_internal(ctx, ctx->chain);
}
