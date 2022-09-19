/*
 * Copyright 2022 Yahoo Inc. All rights reserved.
 */

/*
 * EC keys stored in a PKCS11 smartcard
 */

#include "ssh.h"
#include "misc.h"
#include "pkcs11/sshpkcs11.h"
#include "ecc.h"
#include "mpint.h"

#include <assert.h>

struct ecdsa_key_pkcs11 {
    const struct ec_curve *curve;
    WeierstrassPoint *publicKey;
    const struct ssh_keyalg *ecalg;
    CK_FUNCTION_LIST_PTR funclist;
    CK_SESSION_HANDLE session;
    ptrlen id;
    ssh_key sshk;
};

static void ecpkcs11_freekey(ssh_key *key);

static ssh_key *ecpkcs11_new_pub(const ssh_keyalg *self, ptrlen data) {
    BinarySource src[1];
    struct ecdsa_key_pkcs11 *ec;

    BinarySource_BARE_INIT(src, data.ptr, data.len);
    if (!ptrlen_startswith(get_string(src), ptrlen_from_asciz("ecdsa-sha2"), NULL))
        return NULL;

    ec = snew(struct ecdsa_key_pkcs11);
    memset(ec, 0, sizeof(struct ecdsa_key_pkcs11));
    ec->sshk.vt = self;

    ptrlen curve = get_string(src);
    if (ptrlen_eq_string(curve, ((struct ecsign_extra*)(ssh_ecdsa_nistp256.extra))->curve()->name)) {
        ec->ecalg = &ssh_ecdsa_nistp256;
    } else if (ptrlen_eq_string(curve, ((struct ecsign_extra*)(ssh_ecdsa_nistp384.extra))->curve()->name)) {
        ec->ecalg = &ssh_ecdsa_nistp384;
    } else if (ptrlen_eq_string(curve, ((struct ecsign_extra*)(ssh_ecdsa_nistp521.extra))->curve()->name)) {
        ec->ecalg = &ssh_ecdsa_nistp521;
    } else {
        /* invalid curve */
        ecpkcs11_freekey(&ec->sshk);
        return NULL;
    }
    ec->curve = ((const struct ecsign_extra *)(ec->ecalg->extra))->curve();

    ec->publicKey = get_wpoint(src, ec->curve);

    if (get_err(src) || ec->publicKey == NULL) {
        ecpkcs11_freekey(&ec->sshk);
        return NULL;
    }

    return &ec->sshk;
}

static void ecpkcs11_freekey(ssh_key *key) {
    struct ecdsa_key_pkcs11 *ec = container_of(key, struct ecdsa_key_pkcs11, sshk);
    if (ec->publicKey)
        ecc_weierstrass_point_free(ec->publicKey);
    sfree(ec);
}

static char *ecpkcs11_signkey_invalid(ssh_key *key, unsigned flags)
{
    /* All validity criteria for both ECDSA and EdDSA were checked
     * when we loaded the key in the first place */
    return NULL;
}

static ssh_key *ecpkcs11_new_priv(const ssh_keyalg *self,
                                    ptrlen pub, ptrlen priv)
{
    BinarySource src[1];
    ssh_key *sshk;
    struct ecdsa_key_pkcs11 *ec;

    sshk = ecpkcs11_new_pub(self, pub);
    if (!sshk)
        return NULL;

    ec = container_of(sshk, struct ecdsa_key_pkcs11, sshk);
    BinarySource_BARE_INIT(src, priv.ptr, priv.len);
    ptrlen func = get_data(src, sizeof(CK_FUNCTION_LIST_PTR));
    ptrlen sess = get_data(src, sizeof(CK_SESSION_HANDLE));
    ptrlen obj = get_string(src);

    if (get_err(src) || /*!rsa_verify(rsa)*/ false) {
        ecpkcs11_freekey(&ec->sshk);
        return NULL;
    }

    ec->session = *(CK_SESSION_HANDLE*)sess.ptr;
    ec->funclist = *(CK_FUNCTION_LIST_PTR*)func.ptr;
    ec->id.ptr = mkstr(obj);
    ec->id.len = obj.len;

    return &ec->sshk;
}

static void ecpkcs11_public_blob(ssh_key *key, BinarySink *bs)
{
    struct ecdsa_key_pkcs11 *ec = container_of(key, struct ecdsa_key_pkcs11, sshk);

        put_stringz(bs, ec->ecalg->ssh_id);
        put_stringz(bs, ec->curve->name);
        put_wpoint(bs, ec->publicKey, ec->curve, false);
}

static bool ecpkcs11_has_private(ssh_key *key)
{
    return false;
}

static char *ecpkcs11_cache_str(ssh_key *key)
{
    struct ecdsa_key_pkcs11 *ek = container_of(key, struct ecdsa_key_pkcs11, sshk);
    mp_int *x, *y;

    ecc_weierstrass_get_affine(ek->publicKey, &x, &y);
    char *toret = ecc_cache_str_shared(ek->curve->name, x, y);
    mp_free(x);
    mp_free(y);
    return toret;
}

static key_components *ecpkcs11_components(ssh_key *key)
{
    struct ecdsa_key_pkcs11 *ek = container_of(key, struct ecdsa_key_pkcs11, sshk);
    key_components *kc = key_components_new();

    key_components_add_text(kc, "key_type", "ECDSA");
    key_components_add_text(kc, "curve_name", ek->curve->textname);

    mp_int *x, *y;
    ecc_weierstrass_get_affine(ek->publicKey, &x, &y);
    key_components_add_mp(kc, "public_affine_x", x);
    key_components_add_mp(kc, "public_affine_y", y);
    mp_free(x);
    mp_free(y);

    return kc;
}



static void ecpkcs11_sign(ssh_key *key, ptrlen data, unsigned flags, BinarySink *bs)
{
    struct ecdsa_key_pkcs11 *ec = container_of(key, struct ecdsa_key_pkcs11, sshk);
    CK_RV retVal;

    // step 1: find private key given public key ID
    CK_OBJECT_CLASS private_key= CKO_PRIVATE_KEY;
    CK_ATTRIBUTE private_key_filter[] = {
            { CKA_CLASS, &private_key, sizeof(private_key) },
            { CKA_ID, (void*)ec->id.ptr, ec->id.len}
    };
    size_t filterSize = sizeof(private_key_filter) / sizeof (CK_ATTRIBUTE);
    CK_OBJECT_HANDLE privKey;
    CK_ULONG size = 0;

    if ((retVal = ec->funclist->C_FindObjectsInit(ec->session, private_key_filter, filterSize)) != CKR_OK ||
            (retVal = ec->funclist->C_FindObjects(ec->session, &privKey, 1, &size)) != CKR_OK ||
            (retVal = ec->funclist->C_FindObjectsFinal(ec->session)) != CKR_OK ||
            size != 1) {
        /* failed to find private key */
        /* TODO - log error */
        return;
    }
    // step 2: build data to sign
    unsigned char digest[512 / 8];
    const struct ecsign_extra* extra = ((const struct ecsign_extra *)(ec->ecalg->extra));
    int digestLen = extra->hash->hlen;
    assert(digestLen <= sizeof(digest));
    hash_simple(extra->hash, data, digest);

    // step 3: sign data
    CK_MECHANISM mech;
    mech.mechanism = CKM_ECDSA;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    CK_BYTE_PTR sig = NULL;
    CK_ULONG sigLen = 0;

    /* determine size of signature */
    if ((retVal = ec->funclist->C_SignInit(ec->session, &mech, privKey)) != CKR_OK ||
            (retVal = ec->funclist->C_Sign(ec->session, digest, digestLen, NULL, &sigLen)) != CKR_OK) {
        /* failed to initialized signature and determine size */
        /* TODO - log error */
        goto cleanup_sign;
    }

    sig = snewn(sigLen, unsigned char);
    if ((retVal = ec->funclist->C_Sign(ec->session, digest, digestLen, sig, &sigLen)) != CKR_OK) {
        /* failed to sign */
        /* TODO - log error */
        goto cleanup_sign;
    }

    /* split the ec signature into two bignums and concat them in the result */
    int nlen = sigLen / 2;
    mp_int *r = mp_from_bytes_be(make_ptrlen(&sig[0], nlen));
    mp_int *s = mp_from_bytes_be(make_ptrlen(&sig[nlen], nlen));

    put_stringz(bs, ec->ecalg->ssh_id);

    strbuf *substr = strbuf_new();
    put_mp_ssh2(substr, r);
    put_mp_ssh2(substr, s);

    put_stringsb(bs, substr); /* frees substr internally */

    mp_free(r);
    mp_free(s);

    cleanup_sign:
    if(sig)
        sfree(sig);
}

static int ecpkcs11_pubkey_bits(const ssh_keyalg *self, ptrlen pub)
{
    ssh_key *sshk;
    struct ecdsa_key_pkcs11 *ec;
    int ret;

    sshk = ecpkcs11_new_pub(self, pub);
    if (!sshk)
        return -1;

    ec = container_of(sshk, struct ecdsa_key_pkcs11, sshk);
    ret = ec->curve->fieldBits;
    ecpkcs11_freekey(&ec->sshk);

    return ret;
}

static char *ecpkcs11_alg_desc(const ssh_keyalg *self)
{
    return dupstr("ECC-PKCS11");
}

const ssh_keyalg ssh_ecds_pkcs11 = {
        .new_pub                = ecpkcs11_new_pub,
        .new_priv               = ecpkcs11_new_priv,
        .new_priv_openssh       = NULL, /* ecpkcs11_new_priv_openssh */
        .freekey                = ecpkcs11_freekey,
        .invalid                = ecpkcs11_signkey_invalid,
        .sign                   = ecpkcs11_sign,
        .verify                 = NULL, /* ecpkcs11_verify */
        .public_blob            = ecpkcs11_public_blob,
        .private_blob           = NULL, /* ecpkcs11_private_blob */
        .openssh_blob           = NULL, /* ecpkcs11_openssh_blob */
        .has_private            = ecpkcs11_has_private, /* ecpkcs11_has_private */
        .cache_str              = ecpkcs11_cache_str,
        .components             = ecpkcs11_components, /* components */
        .base_key               = nullkey_base_key,
        .pubkey_bits            = ecpkcs11_pubkey_bits,
        .supported_flags        = nullkey_supported_flags,
        .alternate_ssh_id       = nullkey_alternate_ssh_id,
        .alg_desc               = ecpkcs11_alg_desc,
        .variable_size          = nullkey_variable_size_no,
        .ssh_id                 = "ssh-ecdsa",
        .cache_id               = "ec",
        .extra                  = NULL,
};
