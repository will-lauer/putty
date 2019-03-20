/*
 * EC keys stored in a PKCS11 smartcard
 */

#include "ssh.h"
#include "misc.h"
#include "sshpkcs11.h"
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

static bool ptrlen_eq_oid(ptrlen pl1, const ssh_keyalg* alg)
{
    const unsigned char *oid = ((const struct ecsign_extra *)(alg->extra))->oid;
    const int oidlen = ((const struct ecsign_extra *)(alg->extra))->oidlen;
    const unsigned char *ptr = pl1.ptr;
    return (pl1.len > 2 && /* enough space for encoded oid */
            pl1.len == oidlen + 2 && /* expect lengths to match */
            ptr[0] == 0x06 && /* is a basic asn1 encoding */
            ptr[1] == oidlen && /* oid length is encoded correctly */
            !memcmp(ptr+2, oid, oidlen));
}

static ssh_key *ecpkcs11_new_pub(const ssh_keyalg *self, ptrlen data) {
    BinarySource src[1];
    struct ecdsa_key_pkcs11 *ec;

    BinarySource_BARE_INIT(src, data.ptr, data.len);
    if (!ptrlen_eq_string(get_string(src), "ssh-ecdsa"))
        return NULL;

    ec = snew(struct ecdsa_key_pkcs11);
    memset(ec, 0, sizeof(struct ecdsa_key_pkcs11));
    ec->sshk.vt = &ssh_ecds_pkcs11;

    ptrlen params = get_string(src);
    if (ptrlen_eq_oid(params, &ssh_ecdsa_nistp256)) {
        ec->ecalg = &ssh_ecdsa_nistp256;
    } else if (ptrlen_eq_oid(params, &ssh_ecdsa_nistp384)) {
        ec->ecalg = &ssh_ecdsa_nistp384;
    } else if (ptrlen_eq_oid(params, &ssh_ecdsa_nistp521)) {
        ec->ecalg = &ssh_ecdsa_nistp521;
    } else {
        /* invalid curve */
        ecpkcs11_freekey(&ec->sshk);
        return NULL;
    }
    ec->curve = ((const struct ecsign_extra *)(ec->ecalg->extra))->curve();

    ptrlen pt = get_string(src);
    const char *p = pt.ptr;
    int length = pt.len;

    /* consume asn1 stuff */
    if (p[0] != 0x04 || /* octet string primitive type */
        p[1] != length -2) { /* asn1 length indicator */
        ecpkcs11_freekey(&ec->sshk);
        return NULL;
    }
    p += 2;
    length -= 2;

    ec->publicKey = ecdsa_decode(make_ptrlen(p, length), ec->curve);

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

const ssh_keyalg ssh_ecds_pkcs11 = {
        ecpkcs11_new_pub,
        ecpkcs11_new_priv,
        NULL, /* ecpkcs11_new_priv_openssh */

        ecpkcs11_freekey,
        ecpkcs11_signkey_invalid,
        ecpkcs11_sign,
        NULL, /* ecpkcs11_verify */
        ecpkcs11_public_blob,
        NULL, /* ecpkcs11_private_blob */
        NULL, /* ecpkcs11_openssh_blob */
        NULL, /* ecpkcs11_cache_str */
        ecpkcs11_public_blob,

        ecpkcs11_pubkey_bits,

        "ssh-ecdsa",
        "ec",
        NULL,
        0
};

