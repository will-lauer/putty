/*
 * RSA keys stored in a PKCS11 smartcard
 */

#include "ssh.h"
#include "misc.h"
#include "sshpkcs11.h"
#include "mpint.h"

#include <assert.h>

struct RSAPKCS11Key {
    mp_int *modulus;
    mp_int *exponent;
    CK_FUNCTION_LIST_PTR funclist;
    CK_SESSION_HANDLE session;
    ptrlen id;
    ssh_key sshk;
};

static void rsa2pkcs11_freekey(ssh_key *key);

static ssh_key *rsa2pkcs11_new_pub(const ssh_keyalg *self, ptrlen data) {
    BinarySource src[1];
    struct RSAPKCS11Key *rsa;

    BinarySource_BARE_INIT(src, data.ptr, data.len);
    if (!ptrlen_eq_string(get_string(src), "ssh-rsa"))
        return NULL;

    rsa = snew(struct RSAPKCS11Key);
    memset(rsa, 0, sizeof(struct RSAPKCS11Key));
    rsa->sshk.vt = &ssh_rsa_pkcs11;
    rsa->exponent = get_mp_ssh2(src);
    rsa->modulus = get_mp_ssh2(src);

    if (get_err(src)) {
        rsa2pkcs11_freekey(&rsa->sshk);
        return NULL;
    }

    return &rsa->sshk;
}

static void rsa2pkcs11_freekey(ssh_key *key) {
    struct RSAPKCS11Key *rsa = container_of(key, struct RSAPKCS11Key, sshk);
    if (rsa->modulus)
        mp_free(rsa->modulus);
    if (rsa->exponent)
        mp_free(rsa->exponent);
    if (rsa->id.ptr)
        sfree((void*)rsa->id.ptr);
    sfree(rsa);
}

static ssh_key *rsa2pkcs11_new_priv(const ssh_keyalg *self,
                                    ptrlen pub, ptrlen priv)
{
    BinarySource src[1];
    ssh_key *sshk;
    struct RSAPKCS11Key *rsa;

    sshk = rsa2pkcs11_new_pub(self, pub);
    if (!sshk)
        return NULL;

    rsa = container_of(sshk, struct RSAPKCS11Key, sshk);
    BinarySource_BARE_INIT(src, priv.ptr, priv.len);
    ptrlen func = get_data(src, sizeof(CK_FUNCTION_LIST_PTR));
    ptrlen sess = get_data(src, sizeof(CK_SESSION_HANDLE));
    ptrlen obj = get_string(src);

    if (get_err(src) || /*!rsa_verify(rsa)*/ false) {
        rsa2pkcs11_freekey(&rsa->sshk);
        return NULL;
    }

    rsa->session = *(CK_SESSION_HANDLE*)sess.ptr;
    rsa->funclist = *(CK_FUNCTION_LIST_PTR*)func.ptr;
    rsa->id.ptr = mkstr(obj);
    rsa->id.len = obj.len;

    return &rsa->sshk;
}

static void rsa2pkcs11_public_blob(ssh_key *key, BinarySink *bs)
{
    struct RSAPKCS11Key *rsa = container_of(key, struct RSAPKCS11Key, sshk);

    put_stringz(bs, "ssh-rsa");
    put_mp_ssh2(bs, rsa->exponent);
    put_mp_ssh2(bs, rsa->modulus);
}

static char *rsa2pkcs11_sign_invalid(ssh_key *key, unsigned flags)
{
    struct RSAPKCS11Key *pkcs11key = container_of(key, struct RSAPKCS11Key, sshk);

    struct RSAKey rsakey;

    rsakey.modulus = pkcs11key->modulus;
    rsakey.exponent = pkcs11key->exponent;
    rsakey.private_exponent = NULL;
    rsakey.p = NULL;
    rsakey.q = NULL;
    rsakey.iqmp = NULL;
    rsakey.comment = "";
    rsakey.sshk.vt = &ssh_rsa;

    return ssh_key_invalid(&rsakey.sshk, flags);
}

static int rsa2pkcs11_pubkey_bits(const ssh_keyalg *self, ptrlen pub)
{
    ssh_key *sshk;
    struct RSAPKCS11Key *rsa;
    int ret;

    sshk = rsa2pkcs11_new_pub(self, pub);
    if (!sshk)
        return -1;

    rsa = container_of(sshk, struct RSAPKCS11Key, sshk);
    ret = mp_get_nbits(rsa->modulus);
    rsa2pkcs11_freekey(&rsa->sshk);

    return ret;
}

static void rsa2pkcs11_sign(ssh_key *key, ptrlen data, unsigned flags, BinarySink *bs)
{
    struct RSAPKCS11Key *rsa = container_of(key, struct RSAPKCS11Key, sshk);
    CK_RV retVal;

    // step 1: find private key given public key ID
    CK_OBJECT_CLASS private_key= CKO_PRIVATE_KEY;
    CK_ATTRIBUTE private_key_filter[] = {
            { CKA_CLASS, &private_key, sizeof(private_key) },
            { CKA_ID, (void*)rsa->id.ptr, rsa->id.len}
    };
    size_t filterSize = sizeof(private_key_filter) / sizeof (CK_ATTRIBUTE);
    CK_OBJECT_HANDLE privKey;
    CK_ULONG size = 0;

    if ((retVal = rsa->funclist->C_FindObjectsInit(rsa->session, private_key_filter, filterSize)) != CKR_OK ||
            (retVal = rsa->funclist->C_FindObjects(rsa->session, &privKey, 1, &size)) != CKR_OK ||
            (retVal = rsa->funclist->C_FindObjectsFinal(rsa->session)) != CKR_OK ||
            size != 1) {
        /* failed to find private key */
        /* TODO - log error */
        return;
    }
    // step 2: build data to sign
    unsigned char *bytes;
    size_t nbytes;
    const ssh_hashalg *halg;
    const char *sign_alg_name;

    if (flags & SSH_AGENT_RSA_SHA2_256) {
        halg = &ssh_sha256;
        sign_alg_name = "rsa-sha2-256";
    } else if (flags & SSH_AGENT_RSA_SHA2_512) {
        halg = &ssh_sha512;
        sign_alg_name = "rsa-sha2-512";
    } else {
        halg = &ssh_sha1;
        sign_alg_name = "ssh-rsa";
    }

    nbytes = (mp_get_nbits(rsa->modulus) + 7) / 8;
    bytes = rsa_pkcs1_signature_string(nbytes, halg, data);

    // step 3: sign data
    CK_MECHANISM mech;
    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    CK_BYTE_PTR sig = NULL;
    CK_ULONG sigLen = 0;

    /* determine size of signature */
    if ((retVal = rsa->funclist->C_SignInit(rsa->session, &mech, privKey)) != CKR_OK ||
            (retVal = rsa->funclist->C_Sign(rsa->session, bytes, nbytes, NULL, &sigLen)) != CKR_OK) {
        /* failed to initialized signature and determine size */
        /* TODO - log error */
        goto cleanup_sign;
    }

    sig = snewn(sigLen, unsigned char);
    if ((retVal = rsa->funclist->C_Sign(rsa->session, bytes, nbytes, sig, &sigLen)) != CKR_OK) {
        /* failed to sign */
        /* TODO - log error */
        goto cleanup_sign;
    }

    put_stringz(bs, sign_alg_name);
    put_string(bs, sig, sigLen);

    cleanup_sign:
    smemclr(bytes, nbytes);
    sfree(bytes);
    sfree(sig);
}

const ssh_keyalg ssh_rsa_pkcs11 = {
        rsa2pkcs11_new_pub,
        rsa2pkcs11_new_priv,
        NULL, /* rsa2pkcs11_new_priv_openssh */

        rsa2pkcs11_freekey,
        rsa2pkcs11_sign_invalid,
        rsa2pkcs11_sign,
        NULL, /* rsa2pkcs11_verify */
        rsa2pkcs11_public_blob,
        NULL, /* rsa2pkcs11_private_blob */
        NULL, /* rsa2pkcs11_openssh_blob */
        NULL, /* rsa2pkcs11_cache_str */
        rsa2pkcs11_public_blob,

        rsa2pkcs11_pubkey_bits,

        "ssh-rsa",
        "rsa2",
        NULL,
        0
};

