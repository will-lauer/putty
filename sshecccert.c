/*
 * RSA Certificate implementation for PuTTY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ssh.h"
#include "misc.h"

/* -----------------------------------------------------------------------
 * Implementation of the ssh-rsa-cert-v01 key type
 */

static void ecc_cert_freekey(ssh_key *key);   /* forward reference */

static ssh_key *ecc_cert_new_pub(const ssh_keyalg *self, ptrlen data)
{
    const struct ecsign_extra *extra =
        (const struct ecsign_extra *)((ssh_keyalg*)self->extra)->extra;
    BinarySource src[1];
    struct ec_cert_key *certkey;
    struct ec_curve *curve;

    curve = extra->curve();
    assert(curve->type == EC_WEIERSTRASS || curve->type == EC_EDWARDS);

    BinarySource_BARE_INIT(src, data.ptr, data.len);
    ptrlen certtype = get_string(src);
    if (!ptrlen_eq_string(certtype, self->ssh_id))
        return NULL;

    certkey = snew(struct ec_cert_key);
    memset(certkey, 0, sizeof(struct ec_cert_key));
    certkey->sshk = self;

    certkey->certificate.ptr = snewn(data.len, char);
    memcpy((void*)(certkey->certificate.ptr), data.ptr, data.len);
    certkey->certificate.len = data.len;

    certkey->publicKey.curve = curve;
    certkey->publicKey.infinity = false;

    if (get_err(src)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    certkey->nonce = mkstr(get_string(src));

    ptrlen curvename = get_string(src);
    if (!get_point(src, &certkey->publicKey)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    if (!ptrlen_eq_string(curvename, certkey->publicKey.curve->name) ||
            !certkey->publicKey.x || !certkey->publicKey.y ||
            bignum_cmp(certkey->publicKey.x, curve->p) >= 0 ||
            bignum_cmp(certkey->publicKey.y, curve->p) >= 0)
    {
        ecc_cert_freekey(&certkey->sshk);
        certkey = NULL;
    }
    certkey->serial = get_uint64(src);
    certkey->type = get_uint32(src);
    certkey->keyid = mkstr(get_string(src));
    certkey->principals = mkstr(get_string(src));
    certkey->valid_after = get_uint64(src);
    certkey->valid_before = get_uint64(src);
    certkey->options = mkstr(get_string(src));
    certkey->extensions = mkstr(get_string(src));
    certkey->reserved = mkstr(get_string(src));

    ptrlen sigkey = get_string(src);

    certkey->signature = mkstr(get_string(src));

    if (get_err(src)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    BinarySource sk[1];
    BinarySource_BARE_INIT(sk, sigkey.ptr, sigkey.len);
    ptrlen algname = get_string(sk);
    ssh_key signature_key = find_pubkey_alg_len(algname);
    if (signature_key != NULL) {
        certkey->sigkey = ssh_key_new_pub(signature_key, get_data(sk, get_avail(sk)));
    }

    if (get_err(sk)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    return &certkey->sshk;
}

static void ecc_cert_freekey(ssh_key *key)
{
    struct ec_cert_key *certkey = container_of(key, struct ec_cert_key, sshk);

    if (certkey->certificate.ptr)
        sfree((void*)(certkey->certificate.ptr));
    if (certkey->nonce)
        sfree(certkey->nonce);
    if (certkey->publicKey.x)
        freebn(certkey->publicKey.x);
    if (certkey->publicKey.y)
        freebn(certkey->publicKey.y);
    if (certkey->publicKey.z)
        freebn(certkey->publicKey.z);
    if (certkey->keyid)
        sfree(certkey->keyid);
    if (certkey->principals)
        sfree(certkey->principals);
    if (certkey->options)
        sfree(certkey->options);
    if (certkey->extensions)
        sfree(certkey->extensions);
    if (certkey->reserved)
        sfree(certkey->reserved);
    if (certkey->sigkey)
        ssh_key_free(certkey->sigkey);
    if (certkey->signature)
        sfree(certkey->signature);
    if (certkey->privateKey)
        freebn(certkey->privateKey);

    sfree(certkey);
}

static ssh_key *ecc_cert_new_priv(const ssh_keyalg *self,
        ptrlen pub, ptrlen priv)
{
    BinarySource src[1];
    ssh_key *sshk;
    struct ec_cert_key *certkey;
    struct ec_point *publicKey;

    sshk = ecc_cert_new_pub(self, pub);
    if (!sshk) {
        return NULL;
    }

    certkey = container_of(sshk, struct ec_cert_key, sshk);
    BinarySource_BARE_INIT(src, priv.ptr, priv.len);

    if (certkey->publicKey.curve->type != EC_WEIERSTRASS
        && certkey->publicKey.curve->type != EC_EDWARDS) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    certkey->privateKey = get_mp_ssh2(src);
    if (!certkey->privateKey) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    /* Check that private key generates public key */
    publicKey = ec_public(certkey->privateKey, certkey->publicKey.curve);

    if (!publicKey ||
        bignum_cmp(publicKey->x, certkey->publicKey.x) ||
        bignum_cmp(publicKey->y, certkey->publicKey.y))
    {
        ecc_cert_freekey(&certkey->sshk);
        certkey = NULL;
    }
    ec_point_free(publicKey);

    if (get_err(src)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    return &certkey->sshk;
}

static ssh_key *ecc_cert_new_priv_openssh(const ssh_keyalg *self,
        BinarySource *src)
{
    const struct ecsign_extra *extra =
            (const struct ecsign_extra *)((ssh_keyalg*)self->extra)->extra;
    struct ec_cert_key *certkey;
    struct ec_curve *curve;

    curve = extra->curve();
    assert(curve->type == EC_WEIERSTRASS || curve->type == EC_EDWARDS);

    certkey = snew(struct ec_cert_key);
    memset(certkey, 0, sizeof(struct ec_cert_key));
    certkey->sshk = self;

    ptrlen certdata = get_string(src);
    certkey->certificate.ptr = snewn(certdata.len, char);
    memcpy((void*)(certkey->certificate.ptr), certdata.ptr, certdata.len);
    certkey->certificate.len = certdata.len;

    certkey->privateKey = get_mp_ssh2(src);

    if (get_err(src) || !certkey->privateKey) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    BinarySource cert[1];
    BinarySource_BARE_INIT(cert, certkey->certificate.ptr, certkey->certificate.len);
    ptrlen certtype = get_string(cert);

    certkey->nonce = mkstr(get_string(cert));

    ptrlen curvename = get_string(src);
    bool gotPoint = get_point(cert, &certkey->publicKey);

    certkey->serial = get_uint64(cert);
    certkey->type = get_uint32(cert);
    certkey->keyid = mkstr(get_string(cert));
    certkey->principals = mkstr(get_string(cert));
    certkey->valid_after = get_uint64(cert);
    certkey->valid_before = get_uint64(cert);
    certkey->options = mkstr(get_string(cert));
    certkey->extensions = mkstr(get_string(cert));
    certkey->reserved = mkstr(get_string(cert));

    ptrlen sigkey = get_string(cert);

    certkey->signature = mkstr(get_string(cert));

    if (get_err(cert) || !ptrlen_eq_string(certtype, self->ssh_id) ||
            !ptrlen_eq_string(curvename, certkey->publicKey.curve->name) || !gotPoint ||
            !certkey->publicKey.x || !certkey->publicKey.y ||
            bignum_cmp(certkey->publicKey.x, curve->p) >= 0 ||
            bignum_cmp(certkey->publicKey.y, curve->p) >= 0)
    {
        ecc_cert_freekey(&certkey->sshk);
        certkey = NULL;
    }

    BinarySource sk[1];
    BinarySource_BARE_INIT(sk, sigkey.ptr, sigkey.len);
    ptrlen algname = get_string(sk);
    ssh_key signature_key = find_pubkey_alg_len(algname);
    if (signature_key != NULL) {
        certkey->sigkey = ssh_key_new_pub(signature_key, get_data(sk, get_avail(sk)));
    } else {
        certkey->sigkey = NULL;
    }

    if (get_err(sk)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    return &certkey->sshk;
}

static void ecc_cert_sign(ssh_key *key, const void* data, int datalen,
        BinarySink *bs)
{
    struct ec_cert_key *certkey = container_of(key, struct ec_cert_key, sshk);
    struct ec_key eckey;

    eckey.publicKey.curve = certkey->publicKey.curve;
    eckey.publicKey.x = certkey->publicKey.x;
    eckey.publicKey.y = certkey->publicKey.y;
    eckey.publicKey.z = certkey->publicKey.z;
    eckey.publicKey.infinity = certkey->publicKey.infinity;
    eckey.privateKey = certkey->privateKey;
    eckey.sshk = (*key)->extra;

    return ssh_key_sign(&eckey.sshk, data, datalen, bs);
}

static bool ecc_cert_verify(ssh_key *key, ptrlen sig, ptrlen data)
{
    struct ec_cert_key *certkey = container_of(key, struct ec_cert_key, sshk);
    struct ec_key eckey;

    eckey.publicKey.curve = certkey->publicKey.curve;
    eckey.publicKey.x = certkey->publicKey.x;
    eckey.publicKey.y = certkey->publicKey.y;
    eckey.publicKey.z = certkey->publicKey.z;
    eckey.publicKey.infinity = certkey->publicKey.infinity;
    eckey.privateKey = certkey->privateKey;
    eckey.sshk = (*key)->extra;

    return ssh_key_verify(&eckey.sshk, sig, data);
}

static void ecc_cert_public_blob(ssh_key *key, BinarySink *bs)
{
    struct ec_cert_key *certkey = container_of(key, struct ec_cert_key, sshk);

    // copy the certificate
    put_data(bs, certkey->certificate.ptr, certkey->certificate.len);
}

static void ecc_cert_private_blob(ssh_key *key, BinarySink *bs)
{
    struct ec_cert_key *certkey = container_of(key, struct ec_cert_key, sshk);

    put_mp_ssh2(bs, certkey->privateKey);
}

static void ecc_cert_openssh_blob(ssh_key* key, BinarySink *bs)
{
    // don't return anything. USed only for export, and we don't export certs
}

// Used just for looking up host keys for now, so skip
static char * ecc_cert_cache_str(ssh_key *key)
{
    char *p = snewn(1, char);
    p[0] = '\0';
    return p;
}

static int ecc_cert_pubkey_bits(const ssh_keyalg *self, ptrlen pub)
{
    ssh_key *sshk;
    struct ec_cert_key *certkey;
    int ret;

    sshk = ecc_cert_new_pub(self, pub);
    if (!sshk)
        return -1;

    certkey = container_of(sshk, struct ec_cert_key, sshk);
    ret = certkey->publicKey.curve->fieldBits;
    ecc_cert_freekey(&certkey->sshk);

    return ret;
}

const ssh_keyalg ssh_ecdsa_cert_nistp256 = {
        ecc_cert_new_pub,
        ecc_cert_new_priv,
        ecc_cert_new_priv_openssh,

        ecc_cert_freekey,
        ecc_cert_sign,
        ecc_cert_verify,
        ecc_cert_public_blob,
        ecc_cert_private_blob,
        ecc_cert_openssh_blob,
        ecc_cert_cache_str,

        ecc_cert_pubkey_bits,

        "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        "ecdsa-sha2-nistp256-cert-v01",
        &ssh_ecdsa_nistp256
};

const ssh_keyalg ssh_ecdsa_cert_nistp384 = {
        ecc_cert_new_pub,
        ecc_cert_new_priv,
        ecc_cert_new_priv_openssh,

        ecc_cert_freekey,
        ecc_cert_sign,
        ecc_cert_verify,
        ecc_cert_public_blob,
        ecc_cert_private_blob,
        ecc_cert_openssh_blob,
        ecc_cert_cache_str,

        ecc_cert_pubkey_bits,

        "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        "ecdsa-sha2-nistp384-cert-v01",
        &ssh_ecdsa_nistp384
};

const ssh_keyalg ssh_ecdsa_cert_nistp521 = {
        ecc_cert_new_pub,
        ecc_cert_new_priv,
        ecc_cert_new_priv_openssh,

        ecc_cert_freekey,
        ecc_cert_sign,
        ecc_cert_verify,
        ecc_cert_public_blob,
        ecc_cert_private_blob,
        ecc_cert_openssh_blob,
        ecc_cert_cache_str,

        ecc_cert_pubkey_bits,

        "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        "ecdsa-sha2-nistp521-cert-v01",
        &ssh_ecdsa_nistp521
};
