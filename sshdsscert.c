/*
 * DSS Certificate implementation for PuTTY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ssh.h"
#include "misc.h"

/* -----------------------------------------------------------------------
 * Implementation of the ssh-dss-cert-v01@openssh.com key type
 */

static void dsscert_freekey(ssh_key *key);   /* forward reference */

static ssh_key *dsscert_new_pub(const ssh_keyalg *self, ptrlen data)
{
    BinarySource src[1];
    struct dss_cert_key *certkey;

    BinarySource_BARE_INIT(src, data.ptr, data.len);
    ptrlen certtype = get_string(src);
    if (!ptrlen_eq_string(certtype, ssh_cert_dss.ssh_id))
        return NULL;

    certkey = snew(struct dss_cert_key);
    certkey->sshk = &ssh_cert_dss;

    certkey->certificate.ptr = snewn(data.len, char);
    memcpy((void*)(certkey->certificate.ptr), data.ptr, data.len);
    certkey->certificate.len = data.len;

    certkey->x = NULL;
    certkey->p = certkey->q = certkey->g = certkey->y = NULL;
    certkey->nonce = certkey->keyid = certkey->principals = NULL;
    certkey->options = certkey->extensions = certkey->reserved = NULL;
    certkey->sigkey = NULL;
    certkey->signature = NULL;

    if (get_err(src)) {
        dsscert_freekey(&certkey->sshk);
        return NULL;
    }

    certkey->nonce = mkstr(get_string(src));
    certkey->p = get_mp_ssh2(src);
    certkey->q = get_mp_ssh2(src);
    certkey->g = get_mp_ssh2(src);
    certkey->y = get_mp_ssh2(src);
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
        dsscert_freekey(&certkey->sshk);
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
        dsscert_freekey(&certkey->sshk);
        return NULL;
    }

    return &certkey->sshk;
}

static void dsscert_freekey(ssh_key *key)
{
    struct dss_cert_key *certkey = container_of(key, struct dss_cert_key, sshk);

    if (certkey->certificate.ptr)
        sfree((void*)(certkey->certificate.ptr));
    if (certkey->nonce)
        sfree(certkey->nonce);
    if (certkey->p)
        freebn(certkey->p);
    if (certkey->q)
        freebn(certkey->q);
    if (certkey->g)
        freebn(certkey->g);
    if (certkey->y)
        freebn(certkey->y);
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
    if (certkey->x)
        freebn(certkey->x);

    sfree(certkey);
}

static ssh_key *dsscert_new_priv(const ssh_keyalg *self,
        ptrlen pub, ptrlen priv)
{
    BinarySource src[1];
    ssh_key *sshk;
    struct dss_cert_key *certkey;
    Bignum ytest;

    sshk = dsscert_new_pub(self, pub);
    if (!sshk) {
        return NULL;
    }

    certkey = container_of(sshk, struct dss_cert_key, sshk);
    BinarySource_BARE_INIT(src, priv.ptr, priv.len);
    certkey->x = get_mp_ssh2(src);

    if (get_err(src)) {
        dsscert_freekey(&certkey->sshk);
        return NULL;
    }

    /* validate the key - from sshdss.c */
    ytest = modpow(certkey->g, certkey->x, certkey->p);
    if (0 != bignum_cmp(ytest, certkey->y)) {
        dsscert_freekey(&certkey->sshk);
        freebn(ytest);
        return NULL;
    }
    freebn(ytest);

    return &certkey->sshk;
}

static ssh_key *dsscert_new_priv_openssh(const ssh_keyalg *self,
        BinarySource *src)
{
    struct dss_cert_key *certkey;

    certkey = snew(struct dss_cert_key);
    certkey->sshk = &ssh_cert_dss;

    ptrlen certdata = get_string(src);
    certkey->certificate.ptr = snewn(certdata.len, char);
    memcpy((void*)(certkey->certificate.ptr), certdata.ptr, certdata.len);
    certkey->certificate.len = certdata.len;
    certkey->x = get_mp_ssh2(src);

    if (get_err(src)) {
        dsscert_freekey(&certkey->sshk);
        return NULL;
    }

    BinarySource cert[1];
    BinarySource_BARE_INIT(cert, certkey->certificate.ptr, certkey->certificate.len);
    ptrlen certtype = get_string(cert);

    certkey->nonce = mkstr(get_string(cert));
    certkey->p = get_mp_ssh2(cert);
    certkey->q = get_mp_ssh2(cert);
    certkey->g = get_mp_ssh2(cert);
    certkey->y = get_mp_ssh2(cert);
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

    /* validate the key - from sshdss.c */
    if (get_err(cert) || !ptrlen_eq_string(certtype, ssh_cert_dss.ssh_id)
            || !bignum_cmp(certkey->q, Zero) || !bignum_cmp(certkey->p, Zero)) {
        dsscert_freekey(&certkey->sshk);
        return NULL;
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
        dsscert_freekey(&certkey->sshk);
        return NULL;
    }

    return &certkey->sshk;
}

static void dsscert_sign(ssh_key *key, const void* data, int datalen,
        BinarySink *bs)
{
    struct dss_cert_key *certkey = container_of(key, struct dss_cert_key, sshk);
    struct dss_key dsskey;

    dsskey.p = certkey->p;
    dsskey.q = certkey->q;
    dsskey.g = certkey->g;
    dsskey.y = certkey->y;
    dsskey.x = certkey->x;
    dsskey.sshk = &ssh_dss;

    return ssh_key_sign(&dsskey.sshk, data, datalen, bs);
}

static bool dsscert_verify(ssh_key *key, ptrlen sig, ptrlen data)
{
    struct dss_cert_key *certkey = container_of(key, struct dss_cert_key, sshk);
    struct dss_key dsskey;

    dsskey.p = certkey->p;
    dsskey.q = certkey->q;
    dsskey.g = certkey->g;
    dsskey.y = certkey->y;
    dsskey.x = certkey->x;

    dsskey.sshk = &ssh_dss;

    return ssh_key_verify(&dsskey.sshk, sig, data);
}

static void dsscert_public_blob(ssh_key *key, BinarySink *bs)
{
    struct dss_cert_key *certkey = container_of(key, struct dss_cert_key, sshk);

    // copy the certificate
    put_data(bs, certkey->certificate.ptr, certkey->certificate.len);
}

static void dsscert_private_blob(ssh_key *key, BinarySink *bs)
{
    struct dss_cert_key *dss = container_of(key, struct dss_cert_key, sshk);

    put_mp_ssh2(bs, dss->x);
}

static void dsscert_openssh_blob(ssh_key* key, BinarySink *bs)
{
    // don't return anything. USed only for export, and we don't export certs
}

// Used just for looking up host keys for now, so skip
static char * dsscert_cache_str(ssh_key *key)
{
    char *p = snewn(1, char);
    p[0] = '\0';
    return p;
}

static int dsscert_pubkey_bits(const ssh_keyalg *self, ptrlen pub)
{
    ssh_key *sshk;
    struct dss_cert_key *certkey;
    int ret;

    sshk = dsscert_new_pub(self, pub);
    if (!sshk)
        return -1;

    certkey = container_of(sshk, struct dss_cert_key, sshk);
    ret = bignum_bitcount(certkey->p);
    dsscert_freekey(&certkey->sshk);

    return ret;
}

const ssh_keyalg ssh_cert_dss = {
        dsscert_new_pub,
        dsscert_new_priv,
        dsscert_new_priv_openssh,

        dsscert_freekey,
        dsscert_sign,
        dsscert_verify,
        dsscert_public_blob,
        dsscert_private_blob,
        dsscert_openssh_blob,
        dsscert_cache_str,

        dsscert_pubkey_bits,

        "ssh-dss-cert-v01@openssh.com",
        "dsscert",
        NULL,
};
