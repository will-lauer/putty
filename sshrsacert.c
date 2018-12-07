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

static void rsa2cert_freekey(ssh_key *key);   /* forward reference */

static ssh_key *rsa2cert_new_pub(const ssh_keyalg *self, ptrlen data)
{
    BinarySource src[1];
    struct RSACertKey *certkey;

    BinarySource_BARE_INIT(src, data.ptr, data.len);
    ptrlen certtype = get_string(src);
    if (!ptrlen_eq_string(certtype, self->ssh_id))
        return NULL;

    certkey = snew(struct RSACertKey);
    certkey->sshk = self;

    certkey->certificate.ptr = snewn(data.len, char);
    memcpy((void*)(certkey->certificate.ptr), data.ptr, data.len);
    certkey->certificate.len = data.len;

    certkey->private_exponent = NULL;
    certkey->p = certkey->q = certkey->iqmp = NULL;
    certkey->comment = NULL;
    certkey->modulus = certkey->exponent = NULL;
    certkey->nonce = certkey->keyid = certkey->principals = NULL;
    certkey->options = certkey->extensions = certkey->reserved = NULL;
    certkey->sigkey = NULL;
    certkey->signature = NULL;

    if (get_err(src)) {
        rsa2cert_freekey(&certkey->sshk);
        return NULL;
    }

    certkey->nonce = mkstr(get_string(src));
    certkey->exponent = get_mp_ssh2(src);
    certkey->modulus = get_mp_ssh2(src);
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
        rsa2cert_freekey(&certkey->sshk);
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
        rsa2cert_freekey(&certkey->sshk);
        return NULL;
    }

    return &certkey->sshk;
}

static void rsa2cert_freekey(ssh_key *key)
{
    struct RSACertKey *certkey = container_of(key, struct RSACertKey, sshk);

    if (certkey->certificate.ptr)
        sfree((void*)(certkey->certificate.ptr));
    if (certkey->nonce)
        sfree(certkey->nonce);
    if (certkey->modulus)
        freebn(certkey->modulus);
    if (certkey->exponent)
        freebn(certkey->exponent);
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
    if (certkey->private_exponent)
        freebn(certkey->private_exponent);
    if (certkey->iqmp)
        freebn(certkey->iqmp);
    if (certkey->p)
        freebn(certkey->p);
    if (certkey->q)
        freebn(certkey->q);
    if (certkey->comment)
        sfree(certkey->comment);

    sfree(certkey);
}

static ssh_key *rsa2cert_new_priv(const ssh_keyalg *self,
        ptrlen pub, ptrlen priv)
{
    BinarySource src[1];
    ssh_key *sshk;
    struct RSACertKey *certkey;

    sshk = rsa2cert_new_pub(self, pub);
    if (!sshk) {
        return NULL;
    }

    certkey = container_of(sshk, struct RSACertKey, sshk);
    BinarySource_BARE_INIT(src, priv.ptr, priv.len);
    certkey->private_exponent = get_mp_ssh2(src);
    certkey->p = get_mp_ssh2(src);
    certkey->q = get_mp_ssh2(src);
    certkey->iqmp = get_mp_ssh2(src);
    certkey->comment = NULL;

    struct RSAKey rsakey;

    rsakey.modulus = certkey->modulus;
    rsakey.exponent = certkey->exponent;
    rsakey.private_exponent = certkey->private_exponent;
    rsakey.p = certkey->p;
    rsakey.q = certkey->q;
    rsakey.iqmp = certkey->iqmp;
    rsakey.comment = "";
    rsakey.sshk = &ssh_rsa;

    if (get_err(src) || !rsa_verify(&rsakey)) {
        rsa2cert_freekey(&certkey->sshk);
        return NULL;
    }

    return &certkey->sshk;
}

static ssh_key *rsa2cert_new_priv_openssh(const ssh_keyalg *self,
        BinarySource *src)
{
    struct RSACertKey *certkey;

    certkey = snew(struct RSACertKey);
    certkey->sshk = self;
    certkey->comment = NULL;

    ptrlen certdata = get_string(src);
    certkey->certificate.ptr = snewn(certdata.len, char);
    memcpy((void*)(certkey->certificate.ptr), certdata.ptr, certdata.len);
    certkey->certificate.len = certdata.len;
    certkey->private_exponent = get_mp_ssh2(src);
    certkey->iqmp = get_mp_ssh2(src);
    certkey->p = get_mp_ssh2(src);
    certkey->q = get_mp_ssh2(src);

    if (get_err(src)) {
        rsa2cert_freekey(&certkey->sshk);
        return NULL;
    }

    BinarySource cert[1];
    BinarySource_BARE_INIT(cert, certkey->certificate.ptr, certkey->certificate.len);
    ptrlen certtype = get_string(cert);

    certkey->nonce = mkstr(get_string(cert));
    certkey->exponent = get_mp_ssh2(cert);
    certkey->modulus = get_mp_ssh2(cert);
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

    struct RSAKey rsakey;

    rsakey.modulus = certkey->modulus;
    rsakey.exponent = certkey->exponent;
    rsakey.private_exponent = certkey->private_exponent;
    rsakey.p = certkey->p;
    rsakey.q = certkey->q;
    rsakey.iqmp = certkey->iqmp;
    rsakey.comment = "";
    rsakey.sshk = &ssh_rsa;

    if (get_err(cert) || !ptrlen_eq_string(certtype, self->ssh_id)
            || !rsa_verify(&rsakey)) {
        rsa2cert_freekey(&certkey->sshk);
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
        rsa2cert_freekey(&certkey->sshk);
        return NULL;
    }

    return &certkey->sshk;
}

static void rsa2cert_sign(ssh_key *key, const void* data, int datalen,
        BinarySink *bs)
{
    struct RSACertKey *certkey = container_of(key, struct RSACertKey, sshk);
    struct RSAKey rsakey;

    rsakey.modulus = certkey->modulus;
    rsakey.exponent = certkey->exponent;
    rsakey.private_exponent = certkey->private_exponent;
    rsakey.p = certkey->p;
    rsakey.q = certkey->q;
    rsakey.iqmp = certkey->iqmp;
    rsakey.comment = "";
    rsakey.sshk = &ssh_rsa;

    return ssh_key_sign(&rsakey.sshk, data, datalen, bs);
}

static bool rsa2cert_verify(ssh_key *key, ptrlen sig, ptrlen data)
{
    struct RSACertKey *certkey = container_of(key, struct RSACertKey, sshk);
    struct RSAKey rsakey;

    rsakey.modulus = certkey->modulus;
    rsakey.exponent = certkey->exponent;
    rsakey.private_exponent = certkey->private_exponent;
    rsakey.p = certkey->p;
    rsakey.q = certkey->q;
    rsakey.iqmp = certkey->iqmp;
    rsakey.comment = "";
    rsakey.sshk = &ssh_rsa;

    return ssh_key_verify(&rsakey.sshk, sig, data);
}

static void rsa2cert_public_blob(ssh_key *key, BinarySink *bs)
{
    struct RSACertKey *certkey = container_of(key, struct RSACertKey, sshk);

    // copy the certificate
    put_data(bs, certkey->certificate.ptr, certkey->certificate.len);
}

static void rsa2cert_private_blob(ssh_key *key, BinarySink *bs)
{
    struct RSACertKey *rsa = container_of(key, struct RSACertKey, sshk);

    put_mp_ssh2(bs, rsa->private_exponent);
    put_mp_ssh2(bs, rsa->p);
    put_mp_ssh2(bs, rsa->q);
    put_mp_ssh2(bs, rsa->iqmp);
}

static void rsa2cert_openssh_blob(ssh_key* key, BinarySink *bs)
{
    // don't return anything. USed only for export, and we don't export certs
}

// Used just for looking up host keys for now, so skip
static char * rsa2cert_cache_str(ssh_key *key)
{
    char *p = snewn(1, char);
    p[0] = '\0';
    return p;
}

static int rsa2cert_pubkey_bits(const ssh_keyalg *self, ptrlen pub)
{
    ssh_key *sshk;
    struct RSACertKey *certkey;
    int ret;

    sshk = rsa2cert_new_pub(self, pub);
    if (!sshk)
        return -1;

    certkey = container_of(sshk, struct RSACertKey, sshk);
    ret = bignum_bitcount(certkey->modulus);
    rsa2cert_freekey(&certkey->sshk);

    return ret;
}

const ssh_keyalg ssh_cert_rsa = {
        rsa2cert_new_pub,
        rsa2cert_new_priv,
        rsa2cert_new_priv_openssh,

        rsa2cert_freekey,
        rsa2cert_sign,
        rsa2cert_verify,
        rsa2cert_public_blob,
        rsa2cert_private_blob,
        rsa2cert_openssh_blob,
        rsa2cert_cache_str,

        rsa2cert_pubkey_bits,

        "ssh-rsa-cert-v01@openssh.com",
        "ssh-rsa-cert-v01",
        NULL,
};
