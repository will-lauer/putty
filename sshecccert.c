/*
 * RSA Certificate implementation for PuTTY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ssh.h"
#include "misc.h"
#include "ecc.h"
#include "mpint.h"
#include "pageant.h"

/* -----------------------------------------------------------------------
 * Implementation of the ssh-rsa-cert-v01 key type
 */

static void ecc_cert_freekey(ssh_key *key);   /* forward reference */

static ssh_key *ecc_cert_new_pub(const ssh_keyalg *self, ptrlen data)
{
    const struct ecsign_extra *extra =
        (const struct ecsign_extra *)((ssh_keyalg*)self->extra)->extra;
    BinarySource src[1];
    struct ecdsa_cert_key *certkey;
    struct ec_curve *curve;

    curve = extra->curve();
    assert(curve->type == EC_WEIERSTRASS);

    BinarySource_BARE_INIT(src, data.ptr, data.len);
    ptrlen certtype = get_string(src);
    if (!ptrlen_eq_string(certtype, self->ssh_id))
        return NULL;

    certkey = snew(struct ecdsa_cert_key);
    memset(certkey, 0, sizeof(struct ecdsa_cert_key));
    certkey->sshk.vt = self;

    certkey->certificate.ptr = snewn(data.len, char);
    memcpy((void*)(certkey->certificate.ptr), data.ptr, data.len);
    certkey->certificate.len = data.len;

    certkey->curve = curve;

    if (get_err(src)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    certkey->nonce = mkstr(get_string(src));

    get_string(src); /* curve name */
    certkey->publicKey = get_wpoint(src, curve);
    if (!certkey->publicKey) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
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
    certkey->sigkey = NULL;

    if (get_err(src)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    BinarySource sk_alg[1];
    BinarySource_BARE_INIT(sk_alg, sigkey.ptr, sigkey.len);
    ptrlen algname = get_string(sk_alg);
    if (get_err(sk_alg)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    const ssh_keyalg *signature_key = find_pubkey_alg_len(algname);
    if (signature_key != NULL) {
        BinarySource sk[1];
        BinarySource_BARE_INIT(sk, sigkey.ptr, sigkey.len);
        certkey->sigkey = ssh_key_new_pub(signature_key, get_data(sk, get_avail(sk)));

        if (get_err(sk)) {
            ecc_cert_freekey(&certkey->sshk);
            return NULL;
        }
    }

    return &certkey->sshk;
}

static ssh_key *ed_cert_new_pub(const ssh_keyalg *self, ptrlen data)
{
    const struct ecsign_extra *extra =
        (const struct ecsign_extra *)((ssh_keyalg*)self->extra)->extra;
    BinarySource src[1];
    struct eddsa_cert_key *certkey;
    struct ec_curve *curve;

    curve = extra->curve();
    assert(curve->type == EC_WEIERSTRASS || curve->type == EC_EDWARDS);

    BinarySource_BARE_INIT(src, data.ptr, data.len);
    ptrlen certtype = get_string(src);
    if (!ptrlen_eq_string(certtype, self->ssh_id))
        return NULL;

    certkey = snew(struct eddsa_cert_key);
    memset(certkey, 0, sizeof(struct eddsa_cert_key));
    certkey->sshk.vt = self;

    certkey->certificate.ptr = snewn(data.len, char);
    memcpy((void*)(certkey->certificate.ptr), data.ptr, data.len);
    certkey->certificate.len = data.len;

    certkey->curve = curve;

    if (get_err(src)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    certkey->nonce = mkstr(get_string(src));

    certkey->publicKey = get_epoint(src, curve);

    if (certkey->publicKey == NULL)
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
    certkey->sigkey = NULL;

    if (get_err(src)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    BinarySource sk_alg[1];
    BinarySource_BARE_INIT(sk_alg, sigkey.ptr, sigkey.len);
    ptrlen algname = get_string(sk_alg);

    if (get_err(sk_alg)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    const ssh_keyalg *signature_key = find_pubkey_alg_len(algname);
    if (signature_key != NULL) {
        BinarySource sk[1];
        BinarySource_BARE_INIT(sk, sigkey.ptr, sigkey.len);
        certkey->sigkey = ssh_key_new_pub(signature_key, get_data(sk, get_avail(sk)));

        if (get_err(sk)) {
            ecc_cert_freekey(&certkey->sshk);
            return NULL;
        }
    }

    return &certkey->sshk;
}

static void ecc_cert_freekey(ssh_key *key)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);

    if (certkey->certificate.ptr)
        sfree((void*)(certkey->certificate.ptr));
    if (certkey->nonce)
        sfree(certkey->nonce);
    if (certkey->publicKey)
        ecc_weierstrass_point_free(certkey->publicKey);
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
        mp_free(certkey->privateKey);

    sfree(certkey);
}

static void ed_cert_freekey(ssh_key *key)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);

    if (certkey->certificate.ptr)
        sfree((void*)(certkey->certificate.ptr));
    if (certkey->nonce)
        sfree(certkey->nonce);
    if (certkey->publicKey)
        ecc_edwards_point_free(certkey->publicKey);
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
        mp_free(certkey->privateKey);

    sfree(certkey);
}


static char *ecc_cert_signkey_invalid(ssh_key *key, unsigned flags)
{
    /* All validity criteria for both ECDSA and EdDSA were checked
     * when we loaded the key in the first place */
    return NULL;
}

static ssh_key *ecc_cert_new_priv(const ssh_keyalg *self,
        ptrlen pub, ptrlen priv)
{
    BinarySource src[1];
    ssh_key *sshk;
    struct ecdsa_cert_key *certkey;

    sshk = ssh_key_new_pub(self, pub);
    if (!sshk) {
        return NULL;
    }

    certkey = container_of(sshk, struct ecdsa_cert_key, sshk);
    if (priv.len > 0) {
        /* private key was included, so decode it */
        certkey->hasPrivKey = true;

        BinarySource_BARE_INIT(src, priv.ptr, priv.len);

        certkey->privateKey = get_mp_ssh2(src);
        if (get_err(src) || !certkey->privateKey) {
            ecc_cert_freekey(&certkey->sshk);
            return NULL;
        }
    } else {
        /* no private key present, so look it up later if necessary */
        certkey->hasPrivKey = false;
    }

    return &certkey->sshk;
}

static ssh_key *ed_cert_new_priv(const ssh_keyalg *self, ptrlen pub, ptrlen priv)
{
    BinarySource src[1];
    ssh_key *sshk;
    struct eddsa_cert_key *certkey;

    sshk = ssh_key_new_pub(self, pub);
    if (!sshk) {
        return NULL;
    }

    certkey = container_of(sshk, struct eddsa_cert_key, sshk);
    if (priv.len > 0) {
        /* private key was included, so decode it */
        certkey->hasPrivKey = true;

        BinarySource_BARE_INIT(src, priv.ptr, priv.len);

        certkey->privateKey = get_mp_le(src);
        if (get_err(src) || !certkey->privateKey) {
            ecc_cert_freekey(&certkey->sshk);
            return NULL;
        }
    } else {
        /* no private key present, so look it up later if necessary */
        certkey->hasPrivKey = false;
    }

    return &certkey->sshk;
}

static ssh_key *ecc_cert_new_priv_openssh(const ssh_keyalg *self,
        BinarySource *src)
{
    const struct ecsign_extra *extra =
            (const struct ecsign_extra *)((ssh_keyalg*)self->extra)->extra;
    struct ecdsa_cert_key *certkey;
    struct ec_curve *curve;

    curve = extra->curve();
    assert(curve->type == EC_WEIERSTRASS || curve->type == EC_EDWARDS);

    certkey = snew(struct ecdsa_cert_key);
    memset(certkey, 0, sizeof(struct ecdsa_cert_key));
    certkey->sshk.vt = self;

    ptrlen certdata = get_string(src);
    certkey->certificate.ptr = snewn(certdata.len, char);
    memcpy((void*)(certkey->certificate.ptr), certdata.ptr, certdata.len);
    certkey->certificate.len = certdata.len;

    certkey->hasPrivKey = true;
    certkey->privateKey = get_mp_ssh2(src);

    if (get_err(src) || !certkey->privateKey) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    BinarySource cert[1];
    BinarySource_BARE_INIT(cert, certkey->certificate.ptr, certkey->certificate.len);
    ptrlen certtype = get_string(cert);

    certkey->nonce = mkstr(get_string(cert));

    get_string(src); /* curve name */
    certkey->publicKey = get_wpoint(cert, curve);

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
    certkey->sigkey = NULL;

    if (get_err(cert) || !ptrlen_eq_string(certtype, self->ssh_id) || !certkey->publicKey)
    {
        ecc_cert_freekey(&certkey->sshk);
        certkey = NULL;
    }

    BinarySource sk_alg[1];
    BinarySource_BARE_INIT(sk_alg, sigkey.ptr, sigkey.len);
    ptrlen algname = get_string(sk_alg);

    if (get_err(sk_alg)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    const ssh_keyalg *signature_key = find_pubkey_alg_len(algname);
    if (signature_key != NULL) {
        BinarySource sk[1];
        BinarySource_BARE_INIT(sk, sigkey.ptr, sigkey.len);
        certkey->sigkey = ssh_key_new_pub(signature_key, get_data(sk, get_avail(sk)));

        if (get_err(sk)) {
            ecc_cert_freekey(&certkey->sshk);
            return NULL;
        }
    }

    return &certkey->sshk;
}

static ssh_key *ed_cert_new_priv_openssh(const ssh_keyalg *self,
        BinarySource *src)
{
    const struct ecsign_extra *extra =
            (const struct ecsign_extra *)((ssh_keyalg*)self->extra)->extra;
    struct eddsa_cert_key *certkey;
    struct ec_curve *curve;

    curve = extra->curve();
    assert(curve->type == EC_WEIERSTRASS || curve->type == EC_EDWARDS);

    certkey = snew(struct eddsa_cert_key);
    memset(certkey, 0, sizeof(struct eddsa_cert_key));
    certkey->sshk.vt = self;

    ptrlen certdata = get_string(src);
    certkey->certificate.ptr = snewn(certdata.len, char);
    memcpy((void*)(certkey->certificate.ptr), certdata.ptr, certdata.len);
    certkey->certificate.len = certdata.len;

    certkey->hasPrivKey = true;
    certkey->privateKey = get_mp_ssh2(src);

    if (get_err(src) || !certkey->privateKey) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    BinarySource cert[1];
    BinarySource_BARE_INIT(cert, certkey->certificate.ptr, certkey->certificate.len);
    ptrlen certtype = get_string(cert);

    certkey->nonce = mkstr(get_string(cert));

    certkey->publicKey = get_epoint(cert, curve);

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
    certkey->sigkey = NULL;

    if (get_err(cert) || !ptrlen_eq_string(certtype, self->ssh_id) || certkey->publicKey)
    {
        ecc_cert_freekey(&certkey->sshk);
        certkey = NULL;
    }

    BinarySource sk_alg[1];
    BinarySource_BARE_INIT(sk_alg, sigkey.ptr, sigkey.len);
    ptrlen algname = get_string(sk_alg);

    if (get_err(sk_alg)) {
        ecc_cert_freekey(&certkey->sshk);
        return NULL;
    }

    const ssh_keyalg *signature_key = find_pubkey_alg_len(algname);
    if (signature_key != NULL) {
        BinarySource sk[1];
        BinarySource_BARE_INIT(sk, sigkey.ptr, sigkey.len);
        certkey->sigkey = ssh_key_new_pub(signature_key, get_data(sk, get_avail(sk)));

        if (get_err(sk)) {
            ecc_cert_freekey(&certkey->sshk);
            return NULL;
        }
    }

    return &certkey->sshk;
}

static void ecc_cert_sign(ssh_key *key, ptrlen data, unsigned flags,
        BinarySink *bs)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);
    struct ecdsa_key eckey;

    eckey.curve = certkey->curve;
    eckey.publicKey = certkey->publicKey;
    eckey.privateKey = certkey->privateKey;
    eckey.sshk.vt = key->vt->extra;

    if (certkey->hasPrivKey) {
        ssh_key_sign(&eckey.sshk, data, flags, bs);
    } else if (ssh_find_key) {
        /* didn't have private key - look it up and sign with that */
        strbuf *blob = strbuf_new();
        ssh_key_public_blob(&eckey.sshk, BinarySink_UPCAST(blob));

        struct ssh2_userkey *realkey = (*ssh_find_key)(ptrlen_from_strbuf(blob));
        strbuf_free(blob);

        if (realkey) {
            ssh_key_sign(realkey->key, data, flags, bs);
        }
    }
}

static void ed_cert_sign(ssh_key *key, ptrlen data, unsigned flags,
        BinarySink *bs)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);
    struct eddsa_key eckey;

    eckey.curve = certkey->curve;
    eckey.publicKey = certkey->publicKey;
    eckey.privateKey = certkey->privateKey;
    eckey.sshk.vt = key->vt->extra;

    if (certkey->hasPrivKey) {
        ssh_key_sign(&eckey.sshk, data, flags, bs);
    } else if (ssh_find_key) {
        /* didn't have private key - look it up and sign with that */
        strbuf *blob = strbuf_new();
        ssh_key_public_blob(&eckey.sshk, BinarySink_UPCAST(blob));

        struct ssh2_userkey *realkey = (*ssh_find_key)(ptrlen_from_strbuf(blob));
        strbuf_free(blob);

        if (realkey) {
            ssh_key_sign(realkey->key, data, flags, bs);
        }
    }
}

static bool ecc_cert_verify(ssh_key *key, ptrlen sig, ptrlen data)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);
    struct ecdsa_key eckey;

    eckey.curve = certkey->curve;
    eckey.publicKey = certkey->publicKey;
    eckey.privateKey = certkey->privateKey;
    eckey.sshk.vt = key->vt->extra;

    return ssh_key_verify(&eckey.sshk, sig, data);
}

static bool ed_cert_verify(ssh_key *key, ptrlen sig, ptrlen data)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);
    struct eddsa_key eckey;

    eckey.curve = certkey->curve;
    eckey.publicKey = certkey->publicKey;
    eckey.privateKey = certkey->privateKey;
    eckey.sshk.vt = key->vt->extra;

    return ssh_key_verify(&eckey.sshk, sig, data);
}

static void ecc_cert_public_blob(ssh_key *key, BinarySink *bs)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);

    // copy the certificate
    put_data(bs, certkey->certificate.ptr, certkey->certificate.len);
}

static void ecc_cert_signature_public_blob(ssh_key *key, BinarySink *bs)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);

    ssh_key_public_blob(certkey->sigkey,bs);
}

static void ed_cert_public_blob(ssh_key *key, BinarySink *bs)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);

    // copy the certificate
    put_data(bs, certkey->certificate.ptr, certkey->certificate.len);
}

static void ed_cert_signature_public_blob(ssh_key *key, BinarySink *bs)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);

    ssh_key_public_blob(certkey->sigkey,bs);
}

static void ecc_cert_real_public_blob(ssh_key *key, BinarySink *bs)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);

    put_stringz(bs, ((ssh_keyalg*)certkey->sshk.vt->extra)->ssh_id);
    put_stringz(bs, certkey->curve->name);
    put_wpoint(bs, certkey->publicKey, certkey->curve, false);

}

static void ed_cert_real_public_blob(ssh_key *key, BinarySink *bs)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);

    put_stringz(bs, ((ssh_keyalg*)certkey->sshk.vt->extra)->ssh_id);
    put_epoint(bs, certkey->publicKey, certkey->curve, false);
}

static void ecc_cert_private_blob(ssh_key *key, BinarySink *bs)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);

    put_mp_ssh2(bs, certkey->privateKey);
}

static void ed_cert_private_blob(ssh_key *key, BinarySink *bs)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);

    put_mp_ssh2(bs, certkey->privateKey);
}

static void ecc_cert_openssh_blob(ssh_key* key, BinarySink *bs)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);

    put_stringpl(bs, certkey->certificate);

    if (certkey->hasPrivKey) {
        put_mp_ssh2(bs, certkey->privateKey);
    }
}

static void ed_cert_openssh_blob(ssh_key* key, BinarySink *bs)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);

    put_stringpl(bs, certkey->certificate);

    if (certkey->hasPrivKey) {
        put_mp_ssh2(bs, certkey->privateKey);
    }
}

// Used just for looking up host keys for now, so skip
static char * ecc_cert_cache_str(ssh_key *key)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);

    if (certkey->sigkey != NULL) {
        return ssh_key_cache_str(certkey->sigkey);
    } else {
        char *p = snewn(1, char);
        p[0] = '\0';
        return p;
    }
}

static key_components *ecc_cert_components(ssh_key *key)
{
    struct ecdsa_cert_key *certkey = container_of(key, struct ecdsa_cert_key, sshk);
    struct ecdsa_key eckey;

    eckey.curve = certkey->curve;
    eckey.publicKey = certkey->publicKey;
    eckey.privateKey = certkey->privateKey;
    eckey.sshk.vt = key->vt->extra;

    return ssh_key_components(&eckey.sshk);
}

static key_components *ed_cert_components(ssh_key *key)
{
    struct eddsa_cert_key *certkey = container_of(key, struct eddsa_cert_key, sshk);
    struct eddsa_key eckey;

    eckey.curve = certkey->curve;
    eckey.publicKey = certkey->publicKey;
    eckey.privateKey = certkey->privateKey;
    eckey.sshk.vt = key->vt->extra;

    return ssh_key_components(&eckey.sshk);
}

static int ecc_cert_pubkey_bits(const ssh_keyalg *self, ptrlen pub)
{
    ssh_key *sshk;
    struct ecdsa_cert_key *certkey;
    int ret;

    sshk = ssh_key_new_pub(self, pub);
    if (!sshk)
        return -1;

    certkey = container_of(sshk, struct ecdsa_cert_key, sshk);
    ret = certkey->curve->fieldBits;
    ecc_cert_freekey(&certkey->sshk);

    return ret;
}

static int ed_cert_pubkey_bits(const ssh_keyalg *self, ptrlen pub)
{
    ssh_key *sshk;
    struct eddsa_cert_key *certkey;
    int ret;

    sshk = ssh_key_new_pub(self, pub);
    if (!sshk)
        return -1;

    certkey = container_of(sshk, struct eddsa_cert_key, sshk);
    ret = certkey->curve->fieldBits;
    ecc_cert_freekey(&certkey->sshk);

    return ret;
}

const ssh_keyalg ssh_ecdsa_cert_nistp256 = {
        .new_pub                = ecc_cert_new_pub,
        .new_priv               = ecc_cert_new_priv,
        .new_priv_openssh       = ecc_cert_new_priv_openssh,
        .freekey                = ecc_cert_freekey,
        .invalid                = ecc_cert_signkey_invalid,
        .sign                   = ecc_cert_sign,
        .verify                 = ecc_cert_verify,
        .public_blob            = ecc_cert_public_blob,
        .private_blob           = ecc_cert_private_blob,
        .openssh_blob           = ecc_cert_openssh_blob,
        .cache_str              = ecc_cert_cache_str,
        .real_public_blob       = ecc_cert_real_public_blob,
        .components             = ecc_cert_components,
        .pubkey_bits            = ecc_cert_pubkey_bits,
        .ssh_id                 = "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        .cache_id               = "ecdsa-sha2-nistp256-cert-v01",
        .extra                  = &ssh_ecdsa_nistp256,
};

const ssh_keyalg ssh_ecdsa_cert_nistp384 = {
        .new_pub                = ecc_cert_new_pub,
        .new_priv               = ecc_cert_new_priv,
        .new_priv_openssh       = ecc_cert_new_priv_openssh,
        .freekey                = ecc_cert_freekey,
        .invalid                = ecc_cert_signkey_invalid,
        .sign                   = ecc_cert_sign,
        .verify                 = ecc_cert_verify,
        .public_blob            = ecc_cert_public_blob,
        .private_blob           = ecc_cert_private_blob,
        .openssh_blob           = ecc_cert_openssh_blob,
        .cache_str              = ecc_cert_cache_str,
        .real_public_blob       = ecc_cert_real_public_blob,
        .components             = ecc_cert_components,
        .pubkey_bits            = ecc_cert_pubkey_bits,
        .ssh_id                 = "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        .cache_id               = "ecdsa-sha2-nistp384-cert-v01",
        .extra                  = &ssh_ecdsa_nistp384,
};

const ssh_keyalg ssh_ecdsa_cert_nistp521 = {
        .new_pub                = ecc_cert_new_pub,
        .new_priv               = ecc_cert_new_priv,
        .new_priv_openssh       = ecc_cert_new_priv_openssh,
        .freekey                = ecc_cert_freekey,
        .invalid                = ecc_cert_signkey_invalid,
        .sign                   = ecc_cert_sign,
        .verify                 = ecc_cert_verify,
        .public_blob            = ecc_cert_public_blob,
        .private_blob           = ecc_cert_private_blob,
        .openssh_blob           = ecc_cert_openssh_blob,
        .cache_str              = ecc_cert_cache_str,
        .real_public_blob       = ecc_cert_real_public_blob,
        .components             = ecc_cert_components,
        .pubkey_bits            = ecc_cert_pubkey_bits,
        .ssh_id                 = "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        .cache_id               = "ecdsa-sha2-nistp521-cert-v01",
        .extra                  = &ssh_ecdsa_nistp521,
};

const ssh_keyalg ssh_ecdsa_cert_ed25519 = {
        .new_pub                = ed_cert_new_pub,
        .new_priv               = ed_cert_new_priv,
        .new_priv_openssh       = ed_cert_new_priv_openssh,
        .freekey                = ed_cert_freekey,
        .invalid                = ecc_cert_signkey_invalid,
        .sign                   = ed_cert_sign,
        .verify                 = ed_cert_verify,
        .public_blob            = ed_cert_public_blob,
        .private_blob           = ed_cert_private_blob,
        .openssh_blob           = ed_cert_openssh_blob,
        .cache_str              = ecc_cert_cache_str,
        .real_public_blob       = ed_cert_real_public_blob,
        .components             = ed_cert_components,
        .pubkey_bits            = ed_cert_pubkey_bits,
        .ssh_id                 = "ssh-ed25519-cert-v01@openssh.com",
        .cache_id               = "ssh-ed25519-cert-v01",
        .extra                  = &ssh_ecdsa_ed25519,
};

const ssh_keyalg ssh_ecdsa_cert_nistp256_hostkey = {
        .new_pub                = ecc_cert_new_pub,
        .new_priv               = ecc_cert_new_priv,
        .new_priv_openssh       = ecc_cert_new_priv_openssh,
        .freekey                = ecc_cert_freekey,
        .invalid                = ecc_cert_signkey_invalid,
        .sign                   = ecc_cert_sign,
        .verify                 = ecc_cert_verify,
        .public_blob            = ecc_cert_signature_public_blob,
        .private_blob           = ecc_cert_private_blob,
        .openssh_blob           = ecc_cert_openssh_blob,
        .cache_str              = ecc_cert_cache_str,
        .real_public_blob       = ecc_cert_real_public_blob,
        .components             = ecc_cert_components,
        .pubkey_bits            = ecc_cert_pubkey_bits,
        .ssh_id                 = "ecdsa-sha2-nistp256-cert-v01@openssh.com",
        .cache_id               = "ecdsa-sha2-nistp256-cert-v01",
        .extra                  = &ssh_ecdsa_nistp256,
};

const ssh_keyalg ssh_ecdsa_cert_nistp384_hostkey = {
        .new_pub                = ecc_cert_new_pub,
        .new_priv               = ecc_cert_new_priv,
        .new_priv_openssh       = ecc_cert_new_priv_openssh,
        .freekey                = ecc_cert_freekey,
        .invalid                = ecc_cert_signkey_invalid,
        .sign                   = ecc_cert_sign,
        .verify                 = ecc_cert_verify,
        .public_blob            = ecc_cert_signature_public_blob,
        .private_blob           = ecc_cert_private_blob,
        .openssh_blob           = ecc_cert_openssh_blob,
        .cache_str              = ecc_cert_cache_str,
        .real_public_blob       = ecc_cert_real_public_blob,
        .components             = ecc_cert_components,
        .pubkey_bits            = ecc_cert_pubkey_bits,
        .ssh_id                 = "ecdsa-sha2-nistp384-cert-v01@openssh.com",
        .cache_id               = "ecdsa-sha2-nistp384-cert-v01",
        .extra                  = &ssh_ecdsa_nistp384,
};

const ssh_keyalg ssh_ecdsa_cert_nistp521_hostkey = {
        .new_pub                = ecc_cert_new_pub,
        .new_priv               = ecc_cert_new_priv,
        .new_priv_openssh       = ecc_cert_new_priv_openssh,
        .freekey                = ecc_cert_freekey,
        .invalid                = ecc_cert_signkey_invalid,
        .sign                   = ecc_cert_sign,
        .verify                 = ecc_cert_verify,
        .public_blob            = ecc_cert_signature_public_blob,
        .private_blob           = ecc_cert_private_blob,
        .openssh_blob           = ecc_cert_openssh_blob,
        .cache_str              = ecc_cert_cache_str,
        .real_public_blob       = ecc_cert_real_public_blob,
        .components             = ecc_cert_components,
        .pubkey_bits            = ecc_cert_pubkey_bits,
        .ssh_id                 = "ecdsa-sha2-nistp521-cert-v01@openssh.com",
        .cache_id               = "ecdsa-sha2-nistp521-cert-v01",
        .extra                  = &ssh_ecdsa_nistp521,
};

const ssh_keyalg ssh_ecdsa_cert_ed25519_hostkey = {
        .new_pub                = ed_cert_new_pub,
        .new_priv               = ed_cert_new_priv,
        .new_priv_openssh       = ed_cert_new_priv_openssh,
        .freekey                = ed_cert_freekey,
        .invalid                = ecc_cert_signkey_invalid,
        .sign                   = ed_cert_sign,
        .verify                 = ed_cert_verify,
        .public_blob            = ed_cert_signature_public_blob,
        .private_blob           = ed_cert_private_blob,
        .openssh_blob           = ecc_cert_openssh_blob,
        .cache_str              = ecc_cert_cache_str,
        .real_public_blob       = ed_cert_real_public_blob,
        .components             = ed_cert_components,
        .pubkey_bits            = ed_cert_pubkey_bits,
        .ssh_id                 = "ssh-ed25519-cert-v01@openssh.com",
        .cache_id               = "ssh-ed25519-cert-v01",
        .extra                  = &ssh_ecdsa_ed25519,
};
