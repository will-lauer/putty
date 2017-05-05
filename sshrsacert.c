/*
 * RSA Cert implementation for PuTTY.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ssh.h"
#include "misc.h"

#define ENC(x) \
    PUT_32BIT(blob+bloblen, ssh2_bignum_length((x))-4); bloblen += 4; \
    for (i = ssh2_bignum_length((x))-4; i-- ;) blob[bloblen++]=bignum_byte((x),i);

/* certificate related structs */
struct common_cert {
    uint64 serial;
    unsigned int type;
    char * keyid;
    char * principals;
    uint64 valid_after;
    uint64 valid_before;
    char * options;
    char * extensions;
    char * reserved;
    struct ssh2_userkey * sigkey;
    char * signature;
};

struct RSACert {
    char* nonce;
    Bignum e;
    Bignum n;
    struct common_cert common;
};

struct RSACertKey {
    struct RSACert* certificate;
    int certbloblen;
    char* certblob;
    Bignum private_exponent;
    Bignum iqmp;
    Bignum p;
    Bignum q;
    char *comment;
};

/* common routines */
static uint64* getuint64(const char **data, int *datalen, uint64 *val)
{
    if (*datalen < 8)
        return NULL;
    val->hi = GET_32BIT(*data);
    *data += 4;
    val->lo = GET_32BIT(*data);
    *data += 4;
    *datalen -= 8;

    return val;
}

static unsigned int* getuint32(const char **data, int *datalen, unsigned int *val) {
    if (*datalen < 4)
        return NULL;
    *val = GET_32BIT(*data);
    *data += 4;
    *datalen -= 4;

    return val;
}


/* common routines shared with rsa */
static void getstring(const char **data, int *datalen,
                      const char **p, int *length)
{
    *p = NULL;
    if (*datalen < 4)
    return;
    *length = toint(GET_32BIT(*data));
    if (*length < 0)
        return;
    *datalen -= 4;
    *data += 4;
    if (*datalen < *length)
    return;
    *p = *data;
    *data += *length;
    *datalen -= *length;
}

static Bignum getmp(const char **data, int *datalen)
{
    const char *p;
    int length;
    Bignum b;

    getstring(data, datalen, &p, &length);
    if (!p)
    return NULL;
    b = bignum_from_bytes((unsigned char *)p, length);
    return b;
}

/* common certificate section */
void freecommoncert(struct common_cert *common)
{
    if (common->keyid)
        sfree(common->keyid);
    if (common->principals)
        sfree(common->principals);
    if (common->options)
        sfree(common->options);
    if (common->extensions)
        sfree(common->extensions);
    if (common->reserved)
        sfree(common->reserved);
    if (common->sigkey) {
        common->sigkey->alg->freekey(common->sigkey->data);
        sfree(common->sigkey);
    }
    if (common->signature)
        sfree(common->signature);
}

int readcommoncert(const char** b, int* len, struct common_cert* common)
{
    int keyidlen, plen, optlen, extlen, reslen, sigkeylen, siglen;
    const char *principals, *keyid, *opts, *extensions, *reserved,
            *sigkey, *sig;
    uint64 *serial, *before, *after;
    unsigned int *type;

    serial = getuint64(b, len, &common->serial);
    type = getuint32(b, len, &common->type);
    getstring(b, len, &keyid, &keyidlen);
    if (keyid) {
        common->keyid = snewn(keyidlen + 1, char);
        memcpy(common->keyid, keyid, keyidlen);
        common->keyid[keyidlen] = '\0';
    }
    getstring(b, len, &principals, &plen);
    if (principals) {
        common->principals = snewn(plen + 1, char);
        memcpy(common->principals, principals, plen);
        common->principals[plen] = '\0';
    }
    after = getuint64(b, len, &common->valid_after);
    before = getuint64(b, len, &common->valid_before);
    getstring(b, len, &opts, &optlen);
    if (opts) {
        common->options = snewn(optlen + 1, char);
        memcpy(common->options, opts, optlen);
        common->options[optlen] = '\0';
    }
    getstring(b, len, &extensions, &extlen);
    if (extensions) {
        common->extensions = snewn(extlen + 1, char);
        memcpy(common->extensions, extensions, extlen);
        common->extensions[extlen] = '\0';
    }
    getstring(b, len, &reserved, &reslen);
    if (reserved) {
        common->reserved = snewn(reslen + 1, char);
        memcpy(common->reserved, reserved, reslen);
        common->reserved[reslen] = '\0';
    }
    getstring(b, len, &sigkey, &sigkeylen);
    if (sigkey) {
        const char* sigkeybuf;
        struct ssh2_userkey *key = snew(struct ssh2_userkey);
        memset(key, 0, sizeof(struct ssh2_userkey));
        int alglen, sigkeybuflen;

        sigkeybuf = sigkey;
        sigkeybuflen = sigkeylen;
        alglen = toint(GET_32BIT(sigkeybuf));
        key->alg = find_pubkey_alg_len(alglen, sigkeybuf+4);
        if (key->alg != NULL)
            key->data = key->alg->newkey(key->alg, sigkeybuf, sigkeybuflen);
        key->comment = NULL;

        if (key->alg != NULL && key->data != NULL) {
            common->sigkey = key;
        } else {
            sfree(key);
        }
    }
    getstring(b, len, &sig, &siglen);
    if (sig) {
        common->signature = snewn(siglen + 1, char);
        memcpy(common->signature, sig, siglen);
        common->signature[siglen] = '\0';
    }

    if (!serial || !type ||
                !common->keyid || !common->principals || !after || !before ||
                !common->options || !common->extensions || !common->reserved ||
                !common->sigkey || !common->signature) {
        freecommoncert(common);
        return 0;
    }
    return 1;
}

/* certificate implementation */
static struct RSACert *openssh_createcert(const char **blob, int *len)
{
    const char **b = (const char **) blob;
    struct RSACert *cert;

    int noncelen, common_valid;
    const char *nonce;

    cert = snew(struct RSACert);
    memset(cert, 0, sizeof(struct RSACert));

    /* get cert */
    getstring(b, len, &nonce, &noncelen);
    if (nonce) {
        cert->nonce = snewn(noncelen + 1, char);
        memcpy(cert->nonce, nonce, noncelen);
        cert->nonce[noncelen] = '\0';
    }
    cert->e = getmp(b, len);
    cert->n = getmp(b, len);

    common_valid = readcommoncert(b, len, &cert->common);

    if (!cert->nonce || !cert->e || !cert->n || !common_valid) {
        if (cert->nonce)
            sfree(cert->nonce);
        if (cert->e)
            freebn(cert->e);
        if (cert->n)
            freebn(cert->n);
        sfree(cert);
        return NULL;
    }

    return cert;
}

static void *rsa2certkey_newkey(const struct ssh_signkey *self,
                                const char *data,
                                int len)
{
    const char *p;
    int slen;
    struct RSACertKey *rsa;

    rsa = snew(struct RSACertKey);
    memset(rsa, 0, sizeof(struct RSACertKey));

    getstring(&data, &len, &p, &slen);

    if (!p || slen != 28 || memcmp(p, "ssh-rsa-cert-v01@openssh.com", 28)) {
        sfree(rsa);
        return NULL;
    }

    rsa->certblob = snewn(len+1, char);
    memcpy(rsa->certblob, data, len);
    rsa->certblob[len] = '\0';
    rsa->certbloblen = len;

    rsa->certificate = openssh_createcert(&data, &len);

    if (!rsa->certificate) {
        sfree(rsa->certblob);
        sfree(rsa);
        return NULL;
    }

    return rsa;
}

static void rsa2certkey_freekey(void *key)
{
    struct RSACertKey *rsacert = (struct RSACertKey *) key;


    if (rsacert->private_exponent)
        freebn(rsacert->private_exponent);
    if (rsacert->iqmp)
        freebn(rsacert->iqmp);
    if (rsacert->p)
        freebn(rsacert->p);
    if (rsacert->q)
        freebn(rsacert->q);
    if (rsacert->comment)
        sfree(rsacert->comment);

    if (rsacert->certificate) {
        if (rsacert->certificate->nonce)
            sfree(rsacert->certificate->nonce);
        if (rsacert->certificate->e)
            freebn(rsacert->certificate->e);
        if (rsacert->certificate->n)
            freebn(rsacert->certificate->n);

        freecommoncert(&rsacert->certificate->common);

        sfree(rsacert->certificate);
    }
    if (rsacert->certblob)
        sfree(rsacert->certblob);
    sfree(rsacert);
}

static unsigned char *rsa2certkey_public_blob(void *key, int *len)
{
    struct RSACertKey *certkey = (struct RSACertKey *) key;

    unsigned char * blob;
    blob = snewn(certkey->certbloblen, unsigned char);
    memcpy(blob, certkey->certblob, certkey->certbloblen);
    *len = certkey->certbloblen;
    return blob;
}

static unsigned char *rsa2certkey_private_blob(void *key, int *len)
{
    struct RSACertKey *rsa = (struct RSACertKey *) key;
    int dlen, plen, qlen, ulen, bloblen;
    int i;
    unsigned char *blob, *p;

    dlen = (bignum_bitcount(rsa->private_exponent) + 7) / 8;
    plen = (bignum_bitcount(rsa->p) + 7) / 8;
    qlen = (bignum_bitcount(rsa->q) + 7) / 8;
    ulen = (bignum_bitcount(rsa->iqmp) + 7) / 8;

    /*
     * mpint private_exp, mpint p, mpint q, mpint iqmp. Total 16 +
     * sum of lengths.
     */
    bloblen = 16 + dlen + plen + qlen + ulen;
    blob = snewn(bloblen, unsigned char);
    memset(blob, 0, bloblen);
    p = blob;
    PUT_32BIT(p, dlen);
    p += 4;
    for (i = dlen; i--;)
    *p++ = bignum_byte(rsa->private_exponent, i);
    PUT_32BIT(p, plen);
    p += 4;
    for (i = plen; i--;)
    *p++ = bignum_byte(rsa->p, i);
    PUT_32BIT(p, qlen);
    p += 4;
    for (i = qlen; i--;)
    *p++ = bignum_byte(rsa->q, i);
    PUT_32BIT(p, ulen);
    p += 4;
    for (i = ulen; i--;)
    *p++ = bignum_byte(rsa->iqmp, i);
    assert(p == blob + bloblen);
    *len = bloblen;
    return blob;
}

static void *rsa2certkey_createkey(const struct ssh_signkey *self,
                                    const unsigned char *pub_blob, int pub_len,
                                    const unsigned char *priv_blob, int priv_len)
{
    struct RSACertKey *rsa;
    const char *pb = (const char *) priv_blob;

    rsa = rsa2certkey_newkey(self, (char *) pub_blob, pub_len);
    if (rsa == NULL) {
        return NULL;
    }

    rsa->private_exponent = getmp(&pb, &priv_len);
    rsa->p = getmp(&pb, &priv_len);
    rsa->q = getmp(&pb, &priv_len);
    rsa->iqmp = getmp(&pb, &priv_len);

    struct RSAKey key;
    key.modulus = rsa->certificate->n;
    key.exponent = rsa->certificate->e;
    key.private_exponent = rsa->private_exponent;
    key.p = rsa->p;
    key.q = rsa->q;
    /* verify might modify iqmp, so copy it here to avoid corruption */
    Bignum iqmp = copybn(rsa->iqmp);
    key.iqmp = iqmp;

    if (!rsa_verify(&key)) {
        freebn(key.iqmp);
        rsa2certkey_freekey(rsa);
        return NULL;
    }

    if (iqmp != key.iqmp) {
        /* verify modified iqmp */
        freebn(rsa->iqmp);
        rsa->iqmp = key.iqmp;
    }

    return rsa;
}


static void *rsa2certkey_openssh_createkey(const struct ssh_signkey *self,
                                        const unsigned char **blob, int *len)
{
    const char **b = (const char **) blob;
    struct RSACertKey *certkey;
    int certlen, certtypelen;
    const char *cert, *certtype;

    certkey = snew(struct RSACertKey);
    memset(certkey, 0, sizeof(struct RSACertKey));

    /* get cert */
    getstring(b, len, &cert, &certlen);
    certkey->certblob = snewn(certlen+1, char);
    memcpy(certkey->certblob, cert, certlen);
    certkey->certblob[certlen] = '\0';
    certkey->certbloblen = certlen;
    getstring(&cert, &certlen, &certtype, &certtypelen);
    if (!certtype) {
        sfree(certkey->certblob);
        sfree(certkey);
        return NULL;
    }

    struct RSACert* certificate = snew(struct RSACert);
    memset(certificate, 0, sizeof(struct RSACert));

    /* get cert */
    int noncelen, common_valid;
    const char *nonce;
    getstring(&cert, &certlen, &nonce, &noncelen);
    if (nonce) {
        certificate->nonce = snewn(noncelen + 1, char);
        memcpy(certificate->nonce, nonce, noncelen);
        certificate->nonce[noncelen] = '\0';
    }
    certificate->e = getmp(&cert, &certlen);
    certificate->n = getmp(&cert, &certlen);

    common_valid = readcommoncert(&cert, &certlen, &certificate->common);

    if (!certificate->nonce || !certificate->e || !certificate->n || !common_valid) {
        if (certificate->nonce)
            sfree(certificate->nonce);
        if (certificate->e)
            freebn(certificate->e);
        if (certificate->n)
            freebn(certificate->n);
        sfree(certificate);

        sfree(certkey->certblob);
        sfree(certkey);

        return NULL;
    }
    certkey->certificate = certificate;

    /* get d, iqmp, p, q */
    certkey->private_exponent = getmp(b, len);
    certkey->iqmp = getmp(b, len);
    certkey->p = getmp(b, len);
    certkey->q = getmp(b, len);

    if (!certkey->private_exponent || !certkey->iqmp || !certkey->p || !certkey->q) {
        rsa2certkey_freekey(certkey);
        return NULL;
    }

    /* verify key here */
    struct RSAKey key;
    key.modulus = certkey->certificate->n;
    key.exponent = certkey->certificate->e;
    key.private_exponent = certkey->private_exponent;
    key.p = certkey->p;
    key.q = certkey->q;
    /* verify might modify iqmp, so copy it here to avoid corruption */
    Bignum iqmp = copybn(certkey->iqmp);
    key.iqmp = iqmp;

    if (!rsa_verify(&key)) {
        freebn(key.iqmp);
        rsa2certkey_freekey(certkey);
        return NULL;
    }

    if (iqmp != key.iqmp) {
        /* verify modified iqmp */
        freebn(certkey->iqmp);
        certkey->iqmp = key.iqmp;
    }

    return certkey;
}

static int rsa2certkey_openssh_fmtkey(void *key, unsigned char *blob, int len)
{
    struct RSACertKey *certkey = (struct RSACertKey *) key;
    int bloblen, i;

    bloblen =
    4 + certkey->certbloblen +
    ssh2_bignum_length(certkey->private_exponent) +
    ssh2_bignum_length(certkey->iqmp) +
    ssh2_bignum_length(certkey->p) + ssh2_bignum_length(certkey->q);

    if (bloblen > len)
        return bloblen;

    bloblen = 0;
    PUT_32BIT(blob+bloblen,certkey->certbloblen); bloblen += 4;
    memcpy(blob+bloblen, certkey->certblob, certkey->certbloblen); bloblen += certkey->certbloblen;
    ENC(certkey->private_exponent);
    ENC(certkey->iqmp);
    ENC(certkey->p);
    ENC(certkey->q);

    return bloblen;
}

static int rsa2certkey_pubkey_bits(const struct ssh_signkey *self,
                                const void *blob, int len)
{
    struct RSACertKey *rsa;
    int ret;

    rsa = rsa2certkey_newkey(self, (const char *) blob, len);
    if (!rsa)
    return -1;
    ret = bignum_bitcount(rsa->certificate->n);
    rsa2certkey_freekey(rsa);

    return ret;
}

static int rsa2certkey_verifysig(void *key, const char *sig, int siglen,
              const char *data, int datalen)
{
    struct RSACertKey *certkey = (struct RSACertKey *) key;
    struct RSAKey rsakey;
    rsakey.modulus = certkey->certificate->n;
    rsakey.exponent = certkey->certificate->e;
    rsakey.private_exponent = certkey->private_exponent;
    rsakey.p = certkey->p;
    rsakey.q = certkey->q;
    rsakey.iqmp = certkey->iqmp;

    return ssh_rsa.verifysig(&rsakey, sig, siglen, data, datalen);
}

static unsigned char *rsa2certkey_sign(void *key, const char *data, int datalen,
                int *siglen)
{
    struct RSACertKey *certkey = (struct RSACertKey *) key;
    struct RSAKey rsakey;
    rsakey.modulus = certkey->certificate->n;
    rsakey.exponent = certkey->certificate->e;
    rsakey.private_exponent = certkey->private_exponent;
    rsakey.p = certkey->p;
    rsakey.q = certkey->q;
    rsakey.iqmp = certkey->iqmp;

    return ssh_rsa.sign(&rsakey, data, datalen, siglen);
}



const struct ssh_signkey ssh_cert_rsa = {
    rsa2certkey_newkey,
    rsa2certkey_freekey,
    NULL /*rsa2certkey_fmtkey*/,
    rsa2certkey_public_blob,
    rsa2certkey_private_blob,
    rsa2certkey_createkey,
    rsa2certkey_openssh_createkey,
    rsa2certkey_openssh_fmtkey,
    5,/* cert,d,iqmp,q,p */
    rsa2certkey_pubkey_bits,
    rsa2certkey_verifysig,
    rsa2certkey_sign,
    "ssh-rsa-cert-v01@openssh.com",
    "rsa2cert",
    NULL
};
