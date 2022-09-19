/*
 * Copyright 2022 Yahoo Inc. All rights reserved.
 */
#ifndef PKCS11_SSHPKCS11_H_
#define PKCS11_SSHPKCS11_H_

#if defined(_WIN32)
#pragma pack(push, cryptoki, 1)
#endif

#define CK_PTR *
//#define CK_DECLARE_FUNCTION(returnType, name) returnType __declspec(dllimport) name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
//#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType __declspec(dllimport) (* name)
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)
//#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11.h"

#if defined(_WIN32)
#pragma pack(pop, cryptoki)
#endif

typedef struct ssh2_pkcs11_key {
    const ssh_keyalg *alg;
    strbuf *pubblob;
    strbuf *privblob;
} ssh2_pkcs11_key;

typedef struct ssh2_pkcs11_token {
    CK_SESSION_HANDLE   session;
    bool                logged_in;
    size_t              num_keys;
    ssh2_pkcs11_key     *keys;
} ssh2_pkcs11_token;

typedef struct ssh2_pkcs11_provider {
    const char*         id;
    const char*         pin;
    void*               handle;
    CK_FUNCTION_LIST    *function_list;
    bool                initialized;
    CK_ULONG            nslots;
    CK_SLOT_ID          *slots;
    struct ssh2_pkcs11_token *tokens;
} ssh2_pkcs11_provider;

enum {
    PKCS11_NO_KEYS = 0,
    PKCS11_FAILED = -1,
    PKCS11_INVALID_PIN = -2
};
int pkcs11_add_provider(struct ssh2_pkcs11_provider* provider);
void pkcs11_del_provider(struct ssh2_pkcs11_provider* provider);
void pkcs11_free_provider(struct ssh2_pkcs11_provider* provider);
int pkcs11_refresh_provider(struct ssh2_pkcs11_provider* provider);
int pkcs11_fetch_pub_keys(struct ssh2_pkcs11_provider* provider, CK_ULONG idx);

#endif /* PKCS11_SSHPKCS11_H_ */
