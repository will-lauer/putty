/*
 * Copyright 2018 Oath Inc. All rights reserved.
 */

#include "ssh.h"
#include "sshpkcs11.h"

#include <dlfcn.h>

#include <wincrypt.h>

int pkcs11_add_provider(struct ssh2_pkcs11_provider* provider) {
    
    CK_RV retVal;
    CK_FUNCTION_LIST *funcList; 
    CK_RV (*getFuncList)(CK_FUNCTION_LIST **);
    int validKeys = 0;
    int status = 0;

    // step 1: convert id to canonical path
    //   TBD
    // step 2: check path against whitelist
    //   TBD

    // step 3: load library
    if ((provider->handle = dlopen(provider->id, RTLD_NOW)) == NULL) {
        /* an error occured. cleanup and return */
        return PKCS11_FAILED;
    }

    // step 4: get pkcs11 function list
    if ((getFuncList = dlsym(provider->handle, "C_GetFunctionList")) == NULL) {
        /* error getting pkcs11 function list. abort */
        status = PKCS11_FAILED;
        goto fail;
    }
    if((retVal = (*getFuncList)(&funcList)) != CKR_OK) {
        /* error reading func list */
        status = PKCS11_FAILED;
        goto fail;
    } else {
        provider->function_list = funcList;
    }

    // step 5: initialize pkcs11 module
    if ((retVal = funcList->C_Initialize(NULL)) != CKR_OK) {
        /* error initializing pkcs11 module */
        status = PKCS11_FAILED;
        goto fail;
    } else {
        provider->initialized = TRUE;
    }

    // step 6: get list of slots
    // step 6a: get size of slot list
    if ((retVal = funcList->C_GetSlotList(CK_TRUE, NULL, &provider->nslots)) != CKR_OK) {
        /* failed to get size of slot list */
        status = PKCS11_FAILED;
        goto fail;
    }
    // step 6b: allocate space for slots
    provider->slots = snewn(provider->nslots, CK_SLOT_ID);
    // step 6c: get slot list
    if ((retVal = funcList->C_GetSlotList(CK_TRUE, provider->slots, &provider->nslots)) != CKR_OK) {
        /* failed to get actual slot list */
        status = PKCS11_FAILED;
        goto fail;
    }
    // step 7: get tokens
    // step 7a: allocate space for tokens
    provider->tokens = snewn(provider->nslots, struct ssh2_pkcs11_token);
    memset(provider->tokens, 0, provider->nslots * sizeof(struct ssh2_pkcs11_token));
    // step 7b: foreach slot:
    for (CK_ULONG ii = 0; ii < provider->nslots; ++ii) {
        CK_TOKEN_INFO token;
        // step 7c: get token info
        if ((retVal = funcList->C_GetTokenInfo(provider->slots[ii], &token)) != CKR_OK) {
            /* failed to get token info, so skip this token */
            status = PKCS11_FAILED;
            break;
        }
        if ((token.flags & CKF_TOKEN_INITIALIZED) == 0) {
            /* token is not initialized, so we don't care about it */
            continue;
        }
        // step 7d: check if pin required
        bool needLogin = token.flags & CKF_LOGIN_REQUIRED;
        if (needLogin && !provider->pin.len) {
            /* token requires a pin, but none present */
            status = PKCS11_INVAID_PIN;
            continue;
        }
        // step 7e: open session
        if ((retVal = funcList->C_OpenSession(
                provider->slots[ii], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &provider->tokens[ii].session)) != CKR_OK) {
            /* failed to open session */
            status = PKCS11_FAILED;
            break;
        }
        // step 7f: log in if required
        if (needLogin) {
            retVal = funcList->C_Login(provider->tokens[ii].session, CKU_USER, (CK_UTF8CHAR_PTR)(provider->pin.ptr), provider->pin.len);
            if (retVal != CKR_OK && retVal != CKR_USER_ALREADY_LOGGED_IN) {
                /* failed to log in. cleanup and skip token */
                status = PKCS11_INVAID_PIN;
                if ((retVal = funcList->C_CloseSession(provider->tokens[ii].session)) != CKR_OK) {
                    /* error cleaning up and closing session */
                    /* TODO - log error */
                }
                break;
            } else {
                provider->tokens[ii].logged_in = TRUE;
            }
        }

        // step 8: get keys
        validKeys += pkcs11_fetch_pub_keys(provider, ii);

    }

    if (validKeys > 0)
        return validKeys;

    fail:
    if (provider->initialized) {
        retVal = provider->function_list->C_Finalize(NULL);
        if (retVal != CKR_OK) {
            /* error shuting down pkcs11 module */
            /* TODO - log error */
        }
    }
    provider->function_list = NULL;
    if (provider->handle) {
        dlclose(provider->handle);
        provider->handle = NULL;
    }

    return status;
}

void pkcs11_del_provider(struct ssh2_pkcs11_provider* provider) {
    CK_RV retVal;

    if (provider->initialized) {
        for (int ii = 0; ii < provider->nslots; ++ii) {
            if (provider->tokens[ii].session) {
                /* attempt to close the session */
                retVal = provider->function_list->C_CloseSession(provider->tokens[ii].session);
                if (retVal != CKR_OK) {
                    /* failed to close the session */
                    /* TODO - log the error */
                }
            }
        }

        if ((retVal = provider->function_list->C_Finalize(NULL)) != CKR_OK) {
            /* failed to close the pkcs11 module */
        }
        provider->initialized = FALSE;
    }
    provider->function_list = NULL;
    if (provider->handle) {
        dlclose(provider->handle);
    }
}

void pkcs11_free_provider(struct ssh2_pkcs11_provider* provider) {
    for (int ii = 0; ii < provider->nslots; ++ii) {
        for (int jj = 0; jj < provider->tokens[ii].num_keys; ++jj) {
            if (provider->tokens[ii].keys[jj].comment)
                sfree(provider->tokens[ii].keys[jj].comment);
            if (provider->tokens[ii].keys[jj].key)
                ssh_key_free(provider->tokens[ii].keys[jj].key);
        }
        sfree(provider->tokens[ii].keys);
    }
    sfree(provider->tokens);
    sfree(provider->slots);
    sfree((void*)provider->pin.ptr);
    sfree((void*)provider->id);
}

int pkcs11_refresh_provider(struct ssh2_pkcs11_provider* provider) {
    CK_RV retVal;
    CK_FUNCTION_LIST *funcList;
    CK_RV (*getFuncList)(CK_FUNCTION_LIST **);
    int validKeys = 0;
    int status = 0;

    // Only refresh already initializede providers
    if (!provider->initialized) {
        return PKCS11_FAILED;
    }

    // step 1: convert id to canonical path
    //   NA
    // step 2: check path against whitelist
    //   NA
    // step 3: load library
    //   NA
    // step 4: get pkcs11 function list
    //   NA
    funcList = provider->function_list;

    // step 5: initialize pkcs11 module
    // NA
    // step 5a: clean up old slots
    for (int ii = 0; ii < provider->nslots; ++ii) {
        for (int jj = 0; jj < provider->tokens[ii].num_keys; ++jj) {
            if (provider->tokens[ii].keys[jj].comment)
                sfree(provider->tokens[ii].keys[jj].comment);
            if (provider->tokens[ii].keys[jj].key)
                ssh_key_free(provider->tokens[ii].keys[jj].key);
        }
        sfree(provider->tokens[ii].keys);
        if (provider->tokens[ii].session) {
            /* attempt to close the session */
            retVal = provider->function_list->C_CloseSession(provider->tokens[ii].session);
            if (retVal != CKR_OK) {
                status = PKCS11_FAILED;
            }
        }
    }
    sfree(provider->tokens);
    provider->tokens = NULL;
    sfree(provider->slots);
    provider->slots = NULL;
    provider->nslots = 0;
    if (status == PKCS11_FAILED) {
        return status;
    } else {
        status = 0;
    }
    // step 6: get list of slots
    // step 6a: get size of slot list
    if ((retVal = funcList->C_GetSlotList(CK_TRUE, NULL, &provider->nslots)) != CKR_OK) {
        /* failed to get size of slot list */
        return PKCS11_FAILED;
    }
    // step 6b: allocate space for slots
    provider->slots = snewn(provider->nslots, CK_SLOT_ID);
    memset(provider->slots, 0, provider->nslots * sizeof(CK_SLOT_ID));
    // step 6c: get slot list
    if ((retVal = funcList->C_GetSlotList(CK_TRUE, provider->slots, &provider->nslots)) != CKR_OK) {
        /* failed to get actual slot list */
        return PKCS11_FAILED;
    }
    // step 7: get tokens
    // step 7a: allocate space for tokens
    provider->tokens = snewn(provider->nslots, struct ssh2_pkcs11_token);
    memset(provider->tokens, 0, provider->nslots * sizeof(struct ssh2_pkcs11_token));
    // step 7b: foreach slot:
    for (CK_ULONG ii = 0; ii < provider->nslots; ++ii) {
        CK_TOKEN_INFO token;
        // step 7c: get token info
        if ((retVal = funcList->C_GetTokenInfo(provider->slots[ii], &token)) != CKR_OK) {
            /* failed to get token info, so skip this token */
            status = PKCS11_FAILED;
            break;
        }
        if ((token.flags & CKF_TOKEN_INITIALIZED) == 0) {
            /* token is not initialized, so we don't care about it */
            continue;
        }
        // step 7d: check if pin required
        bool needLogin = token.flags & CKF_LOGIN_REQUIRED;
        if (needLogin && !provider->pin.len) {
            /* token requires a pin, but none present */
            status = PKCS11_INVAID_PIN;
            continue;
        }
        // step 7e: open session
        if ((retVal = funcList->C_OpenSession(
                provider->slots[ii], CKF_RW_SESSION|CKF_SERIAL_SESSION, NULL, NULL, &provider->tokens[ii].session)) != CKR_OK) {
            /* failed to open session */
            status = PKCS11_FAILED;
            break;
        }
        // step 7f: log in if required
        if (needLogin) {
            retVal = funcList->C_Login(provider->tokens[ii].session, CKU_USER, (CK_UTF8CHAR_PTR)(provider->pin.ptr), provider->pin.len);
            if (retVal != CKR_OK && retVal != CKR_USER_ALREADY_LOGGED_IN) {
                /* failed to log in. cleanup and skip token */
                status = PKCS11_INVAID_PIN;
                if ((retVal = funcList->C_CloseSession(provider->tokens[ii].session)) != CKR_OK) {
                    /* error cleaning up and closing session */
                    /* TODO - log error */
                }
                break;
            } else {
                provider->tokens[ii].logged_in = TRUE;
            }
        }

        // step 8: get keys
        validKeys += pkcs11_fetch_pub_keys(provider, ii);

    }

    if (validKeys > 0)
        return validKeys;

    return status;
}

int pkcs11_fetch_pub_keys(struct ssh2_pkcs11_provider* provider, CK_ULONG idx)
{
    CK_FUNCTION_LIST *funcList = provider->function_list;
    CK_SESSION_HANDLE sess = provider->tokens[idx].session;
    CK_RV retVal;
    CK_OBJECT_CLASS public_key= CKO_PUBLIC_KEY;
    CK_ATTRIBUTE public_key_filter[] = {
            { CKA_CLASS, &public_key, sizeof(public_key) }
    };
    CK_ATTRIBUTE attrs[] = {
            { CKA_ID, NULL, 0 },
            { CKA_KEY_TYPE, NULL, 0 },
            { CKA_MODULUS, NULL, 0 },
            { CKA_PUBLIC_EXPONENT, NULL, 0 },
            { CKA_EC_PARAMS, NULL, 0 },
            { CKA_EC_POINT, NULL, 0 }
    };
    size_t numAttrs = sizeof(attrs) / sizeof(CK_ATTRIBUTE);
    CK_OBJECT_HANDLE objs[32];
    size_t numObjs = sizeof(objs) / sizeof(CK_OBJECT_HANDLE);
    int numFound = 0;
    CK_ULONG objsFound;

    if ((retVal = funcList->C_FindObjectsInit(sess, public_key_filter, 1)) != CKR_OK) {
        /* failed to search for public key objects */
        /* TODO - log failure and return */
        return 0;
    }
    /* find the objects that matches our search */
    if ((retVal = funcList->C_FindObjects(sess, objs, numObjs, &objsFound)) != CKR_OK) {
        /* error retrieving object from search. abort search */
        /* TODO - log error */
        return 0;
    }

    if ((retVal = funcList->C_FindObjectsFinal(sess)) != CKR_OK) {
        /* failed to close search */
        /* TODO - log failure */
        return 0;
    }

    provider->tokens[idx].keys = snewn(objsFound, struct ssh2_userkey);
    memset(provider->tokens[idx].keys, 0, sizeof(struct ssh2_userkey) * objsFound);
    provider->tokens[idx].num_keys = objsFound;

    for (int ii = 0; ii < objsFound; ++ii) {
        /* reinitialize attribute array prior to querying for sizes */
        for (int jj = 0; jj < numAttrs; ++jj) {
            attrs[jj].pValue = NULL;
            attrs[jj].ulValueLen = 0;
        }
        /* get attribute sizes from found object */
        retVal = funcList->C_GetAttributeValue(sess, objs[ii], attrs, numAttrs);
        if (retVal != CKR_OK && retVal != CKR_ATTRIBUTE_TYPE_INVALID) {
            /* failed to get attribute values from the object. skip this object */
            /* TODO - log error */
            continue;
        }
        /* allocate buffers for the attributes */
        for (int jj = 0; jj < numAttrs; ++jj) {
            if (attrs[jj].ulValueLen > 0 && attrs[jj].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
                attrs[jj].pValue = snewn(attrs[jj].ulValueLen, char);
            } else {
                attrs[jj].ulValueLen = 0;
            }
        }
        /* get attribute values from found object */
        retVal = funcList->C_GetAttributeValue(sess, objs[ii], attrs, numAttrs);
        if (retVal != CKR_OK && retVal != CKR_ATTRIBUTE_TYPE_INVALID) {
            /* failed to get attribute values. skip this object and free memory */
            /* TODO - log error */
        } else {
            const ssh_keyalg *alg = NULL;
            strbuf *pubblob = strbuf_new();
            BinarySink *pubbs = BinarySink_UPCAST(pubblob);
            strbuf *privblob = strbuf_new();
            BinarySink *privbs = BinarySink_UPCAST(privblob);
            put_data(privbs, &funcList, sizeof(CK_FUNCTION_LIST_PTR));
            put_data(privbs, &sess, sizeof(CK_SESSION_HANDLE));
            put_string(privbs, attrs[0].pValue, attrs[0].ulValueLen);

            /* extract public key and build ssh_userkey */
            switch (*(CK_KEY_TYPE*)(attrs[1].pValue)) {
            case CKK_RSA:
                if (attrs[2].ulValueLen != CKR_ATTRIBUTE_TYPE_INVALID && attrs[3].ulValueLen != CKR_ATTRIBUTE_TYPE_INVALID) {
                    /* alg name */
                    put_stringz(pubbs, "ssh-rsa");
                    /* and exponent */
                    put_string(pubbs, attrs[3].pValue, attrs[3].ulValueLen);
                    /* add modulus */
                    put_string(pubbs, attrs[2].pValue, attrs[2].ulValueLen);
                    alg = &ssh_rsa_pkcs11;
                }
                break;
            case CKK_EC:
                if (attrs[4].ulValueLen != CKR_ATTRIBUTE_TYPE_INVALID && attrs[5].ulValueLen != CKR_ATTRIBUTE_TYPE_INVALID) {
                    /* alg name */
                    put_stringz(pubbs, "ssh-ecdsa");
                    /* put in curve name */
                    put_string(pubbs, attrs[4].pValue, attrs[4].ulValueLen); /* get curve name from attrs[4].pValue - params */
                    /* put in point */
                    put_string(pubbs, attrs[5].pValue, attrs[5].ulValueLen);
                    /* select alg based on params */
                    alg = &ssh_ecds_pkcs11;
                }
                break;
            }

            if (alg != NULL) {
                ssh_key *sshk = ssh_key_new_priv(alg, ptrlen_from_strbuf(pubblob), ptrlen_from_strbuf(privblob));
                if (sshk) {
                    /* we found a valid key. store it */
                    provider->tokens[idx].keys[ii].key = sshk;
                    provider->tokens[idx].keys[ii].comment = dupprintf("%s", provider->id);
                    numFound++;
                }
            }

            strbuf_free(pubblob);
            strbuf_free(privblob);
        }

        /* free allocated memory */
        for (int jj = 0; jj < numAttrs; ++jj) {
            if (attrs[jj].pValue) {
                sfree(attrs[jj].pValue);
            }
        }
    }

    return numFound;
}

void pkcs11_add_keys(struct ssh2_pkcs11_provider* provider, tree234* tree)
{
    int ii, jj;
    for (ii = 0; ii < provider->nslots; ++ii) {
        for (jj = 0; jj < provider->tokens[ii].num_keys; ++jj) {
            struct ssh2_userkey *key = provider->tokens[ii].keys+jj;
            if (key->key == NULL)
                continue;
            if (add234(tree, key) != key) {
                /* failed to add key to tree */
                /* log the error, but continue with the other keys */
            }
        }
    }
}

void pkcs11_remove_keys(struct ssh2_pkcs11_provider* provider, tree234* tree, cmpfn234 fcn)
{
    int ii, jj;
    for (ii = 0; ii < provider->nslots; ++ii) {
        for (jj = 0; jj < provider->tokens[ii].num_keys; ++jj) {
            struct ssh2_userkey *key = find234(tree, provider->tokens[ii].keys+jj, fcn);

            if (key != NULL)
                del234(tree, key);
        }
    }
}

