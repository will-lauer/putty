General flow for PKCS11 support:

agent:
    Handle new messages:
        SSH_AGENTC_ADD_SMARTCARD_KEY
        SSH_AGENTC_REMOVE_SMARTCARD_KEY
    add:
        message provide 
            library path name
            pin
            optional constraints (lifetime, confirm)
        flow:
            check path against whitelist
            add provider:
                verify not already loaded
                open library
                get address of C_GetFunctionList
                get function list
                initialize pkcs11 module
                get module info
                get slot list size
                get slot list
                foreach slot
                    get token info
                    check if initialized
                    open session with pin && fetch keys
            foreach key from provider
                if not in keylist
                    add
                else
                    free
    free:
        message provide 
            library path name
            pin
        flow:
            remove all keys from provider
            remove provider from provider list
            foreach slot
                close session
            finalize provider
            close library
            
SSHCA support:
    ReadSlot - return contents of f9 slot
    Attest - attest contents of named slot
    AddHardCert - install cert in way retrievable by pagaent - yinit uses yubico-agent, but could install cert in yubikey
