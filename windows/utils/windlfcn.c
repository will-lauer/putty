/*
 * Copyright 2022 Yahoo Inc. All rights reserved.
 */

#include <dlfcn.h>

HMODULE
dlopen(const char *filename, int flags)
{
    return LoadLibraryExA(filename, 0, LOAD_WITH_ALTERED_SEARCH_PATH );
}

int
dlclose(HMODULE handle)
{
    FreeLibrary(handle);
    return 0;
}

void * __stdcall
dlsym(HMODULE handle, const char *symbol)
{
    return GetProcAddress(handle, symbol);
}
