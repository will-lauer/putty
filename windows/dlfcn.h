/*
 * Copyright 2018 Oath Inc. All rights reserved.
 */
#ifndef WINDOWS_DLFCN_H_
#define WINDOWS_DLFCN_H_

#include <Windows.h>

#define RTLD_NOW 0

#define dlerror() GetLastError()

HMODULE dlopen(const char *filename, int flags);

int dlclose(HMODULE handle);

void * __stdcall dlsym(HMODULE handle, const char *symbol);

#endif /* WINDOWS_DLFCN_H_ */
