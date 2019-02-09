#pragma once

#include <windows.h>
#include <intrin.h>

#include "internals.h"

#pragma intrinsic(_rotr)
#pragma intrinsic(_rotr64)
#pragma intrinsic(_ReturnAddress)

#define BITS64


//#define INT3() __debugbreak()
#define INT3() 

#define EXITFUNC_SEH        0xEA320EFE
#define EXITFUNC_THREAD     0x0A2A1DE0
#define EXITFUNC_PROCESS    0x56A2B5F0

typedef HMODULE(WINAPI * LOADLIBRARYA)(LPCSTR);
typedef FARPROC(WINAPI * GETPROCADDRESS)(HMODULE, LPCSTR);
typedef LPVOID(WINAPI * VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
typedef (*PRINTF)(const char*, ...);

#define KERNEL32DLL_HASH       0x6A4ABC5B
#define LOADLIBRARYA_HASH      0xEC0E4E8E
#define GETPROCADDRESS_HASH    0x7C0DFCAA
#define VIRTUALALLOC_HASH      0x91AFCA54

#define HASH_KEY    13

__declspec(dllexport) UINT_PTR WINAPI Loader(void* addr, void* param);