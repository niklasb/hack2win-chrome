#pragma once

#include <Windows.h>
#include <vector>
#include <string>
#include <stdio.h>
#include <tchar.h>
#include <stdio.h> 
#include <strsafe.h>

#define SHELLCODE 1

typedef ULONG(__cdecl *f_DbgPrintEx)(
	_In_ ULONG ComponentId,
	_In_ ULONG Level,
	_In_ PCSTR Format,
	...
	);

extern f_DbgPrintEx DbgPrintEx;
extern FILE* logfile;

#define LOG(fmt, ...) do {if(logfile){fprintf(logfile, fmt, __VA_ARGS__);fflush(0);}}while(0)
//#define LOG(fmt, ...) DbgPrintEx(77 /*DPFLTR_IHVDRIVER_ID*/, 3 /*DPFLTR_INFO_LEVEL*/, fmt, __VA_ARGS__);
//#define LOG(fmt, ...) do {char logbuf[1024];sprintf_s(logbuf,sizeof logbuf, fmt, __VA_ARGS__);MessageBoxA(0, logbuf,"hi", 0);}while(0)
//#define LOG(fmt, ...) do {}while(0)

#define MSGBOX(fmt, ...) do {char logbuf[1024];sprintf_s(logbuf,sizeof logbuf, fmt, __VA_ARGS__);MessageBoxA(0, logbuf,"hi", 0);}while(0)

#define PROP(x) do{bool res = (x); if (!res) return res;}while(0)

//void* memcpy_hack(void* dest, const void* src, size_t len);
