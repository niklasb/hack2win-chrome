#include "internals.h"

char* find_mod(const char* name) {
	_PPEB peb = (_PPEB)__readgsqword(0x60);

	// get the processes loaded modules. ref: http://msdn.microsoft.com/en-us/library/aa813708(VS.85).aspx
	PPEB_LDR_DATA ldr = peb->pLdr;

	// get the first entry of the InMemoryOrder module list
	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)ldr->InMemoryOrderModuleList.Flink;
	PLDR_DATA_TABLE_ENTRY first = entry;
	char buf[1024];
	do {
		entry->BaseDllName.pBuffer;
		int i = 0;
		for (; i < entry->BaseDllName.Length; ++i) {
			buf[i] = entry->BaseDllName.pBuffer[i] & 0xff;
		}
		buf[i] = 0;
		if (!_stricmp(buf, name))
			return (char*)entry->DllBase;
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InMemoryOrderModuleList.Flink;
	} while (entry && entry != first);
	return 0;
}
