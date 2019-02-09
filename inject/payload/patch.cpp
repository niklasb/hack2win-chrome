#include <Windows.h>
#include "patch.h"

void insert_jmp(char* location, void* target, bool call) {
	location[0] = 0x49;
	location[1] = 0xbb;  // mov r11,...
	*(void**)(location + 2) = target;
	location[10] = 0x41;
	location[11] = 0xff;
	location[12] = call ? 0xd3 : 0xe3;
}

// add a function call to `stub` at function entry
// TODO this doesn't seem to work properly, why? stack misalignment?
void patch_entry(char* location, size_t prefix_len, void* stub) {
	char* tramp = (char*)VirtualAlloc(0, 0x2000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	DWORD dummy;
	VirtualProtect((void*)((DWORD64)location & ~0xfff), 0x2000, PAGE_EXECUTE_READWRITE, &dummy);

	/*
	memcpy(tramp, location, prefix_len);
	insert_jmp(tramp + prefix_len, location + prefix_len, 0);
	insert_jmp(location, tramp, 0);
	*/
	
	insert_jmp(tramp, stub, 1);
	memcpy(tramp + 13, location, prefix_len);
	insert_jmp(tramp + 13 + prefix_len, location + prefix_len, 0);
	insert_jmp(location, tramp, 0);
	
}

// replace function by stub
void patch_replace(void* location, void* stub) {
	char* s = (char*)location;
	DWORD dummy;
	VirtualProtect((void*)((DWORD64)location & ~0xfff), 0x2000, PAGE_EXECUTE_READWRITE, &dummy);
	insert_jmp(s, stub, 0);
}