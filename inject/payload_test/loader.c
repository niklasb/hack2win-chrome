#include <Windows.h>

#define BITS64
#define DEREF(name)    *(UINT_PTR*)(name)
#define DEREF_64(name) *(DWORD64*)(name)
#define DEREF_32(name) *(DWORD*)(name)
#define DEREF_16(name) *(WORD*)(name)
#define DEREF_8(name)  *(BYTE*)(name)

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress)
{
	WORD wIndex = 0;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;

	pNtHeaders = (PIMAGE_NT_HEADERS)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

	pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders->OptionalHeader) + pNtHeaders->FileHeader.SizeOfOptionalHeader);

	if (dwRva < pSectionHeader[0].PointerToRawData)
		return dwRva;

	for (wIndex = 0; wIndex < pNtHeaders->FileHeader.NumberOfSections; wIndex++)
	{
		if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
			return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
	}

	return 0;
}

DWORD GetLoaderOffset(VOID * lpReflectiveDllBuffer)
{
	UINT_PTR uiBaseAddress = 0;
	UINT_PTR uiExportDir = 0;
	UINT_PTR uiNameArray = 0;
	UINT_PTR uiAddressArray = 0;
	UINT_PTR uiNameOrdinals = 0;
	DWORD dwCounter = 0;

#ifdef BITS64
	WORD magic = 0x020B; // PE32+
#else
	WORD magic = 0x010B; // PE32
#endif

	uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

	// get the File Offset of the modules NT Header
	uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

	// currenlty we can only process a PE file which is the same type as the one this fuction has
	// been compiled as, due to various offset in the PE structures being defined at compile time.
	if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic != magic)
		return 0;

	// uiNameArray = the address of the modules export directory entry
	uiNameArray = (UINT_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	// get the File Offset of the export directory
	uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress);

	// get the File Offset for the array of name pointers
	uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress);

	// get the File Offset for the array of addresses
	uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress);

	// get the File Offset for the array of name ordinals
	uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress);

	// get a counter for the number of exported functions...
	dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

	// loop through all the exported functions to find the ReflectiveLoader
	while (dwCounter--)
	{
		char * cpExportedFunctionName = (char *)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress));

		if (strstr(cpExportedFunctionName, "ReflectiveLoader") != NULL)
		{
			UINT_PTR addr = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions;

			// get the File Offset for the array of addresses
			uiAddressArray = uiBaseAddress + Rva2Offset(addr, uiBaseAddress);

			// use the functions name ordinal as an index into the array of name pointers
			uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

			// return the File Offset to the ReflectiveLoader() functions code...
			return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress);
		}
		// get the next exported function name
		uiNameArray += sizeof(DWORD);

		// get the next exported function name ordinal
		uiNameOrdinals += sizeof(WORD);
	}

	return 0;
}
