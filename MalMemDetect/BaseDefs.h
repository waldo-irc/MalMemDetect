#pragma once
typedef LONG NTSTATUS;
typedef DWORD KPRIORITY;
typedef WORD UWORD;

typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // UNICODE_STRING
    MemoryRegionInformation, // MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
    MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
    MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation, // MEMORY_ENCLAVE_IMAGE_INFORMATION // since REDSTONE3
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_IMAGE_INFORMATION {
    PVOID ImageBase;
    SIZE_T SizeOfImage;
    union {
        ULONG ImageFlags;
        struct {
            ULONG ImagePartialMap : 1;
            ULONG ImageNotExecutable : 1;
            ULONG ImageSigningLevel : 4; // REDSTONE3
            ULONG Reserved : 26;
        };
    };
} MEMORY_IMAGE_INFORMATION, * PMEMORY_IMAGE_INFORMATION;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION
{
    NTSTATUS                ExitStatus;
    PVOID                   TebBaseAddress;
    CLIENT_ID               ClientId;
    KAFFINITY               AffinityMask;
    KPRIORITY               Priority;
    KPRIORITY               BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

enum THREADINFOCLASS
{
    ThreadBasicInformation,
};

// These logging funcs were borrowed from Mr. Un1k0d3r and his wonderful class.  https://github.com/Mr-Un1k0d3r
void Log(CHAR** data) {
    CHAR path[256];
    DWORD dwBytes;
    snprintf(path, 255, "C:\\%d.log", GetCurrentProcessId());
    HANDLE hFile = CreateFile(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, *data, strlen(*data), &dwBytes, NULL);
    memset(*data, 0x00, 256);
    CloseHandle(hFile);
}

void LogDetected(CHAR** data) {
    CHAR path[256];
    DWORD dwBytes;
    snprintf(path, 255, "C:\\Detected_%d.log", GetCurrentProcessId());
    HANDLE hFile = CreateFile(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    WriteFile(hFile, *data, strlen(*data), &dwBytes, NULL);
    memset(*data, 0x00, 256);
    CloseHandle(hFile);
}

template <typename T>
inline MH_STATUS MH_CreateHookEx(LPVOID pTarget, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHook(pTarget, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

template <typename T>
inline MH_STATUS MH_CreateHookApiEx(
    LPCWSTR pszModule, LPCSTR pszProcName, LPVOID pDetour, T** ppOriginal)
{
    return MH_CreateHookApi(
        pszModule, pszProcName, pDetour, reinterpret_cast<LPVOID*>(ppOriginal));
}

NTSTATUS _ReadProcessMemory(HANDLE h_process, PVOID mem_addr, PVOID buf, SIZE_T mem_size, PSIZE_T mem_read) {
    return syscall.CallSyscall("NtReadVirtualMemory", h_process, mem_addr, buf, mem_size, mem_read).result;
    //return;
}

void _WriteProcessMemory(HANDLE h_process, PVOID mem_addr, PVOID buf, SIZE_T mem_size, PSIZE_T mem_read) {
    syscall.CallSyscall("NtWriteVirtualMemory", h_process, mem_addr, buf, mem_size, mem_read);
    return;
}

void _VirtualProtect(HANDLE h_process, PVOID* mem_addr, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
    syscall.CallSyscall("NtProtectVirtualMemory", h_process, mem_addr, &NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
    return;
}

NTSTATUS _VirtualQuery(HANDLE h_process, PVOID mem_addr, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    return syscall.CallSyscall("NtQueryVirtualMemory", h_process, mem_addr, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength).result;
    //return;
}