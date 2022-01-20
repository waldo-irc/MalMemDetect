#define _CRT_SECURE_NO_WARNINGS // Im a scrub
// Windows Libs
#include <windows.h>
#include <wininet.h>
#include <winnt.h>
#include <string>
#include <algorithm>
#include <psapi.h>
#include <intrin.h>
#pragma intrinsic(_ReturnAddress)
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

// Third Party Libs
#include <MinHook.h>
#include <syscall.hpp>
static auto& syscall = freshycalls::Syscall::get_instance();

// Custom libs
#include "BaseDefs.h"
#include "Hollow.h"
#include "Refresh.h"

#if defined _M_X64
#pragma comment(lib, "libMinHook.x64.lib")
#elif defined _M_IX86
#pragma comment(lib, "libMinHook-x86.lib")
#endif

// Globals for monitoring
DWORD threadMonitor = NULL;
static std::string dllMonitor = "NULL";
BOOL jit = FALSE;

// Define NtQueryInformationThread function for user later
typedef NTSTATUS (WINAPI* NtQueryInformationThread_t)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);
NtQueryInformationThread_t NtQueryInformationThread;

struct CallStackFrame
{
    ULONG_PTR calledFrom;
    ULONG_PTR stackAddr;
    ULONG_PTR frameAddr;
    ULONG_PTR origFrameAddr;
    ULONG_PTR retAddr;
    ULONG_PTR overwriteWhat;
};
static BOOL runAlloc = TRUE;
LPVOID(WINAPI* OldAlloc)(PVOID hHeap, ULONG dwFlags, SIZE_T dwBytes);
//Hooked Malloc
LPVOID WINAPI HookedAlloc(PVOID hHeap, ULONG dwFlags, SIZE_T dwBytes) {
    LPVOID retPointer = OldAlloc(hHeap, dwFlags, dwBytes);

    if (runAlloc) {
        DWORD callerId = GetCurrentThreadId();
        runAlloc = FALSE;
        CHAR* log = (CHAR*)malloc(256);
        HMODULE hModule;
        char lpBaseName[256] = { 0 };
        if (memcmp(_ReturnAddress(), "\x4c\x8b\xc0\x48\x85\xc0\x0f\x84", 8) == 0 || memcmp(_ReturnAddress(), "\x48\x8b\xd8\x48\x85\xc0\x0f\x84", 8) == 0) {
            strcpy_s(lpBaseName, "ntdll.dll");
        }
        else {
            LPCSTR data = (LPCSTR)_ReturnAddress();
            if (::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule) == 1) {
                ::GetModuleBaseNameA(GetCurrentProcess(), hModule, lpBaseName, sizeof(lpBaseName));
            }
            else {
                if (threadMonitor == NULL) {
                    threadMonitor = callerId;
                }
                snprintf(log, 255, "Suspicious Malloc() from thread with id:%d LPVOID:%p Heap Handle:%p Size: %i\n", callerId, retPointer, hHeap, dwBytes);
                LogDetected(&log);
            }
        }

        std::string modName = lpBaseName;
        std::transform(modName.begin(), modName.end(), modName.begin(),
            [](unsigned char c) { return tolower(c); });
        if (dllMonitor != "NULL" && dllMonitor.find(modName) != std::string::npos) {
            snprintf(log, 255, "Suspicious Malloc() from module with name:%s LPVOID:%p Heap Handle:%p %l Size: %i\n", dllMonitor.c_str(), retPointer, hHeap, dwBytes);
            LogDetected(&log);
        }
        //snprintf(log, 255, "Suspicious Malloc() from thread with name:%s id:%d LPVOID:%p Heap Handle:%p Size: %i\n", modName, callerId, retPointer, hHeap, dwBytes);
        //LogDetected(&log);
        free(log);
        runAlloc = TRUE;
    }

    return retPointer;
}

void(WINAPI* OldSleep)(DWORD dwMiliseconds);
//Hooked Sleep
void WINAPI HookedSleep(DWORD dwMiliseconds) {
    DWORD callerId = GetCurrentThreadId();

    CHAR* log = (CHAR*)malloc(256);
    HMODULE hModule;
    char lpBaseName[256] = { 0 };
    if (memcmp(_ReturnAddress(), "\x4c\x8b\xc0\x48\x85\xc0\x0f\x84", 8) == 0 || memcmp(_ReturnAddress(), "\x48\x8b\xd8\x48\x85\xc0\x0f\x84", 8) == 0) {
        strcpy_s(lpBaseName, "ntdll.dll");
    }
    else {
        LPCSTR data = (LPCSTR)_ReturnAddress();
        if (::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule) == 1) {
            ::GetModuleBaseNameA(GetCurrentProcess(), hModule, lpBaseName, sizeof(lpBaseName));
        }
        else {
            if (threadMonitor == NULL) {
                threadMonitor = callerId;
            }
            snprintf(log, 255, "Suspicious Sleep() from thread with id:%d Miliseconds: %d\n", callerId, dwMiliseconds);
            LogDetected(&log);
        }
    }
    std::string modName = lpBaseName;
    std::transform(modName.begin(), modName.end(), modName.begin(),
        [](unsigned char c) { return tolower(c); });
    if (dllMonitor != "NULL" && dllMonitor.find(modName) != std::string::npos) {
        snprintf(log, 255, "Suspicious Sleep() from module with name: %s Miliseconds: %d\n", dllMonitor.c_str(), dwMiliseconds);
        LogDetected(&log);
    }
    free(log);

    OldSleep(dwMiliseconds);
}

NTSTATUS(WINAPI* OldWaitForSingleObj)(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut);
//Hooked NtWaitForSingleObject
NTSTATUS WINAPI HookedWaitForSingleObj(HANDLE ObjectHandle, BOOLEAN Alertable, PLARGE_INTEGER TimeOut) {
    DWORD callerId = GetCurrentThreadId();

    CHAR* log = (CHAR*)malloc(256);
    HMODULE hModule;
    char lpBaseName[256] = { 0 };
    if (memcmp(_ReturnAddress(), "\x4c\x8b\xc0\x48\x85\xc0\x0f\x84", 8) == 0 || memcmp(_ReturnAddress(), "\x48\x8b\xd8\x48\x85\xc0\x0f\x84", 8) == 0) {
        strcpy_s(lpBaseName, "ntdll.dll");
    }
    else {
        LPCSTR data = (LPCSTR)_ReturnAddress();
        if (::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule) == 1) {
            ::GetModuleBaseNameA(GetCurrentProcess(), hModule, lpBaseName, sizeof(lpBaseName));
        }
        else {
            if (threadMonitor == NULL) {
                threadMonitor = callerId;
            }
            snprintf(log, 255, "Suspicious NtWaitForSingleObject() from thread with id:%d Timeout: %u\n", callerId, TimeOut);
            LogDetected(&log);
        }
    }
    std::string modName = lpBaseName;
    std::transform(modName.begin(), modName.end(), modName.begin(),
        [](unsigned char c) { return tolower(c); });
    if (dllMonitor != "NULL" && dllMonitor.find(modName) != std::string::npos) {
        snprintf(log, 255, "Suspicious NtWaitForSingleObject() from module with name: %s Timeout: %u\n", dllMonitor.c_str(), TimeOut);
        LogDetected(&log);
    }
    free(log);

    return OldWaitForSingleObj(ObjectHandle, Alertable, TimeOut);
}

HINTERNET(WINAPI* OldInternetConnectA)(HINTERNET hConnect, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
//Hooked InternetConnectA
HINTERNET WINAPI HookedInternetConnectA(HINTERNET hConnect, LPCSTR lpszServerName, INTERNET_PORT nServerPort, LPCSTR lpszUserName, LPCSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    DWORD callerId = GetCurrentThreadId();

    CHAR* log = (CHAR*)malloc(256);
    HMODULE hModule;
    char lpBaseName[256] = { 0 };
    if (memcmp(_ReturnAddress(), "\x4c\x8b\xc0\x48\x85\xc0\x0f\x84", 8) == 0 || memcmp(_ReturnAddress(), "\x48\x8b\xd8\x48\x85\xc0\x0f\x84", 8) == 0) {
        strcpy_s(lpBaseName, "ntdll.dll");
    }
    else {
        LPCSTR data = (LPCSTR)_ReturnAddress();
        if (::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule) == 1) {
            ::GetModuleBaseNameA(GetCurrentProcess(), hModule, lpBaseName, sizeof(lpBaseName));
        }
        else {
            if (threadMonitor == NULL) {
                threadMonitor = callerId;
            }
            snprintf(log, 255, "Suspicious InternetConnectA() from thread with id:%d Name: %s Creds: %s[%s]\n", callerId, lpszServerName, lpszUserName, lpszPassword);
            LogDetected(&log);
        }
    }
    std::string modName = lpBaseName;
    std::transform(modName.begin(), modName.end(), modName.begin(),
        [](unsigned char c) { return tolower(c); });
    //printf("Suspicious InternetConnectA() from thread with id: %d, Name: %s\n", callerId, lpszServerName);
    if (dllMonitor != "NULL" && dllMonitor.find(modName) != std::string::npos) {
        snprintf(log, 255, "Suspicious InternetConnectA() from module with name: %s, Name: %s Creds: %s[%s]\n", dllMonitor.c_str(), lpszServerName, lpszUserName, lpszPassword);
        LogDetected(&log);
    }
    free(log);

    return OldInternetConnectA(hConnect, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

HINTERNET(WINAPI* OldInternetConnectW)(HINTERNET hConnect, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext);
//Hooked InternetConnectA
HINTERNET WINAPI HookedInternetConnectW(HINTERNET hConnect, LPCWSTR lpszServerName, INTERNET_PORT nServerPort, LPCWSTR lpszUserName, LPCWSTR lpszPassword, DWORD dwService, DWORD dwFlags, DWORD_PTR dwContext) {
    DWORD callerId = GetCurrentThreadId();

    CHAR* log = (CHAR*)malloc(256);
    HMODULE hModule;
    char lpBaseName[256] = { 0 };
    if (memcmp(_ReturnAddress(), "\x4c\x8b\xc0\x48\x85\xc0\x0f\x84", 8) == 0 || memcmp(_ReturnAddress(), "\x48\x8b\xd8\x48\x85\xc0\x0f\x84", 8) == 0) {
        strcpy_s(lpBaseName, "ntdll.dll");
    }
    else {
        LPCSTR data = (LPCSTR)_ReturnAddress();
        if (::GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCSTR)_ReturnAddress(), &hModule) == 1) {
            ::GetModuleBaseNameA(GetCurrentProcess(), hModule, lpBaseName, sizeof(lpBaseName));
        }
        else {
            if (threadMonitor == NULL) {
                threadMonitor = callerId;
            }
            snprintf(log, 255, "Suspicious InternetConnectW() from thread with id:%d Name: %s Creds: %s[%s]\n", callerId, lpszServerName, lpszUserName, lpszPassword);
            LogDetected(&log);
        }
    }
    std::string modName = lpBaseName;
    std::transform(modName.begin(), modName.end(), modName.begin(),
        [](unsigned char c) { return tolower(c); });
    if (dllMonitor != "NULL" && dllMonitor.find(modName) != std::string::npos) {
        snprintf(log, 255, "Suspicious InternetConnectW() from module with name: %s, Name: %s Creds: %s[%s]\n", dllMonitor.c_str(), lpszServerName, lpszUserName, lpszPassword);
        LogDetected(&log);
    }
    free(log);

    return OldInternetConnectW(hConnect, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext);
}

int main()
{
    NtQueryInformationThread = (NtQueryInformationThread_t)GetProcAddress(LoadLibrary("ntdll.dll"), "NtQueryInformationThread");

    // Sleep for sanity
    //Sleep(100);

    // Most of this stuff will break stuff so I commented it out.
    // Refresh the most important DLLs in case they are hooked and detect any VEH hooks
    //universalRefresher("ntdll.dll");
    //universalRefresher("kernel32.dll");
    //universalRefresher("kernelbase.dll");
    //universalRefresher("msvcrt.dll");

    // Break the exception dispatcher.  It will always just immediately return.  We do this AFTER the unhooking as that removes hooks and restores PAGE_EXECUTE_READ to the .text
    /*ULONG oldProtect;
    FARPROC addr = 0;
    HMODULE libntdll = LoadLibraryA("ntdll.dll");
    if (libntdll) {
        addr = GetProcAddress(libntdll, "KiUserExceptionDispatcher");
    }
    if (addr != 0) {
        char* moduleChar = (char*)addr;
        _VirtualProtect(GetCurrentProcess(), (PVOID*)&addr, (PSIZE_T)1, PAGE_EXECUTE_READWRITE, &oldProtect);
        moduleChar[0] = 0xC3;
        _VirtualProtect(GetCurrentProcess(), (PVOID*)&addr, (PSIZE_T)1, oldProtect, &oldProtect);
    }*/

    // Detect any DLL or EXE hollows and any Inline Hooks
    std::string Monitor = DetectHollowingAndHooks(GetCurrentProcessId());
    if (Monitor != "NULL") {
        dllMonitor = Monitor;
    }

    // Start our own hooks and log failures
    CHAR* log = (CHAR*)malloc(256);
    // Initialize MinHook.
    if (MH_Initialize() != MH_OK)
    {
        snprintf(log, 255, "Failed to initalize minhook!  Try again running as Admin.\n\n");
        Log(&log);
        return 1;
    }

    if (MH_CreateHookApiEx(
        L"ntdll.dll", "RtlAllocateHeap", &HookedAlloc, &OldAlloc) != MH_OK)
    {
        snprintf(log, 255, "Failed to hook RtlAllocateHeap!  Try again running as Admin.\n\n");
        Log(&log);
        return 1;
    }

    /*if (MH_CreateHookApiEx(
        L"kernel32.dll", "Sleep", &HookedSleep, &OldSleep) != MH_OK)
    {
        snprintf(log, 255, "Failed to hook Sleep!  Try again running as Admin.\n\n");
        Log(&log);
        return 1;
    }*/

    if (MH_CreateHookApiEx(
        L"ntdll.dll", "NtWaitForSingleObject", &HookedWaitForSingleObj, &OldWaitForSingleObj) != MH_OK)
    {
        snprintf(log, 255, "Failed to hook NtWaitForSingleObject!  Try again running as Admin.\n\n");
        Log(&log);
        return 1;
    }

    
    FARPROC InternetConnectA = GetProcAddress(LoadLibraryA("wininet.dll"), "InternetConnectA");
    if (MH_CreateHook(InternetConnectA, &HookedInternetConnectA, reinterpret_cast<LPVOID*>(&OldInternetConnectA)) != MH_OK)
    {
        snprintf(log, 255, "Failed to hook InternetConnectA!  Try again running as Admin.\n\n");
        Log(&log);
        return 1;
    }

    FARPROC InternetConnectW = GetProcAddress(LoadLibraryA("wininet.dll"), "InternetConnectW");
    if (MH_CreateHook(InternetConnectW, &HookedInternetConnectA, reinterpret_cast<LPVOID*>(&OldInternetConnectW)) != MH_OK)
    {
        snprintf(log, 255, "Failed to hook InternetConnectW!  Try again running as Admin.\n\n");
        Log(&log);
        return 1;
    }

    // Enable the hook for MessageBoxW.
    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    {
        snprintf(log, 255, "Failed to enable all hooks!  Try again running as Admin.\n\n");
        Log(&log);
        return 1;
    }
    free(log);
    return 0;
}

BOOL attached = FALSE;
#if defined(RELEASE_DLL) || defined(RELEASE_DLL64)
BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        main();
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
#endif