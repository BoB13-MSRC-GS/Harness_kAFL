#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <string.h>
#include <tchar.h>
#include <psapi.h>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <wchar.h>
#include <locale.h>

#include "nyx_api.h"
#pragma comment(lib, "ntdll.lib")

#define ARRAY_SIZE 1024
#define INFO_SIZE                       (128 << 10)				/* 128KB info string */ 
#define CALLBACK_ADDR 0x34160//0x3a2a0 //

//#define SERVICE_NAME "SysMain"
//#define SERVICE_NAME "TapiSrv"
#define MAX_PATH_LENGTH 256
#define MAX_NAME_LENGTH 256
char serviceName[MAX_NAME_LENGTH];

const uint64_t _1MB = 1024 * 1024;

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

#define STATUS_WORKING_SET_QUOTA 0xc00000a1

#define MAP_PROCESS 1
#define MAP_SYSTEM 2

extern "C" NTSYSCALLAPI NTSTATUS NTAPI
NtLockVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID * BaseAddress,
    _Inout_ PSIZE_T RegionSize, _In_ ULONG MapType);

wchar_t* readServicePath(const char* filePath) {
    FILE* file = fopen(filePath, "r");
    if (file == NULL) {
        hprintf("Failed to open file: %s\n", filePath);
        return NULL;
    }

    char pathBuffer[MAX_PATH_LENGTH];
    if (fgets(pathBuffer, MAX_PATH_LENGTH, file) == NULL) {
        hprintf("Failed to read service path from file\n");
        fclose(file);
        return NULL;
    }

    pathBuffer[strcspn(pathBuffer, "\n")] = '\0';
    fclose(file);

    wchar_t* dllPath = (wchar_t*)malloc(MAX_PATH_LENGTH * sizeof(wchar_t));
    if (dllPath == NULL) {
        hprintf("Memory allocation failed\n");
        return NULL;
    }

    MultiByteToWideChar(CP_ACP, 0, pathBuffer, -1, dllPath, MAX_PATH_LENGTH);
    return dllPath;
}

void readServiceName(const char* filePath) {
    FILE* file = fopen(filePath, "r");
    if (file == NULL) {
        hprintf("Failed to open file: %s\n", filePath);
        exit(1);
    }

    if (fgets(serviceName, MAX_NAME_LENGTH, file) == NULL) {
        hprintf("Failed to read service name from file\n");
        fclose(file);
        exit(1);
    }

    serviceName[strcspn(serviceName, "\n")] = '\0';
    fclose(file);
}

#define SERVICE_NAME serviceName

DWORD readUTF16File(const char* filename) {
    int pidValue = 0;
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        hprintf("Failed to open PID output file.\n");
        return pidValue;
    }

    unsigned char bom[2];
    fread(bom, 1, 2, file);
    if (bom[0] != 0xFF || bom[1] != 0xFE) {
        hprintf("File is not UTF-16 LE encoded.\n");
        fclose(file);
        return pidValue;
    }

    wchar_t buffer[128];
    if (fgetws(buffer, sizeof(buffer) / sizeof(wchar_t), file) != NULL) {
        setlocale(LC_ALL, "");

        hprintf("Found PID: %ws\n", buffer);

        pidValue = _wtoi(buffer);
        if (pidValue > 0) {
            hprintf("PID as integer: %d\n", pidValue);
        }
    }
    else {
        hprintf("No running service found.\n");
    }

    fclose(file);

    return pidValue;
}

DWORD RunServiceAndPid() {
    const char* startServiceCommand =
        "powershell -Command \"Get-Service | Where-Object {$_.Name -like 'PimIndex*'} | ForEach-Object { Start-Service -Name $_.Name; }\"";
    printf("Starting services that begin with 'PimIndex'...\n");
    int result = system(startServiceCommand);
    if (result != 0) {
        printf("Failed to start services.\n");
        return 1;
    }

    const char* findPidCommand =
        "powershell -Command \"(Get-WmiObject Win32_Service | Where-Object {$_.Name -like 'PimIndex*' -and $_.State -eq 'Running'} | Select-Object -ExpandProperty ProcessId | Select-Object -First 1) > pid_output.txt\"";

    printf("\nFinding PID of running 'PimIndex' services...\n");
    result = system(findPidCommand);
    if (result != 0) {
        printf("Failed to find PID of services.\n");
        return 1;
    }

    int pidValue = readUTF16File("pid_output.txt");
    remove("pid_output.txt");
    Sleep(3000);
    return pidValue;
}

bool ForceLockInWorkingSet(HANDLE Process, PVOID BaseAddress,
    SIZE_T RegionSize) {
    for (size_t Tries = 0; Tries < 10; Tries++) {
        const NTSTATUS Status =
            NtLockVirtualMemory(Process, &BaseAddress, &RegionSize, MAP_PROCESS);

        if (NT_SUCCESS(Status)) {
            return true;
        }

        if (Status == STATUS_WORKING_SET_QUOTA) {
            SIZE_T MinimumWorkingSetSize = 0;
            SIZE_T MaximumWorkingSetSize = 0;
            DWORD Flags;

            if (!GetProcessWorkingSetSizeEx(Process, &MinimumWorkingSetSize,
                &MaximumWorkingSetSize, &Flags)) {
                hprintf("[Injector] Error GetProcessWorkingSetSizeEx: %d\n", GetLastError());
                return false;
            }

            MaximumWorkingSetSize *= 2;
            MinimumWorkingSetSize *= 2;

            hprintf("\tGrowing working set to %lld MB..\r",
                MinimumWorkingSetSize / _1MB);

            Flags = QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE;

            if (!SetProcessWorkingSetSizeEx(Process, MinimumWorkingSetSize,
                MaximumWorkingSetSize, Flags)) {
                hprintf("[Injector] Error SetProcessWorkingSetSizeEx: %d\n", GetLastError());
                return false;
            }
        }
    }

    hprintf("[Injector] Error, Ran out of tries to grow the working set.\n");

    return false;
}

bool LockMem(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION MemoryInfo;
    uint64_t NumberBytes = 0;
    uint64_t AmountMb = 0;
    for (uint8_t* Address = 0;
        VirtualQueryEx(hProcess, Address, &MemoryInfo, sizeof(MemoryInfo));
        Address = (uint8_t*)MemoryInfo.BaseAddress + MemoryInfo.RegionSize) {
        PVOID BaseAddress = MemoryInfo.BaseAddress;
        SIZE_T RegionSize = MemoryInfo.RegionSize;
        const uint32_t BadProtectBits = PAGE_GUARD | PAGE_NOACCESS;
        if (MemoryInfo.Protect & BadProtectBits) {
            // printf("Skipping %p - %llx because of protect bad bits..\n",
            //         BaseAddress, RegionSize);
            continue;
        }

        const uint32_t BadStatetBits = MEM_FREE | MEM_RESERVE;
        if (MemoryInfo.State & BadStatetBits) {
            // printf("Skipping %p - %llx because of state bad bits..\n",
            //         BaseAddress, RegionSize);
            continue;
        }

        if (!ForceLockInWorkingSet(hProcess, BaseAddress, RegionSize)) {
            hprintf("[Injector] Error ForceLockInWorkingSet: %d\n", GetLastError());
            return false;
        }

        // printf("Locked %p (%lld MB) in memory..\r", BaseAddress, RegionSize /
        // _1MB);

        auto Buffer = std::make_unique<uint8_t[]>(RegionSize);
        SIZE_T NumberBytesRead = 0;
        const bool Ret = ReadProcessMemory(hProcess, BaseAddress, Buffer.get(),
            RegionSize, &NumberBytesRead);
        if (!Ret || NumberBytesRead != RegionSize) {
            hprintf("[Injector] Error ReadProcessMemory: %d\n", GetLastError());
            return false;
        }

        // printf("Read region %p..\r", BaseAddress);
        NumberBytes += RegionSize;
        AmountMb = NumberBytes / _1MB;
        hprintf("\tLocked %llu MBs..\r", AmountMb);
    }

    hprintf("\tDone, locked %llu MBs\n", AmountMb);
    return true;
}

int main() {
    hprintf("[Injector] Start\n");
    hprintf("[Injector] Call readServiceName\n");
    readServiceName("C:\\Users\\Public\\ServiceName.txt");
    // edit this dll path
    wchar_t dllPath[] = L"C:\\Users\\Public\\kafl_pimindexmaintenance.dll";
    //hprintf("[Injector] Call readServicePath\n");
    //wchar_t* dllPath = readServicePath("C:\\Users\\Public\\ServicePath.txt");
    //DWORD PID = GetServicePID2(SERVICE_NAME);
    DWORD PID = RunServiceAndPid();

    hprintf("[Injector] Target Service: %s\n", SERVICE_NAME);
    hprintf("[Injector] Target Service PID: %d\n", PID);
    hprintf("[Injector] Harness DLL Path: %ws\n", dllPath);

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (hProcess == NULL) {
        hprintf("[Injector] Service OpenProcess Error: %d\n", GetLastError());
        return 1;
    }

    hprintf("[Injector] Try DLL Injection\n");
    hprintf("\tCall VirtualAllocEx\n");
    LPVOID remoteString = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);
    hprintf("\tCall VirtualAllocEx Addr: 0x%llX\n", (unsigned long long*)remoteString);
    hprintf("\tCall WriteProcessMemory\n");
    WriteProcessMemory(hProcess, remoteString, dllPath, sizeof(dllPath), NULL);

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

    hprintf("\tCall CreateRemoteThread\n");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteString, 0, NULL);
    //SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
    if (hThread == NULL) {
        hprintf("[Injector] Error CreateRemoteThread: %d\n", GetLastError());
        return 1;
    }
    hprintf("[Injector] Success DLL Injection\n");


    hprintf("[Injector] Try Lock Mem\n");
    if (LockMem(hProcess) == false) {
        hprintf("[Injector] Error Lock Mem\n");
        return 1;
    }
    hprintf("[Injector] Success Lock Mem\n");

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}