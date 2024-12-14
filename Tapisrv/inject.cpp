#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <string.h>
#include <tchar.h>
#include <psapi.h>

#include "nyx_api.h"
#pragma comment(lib, "ntdll.lib")

#define ARRAY_SIZE 1024
#define INFO_SIZE                       (128 << 10)				/* 128KB info string */ 
#define CALLBACK_ADDR 0x34160//0x3a2a0 //

//#define SERVICE_NAME "SysMain"
#define SERVICE_NAME "TapiSrv"

DWORD GetServicePID(const TCHAR* serviceName) {
    SC_HANDLE scmHandle, serviceHandle;
    ENUM_SERVICE_STATUS_PROCESS* services;
    DWORD bytesNeeded, servicesReturned, i, processID = 0;

    scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);

    if (scmHandle == NULL) {
        _tprintf(_T("Failed to open Service Control Manager. Error %lu\n"), GetLastError());
        return 0;
    }

    if (!EnumServicesStatusEx(scmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        NULL, 0, &bytesNeeded, &servicesReturned, NULL, NULL)) {
        if (GetLastError() != ERROR_MORE_DATA) {
            _tprintf(_T("Failed to enumerate services. Error %lu\n"), GetLastError());
            CloseServiceHandle(scmHandle);
            return 0;
        }
    }

    services = (ENUM_SERVICE_STATUS_PROCESS*)malloc(bytesNeeded);
    if (services == NULL) {
        _tprintf(_T("Memory allocation error.\n"));
        CloseServiceHandle(scmHandle);
        return 0;
    }

    if (!EnumServicesStatusEx(scmHandle, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
        (LPBYTE)services, bytesNeeded, &bytesNeeded, &servicesReturned, NULL, NULL)) {
        _tprintf(_T("Failed to enumerate services. Error %lu\n"), GetLastError());
        free(services);
        CloseServiceHandle(scmHandle);
        return 0;
    }

    for (i = 0; i < servicesReturned; i++) {
        if (_tcscmp(services[i].lpServiceName, serviceName) == 0) {
            serviceHandle = OpenService(scmHandle, services[i].lpServiceName, SERVICE_QUERY_STATUS);
            if (serviceHandle != NULL) {
                SERVICE_STATUS_PROCESS serviceStatus;
                if (QueryServiceStatusEx(serviceHandle, SC_STATUS_PROCESS_INFO, (LPBYTE)&serviceStatus, sizeof(SERVICE_STATUS_PROCESS), &bytesNeeded)) {
                    processID = serviceStatus.dwProcessId;
                }
                else {
                    _tprintf(_T("Failed to query service status. Error %lu\n"), GetLastError());
                }
                CloseServiceHandle(serviceHandle);
            }
            else {
                _tprintf(_T("Failed to open service. Error %lu\n"), GetLastError());
            }
            break;
        }
    }

    free(services);
    CloseServiceHandle(scmHandle);

    return processID;
}

BOOL EnablePrivilegeForProcess(DWORD dwPID, LPCTSTR lpszPrivilege) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
    if (hProcess == NULL) {
        hprintf("Failed to open process. Error: %d\n", GetLastError());
        return FALSE;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        hprintf("OpenProcessToken failed. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return FALSE;
    }

    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        hprintf("LookupPrivilegeValue error: %u\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        hprintf("AdjustTokenPrivileges error: %u\n", GetLastError());
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        hprintf("The token does not have the specified privilege.\n");
        CloseHandle(hToken);
        CloseHandle(hProcess);
        return FALSE;
    }

    CloseHandle(hToken);
    CloseHandle(hProcess);
    return TRUE;
}

int main() {
    // edit this dll path
    wchar_t dllPath[] = L"C:\\Users\\Public\\kafl_tapisrv.dll";

    DWORD servicePID = GetServicePID(_T(SERVICE_NAME));
    if (servicePID == 0) {
        hprintf("Failed to get service PID\n");
        return 1;
    }

    hprintf("[go_inject]: %d\n", servicePID);

    // 프로세스에 SE_INCREASE_QUOTA_NAME 권한 부여 시도
    if (EnablePrivilegeForProcess(servicePID, SE_INCREASE_QUOTA_NAME)) {
        hprintf("Successfully enabled SE_INCREASE_QUOTA_NAME privilege for TapiSrv\n");
    }
    else {
        hprintf("Failed to enable SE_INCREASE_QUOTA_NAME privilege for TapiSrv\n");
        // 권한 부여에 실패해도 계속 진행
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, servicePID);
    if (hProcess == NULL) {
        hprintf("Service OpenProcess Error: %d\n", GetLastError());
        return 1;
    }


    LPVOID remoteString = VirtualAllocEx(hProcess, NULL, sizeof(dllPath), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, remoteString, dllPath, sizeof(dllPath), NULL);

    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");

    hprintf("GO INJECT\n");
    hprintf("kernel32 addr: 0x%llx\n", loadLibraryAddr);
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, remoteString, 0, NULL);
    //SetThreadPriority(hThread, THREAD_PRIORITY_ABOVE_NORMAL);
    if (hThread == NULL) {
        hprintf("Error2: %d\n", GetLastError());
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, remoteString, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
