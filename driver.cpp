extern "C" {
#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>
}

// Compatibility layer for different WDK versions
#ifdef POOL_FLAG_NON_PAGED
#define ALLOCATE_NONPAGED_POOL(size, tag) \
        ExAllocatePool2(POOL_FLAG_NON_PAGED, size, tag)
#define FREE_POOL(ptr) ExFreePool(ptr)
#else
#pragma warning(push)
#pragma warning(disable: 4996)
#define ALLOCATE_NONPAGED_POOL(size, tag) \
        ExAllocatePoolWithTag(NonPagedPool, size, tag)
#define FREE_POOL(ptr) ExFreePoolWithTag(ptr, 'DAER')
#pragma warning(pop)
#endif

#define SHARED_SECTION_NAME L"\\BaseNamedObjects\\ProcessReaderSection"
#define MAX_RESPONSE_SIZE (4 * 1024)  // 4KB for response data

// Process offsets
#ifdef _WIN64
#define EPROCESS_IMAGEFILENAME_OFFSET 0x5A8
#else
#define EPROCESS_IMAGEFILENAME_OFFSET 0x2E0
#endif

// Commands from usermode
typedef enum _READER_COMMAND {
    CMD_NONE = 0,
    CMD_GET_SYSTEM_VERSION = 1,
    CMD_FIND_PROCESS = 2,
    CMD_READ_PROCESS_INFO = 3,
    CMD_LIST_PROCESSES = 4,
    CMD_STOP_THREAD = 99
} READER_COMMAND;

// Shared memory structure
typedef struct _SHARED_READER_DATA {
    // Control fields
    volatile LONG MagicNumber;       // 0xDEADBEEF from usermode, 0xCAFEBABE from kernel
    volatile LONG ThreadRunning;     // 1 = kernel thread is running

    // Command interface
    volatile LONG Command;           // Command from usermode (READER_COMMAND)
    volatile LONG CommandReady;      // 1 = command ready for processing
    volatile LONG ResponseReady;     // 1 = response ready for reading
    volatile LONG ProcessingCommand; // 1 = kernel is processing command

    // Command parameters
    CHAR TargetProcessName[256];    // For CMD_FIND_PROCESS
    ULONG TargetPid;                // For CMD_READ_PROCESS_INFO

    // Response fields
    volatile LONG ResponseStatus;    // NTSTATUS of operation
    volatile LONG ResponseLength;    // Length of response data

    // Statistics
    LARGE_INTEGER LastCommandTime;
    volatile LONG CommandsProcessed;

    // Response buffer (variable length data)
    CHAR ResponseBuffer[MAX_RESPONSE_SIZE];

} SHARED_READER_DATA, * PSHARED_READER_DATA;

// Process info structure for response
typedef struct _PROCESS_INFO {
    ULONG ProcessId;
    CHAR ProcessName[256];
    PVOID BaseAddress;
    CHAR AdditionalInfo[512];
} PROCESS_INFO, * PPROCESS_INFO;

// Globals
HANDLE g_SectionHandle = nullptr;
PVOID g_SectionObject = nullptr;
PVOID g_SystemMapping = nullptr;
SIZE_T g_MappedSize = 0;
HANDLE g_ThreadHandle = nullptr;
volatile LONG g_ThreadShouldExit = 0;

// Safe function to get process name
PCHAR GetProcessName(PEPROCESS Process) {
    __try {
        typedef PCHAR(*PsGetProcessImageFileNameFunc)(PEPROCESS);
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsGetProcessImageFileName");

        PsGetProcessImageFileNameFunc getImageFileName =
            (PsGetProcessImageFileNameFunc)MmGetSystemRoutineAddress(&routineName);

        if (getImageFileName) {
            return getImageFileName(Process);
        }

        return (PCHAR)((PUCHAR)Process + EPROCESS_IMAGEFILENAME_OFFSET);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return "Unknown";
    }
}

// Get Windows version from SharedUserData
NTSTATUS GetWindowsVersion(PCHAR outputBuffer, SIZE_T bufferSize) {
    typedef struct _MY_KUSER_SHARED_DATA {
        ULONG TickCountLowDeprecated;
        ULONG TickCountMultiplier;
        UCHAR Reserved[0x258];
        USHORT NtBuildNumber;
        USHORT Reserved2;
        ULONG Reserved3;
        ULONG NtMajorVersion;
        ULONG NtMinorVersion;
    } MY_KUSER_SHARED_DATA, * PMY_KUSER_SHARED_DATA;

    PMY_KUSER_SHARED_DATA sharedData = (PMY_KUSER_SHARED_DATA)0x7FFE0000;

    __try {
        ULONG majorVersion = sharedData->NtMajorVersion;
        ULONG minorVersion = sharedData->NtMinorVersion;
        USHORT buildNumber = sharedData->NtBuildNumber;

        NTSTATUS status = RtlStringCbPrintfA(
            outputBuffer,
            bufferSize,
            "Windows %u.%u Build %u",
            majorVersion,
            minorVersion,
            buildNumber
        );

        if (NT_SUCCESS(status)) {
            if (buildNumber >= 22000) {
                RtlStringCbCatA(outputBuffer, bufferSize, " (Windows 11)");
            }
            else if (buildNumber >= 19041) {
                RtlStringCbCatA(outputBuffer, bufferSize, " (Windows 10)");
            }
            else if (majorVersion == 6 && minorVersion == 3) {
                RtlStringCbCatA(outputBuffer, bufferSize, " (Windows 8.1)");
            }
            else if (majorVersion == 6 && minorVersion == 2) {
                RtlStringCbCatA(outputBuffer, bufferSize, " (Windows 8)");
            }
            else if (majorVersion == 6 && minorVersion == 1) {
                RtlStringCbCatA(outputBuffer, bufferSize, " (Windows 7)");
            }

            return STATUS_SUCCESS;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_ACCESS_VIOLATION;
    }

    return STATUS_UNSUCCESSFUL;
}

// Find process by name and get info
NTSTATUS FindProcessByName(const char* targetName, PPROCESS_INFO pInfo) {
    for (ULONG pid = 4; pid < 65536; pid += 4) {
        PEPROCESS process = NULL;

        // Skip PID 0 (System Idle Process) - PsLookupProcessByProcessId doesn't accept it
        if (pid == 0) continue;

        NTSTATUS status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);

        if (NT_SUCCESS(status) && process) {
            PCHAR processName = GetProcessName(process);

            if (processName && _stricmp(processName, targetName) == 0) {
                // Found the process
                pInfo->ProcessId = pid;
                RtlStringCbCopyA(pInfo->ProcessName, sizeof(pInfo->ProcessName), processName);

                // Get additional info
                HANDLE hProcess = PsGetProcessId(process);
                RtlStringCbPrintfA(pInfo->AdditionalInfo, sizeof(pInfo->AdditionalInfo),
                    "PID: %u, EPROCESS: 0x%p, Handle: 0x%p",
                    pid, process, hProcess);

                ObDereferenceObject(process);
                return STATUS_SUCCESS;
            }

            ObDereferenceObject(process);
        }
    }

    return STATUS_NOT_FOUND;
}

// List all running processes
NTSTATUS ListProcesses(PSHARED_READER_DATA pShared) {
    ULONG count = 0;
    PCHAR pBuffer = pShared->ResponseBuffer;
    SIZE_T bufferRemaining = MAX_RESPONSE_SIZE;

    // Header
    NTSTATUS status = RtlStringCbPrintfExA(
        pBuffer, bufferRemaining,
        &pBuffer, &bufferRemaining,
        0,
        "=== Process List ===\n"
    );

    if (!NT_SUCCESS(status)) return status;

    // Enumerate processes
    for (ULONG pid = 4; pid < 65536 && bufferRemaining > 100; pid += 4) {
        // Skip PID 0 - PsLookupProcessByProcessId doesn't accept it
        if (pid == 0) continue;

        PEPROCESS process = NULL;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);

        if (NT_SUCCESS(status) && process) {
            PCHAR processName = GetProcessName(process);

            if (processName && strlen(processName) > 0) {
                status = RtlStringCbPrintfExA(
                    pBuffer, bufferRemaining,
                    &pBuffer, &bufferRemaining,
                    0,
                    "[%5u] %s\n",
                    pid, processName
                );

                if (NT_SUCCESS(status)) {
                    count++;
                }
            }

            ObDereferenceObject(process);
        }

        // Limit output
        if (count >= 50) {
            RtlStringCbPrintfExA(
                pBuffer, bufferRemaining,
                &pBuffer, &bufferRemaining,
                0,
                "\n... and more (showing first 50)\n"
            );
            break;
        }
    }

    // Footer
    RtlStringCbPrintfExA(
        pBuffer, bufferRemaining,
        &pBuffer, &bufferRemaining,
        0,
        "\nTotal processes shown: %u\n",
        count
    );

    pShared->ResponseLength = (LONG)(MAX_RESPONSE_SIZE - bufferRemaining);
    return STATUS_SUCCESS;
}

// Process command from usermode
NTSTATUS ProcessCommand(PSHARED_READER_DATA pShared) {
    NTSTATUS status = STATUS_SUCCESS;
    READER_COMMAND cmd = (READER_COMMAND)pShared->Command;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[READER] Processing command: %d\n", cmd);

    // Clear response buffer
    RtlZeroMemory(pShared->ResponseBuffer, MAX_RESPONSE_SIZE);
    pShared->ResponseLength = 0;

    switch (cmd) {
    case CMD_GET_SYSTEM_VERSION:
    {
        status = GetWindowsVersion(pShared->ResponseBuffer, MAX_RESPONSE_SIZE);
        if (NT_SUCCESS(status)) {
            pShared->ResponseLength = (LONG)strlen(pShared->ResponseBuffer);
        }
        break;
    }

    case CMD_FIND_PROCESS:
    {
        PROCESS_INFO procInfo = { 0 };
        status = FindProcessByName(pShared->TargetProcessName, &procInfo);

        if (NT_SUCCESS(status)) {
            RtlStringCbPrintfA(pShared->ResponseBuffer, MAX_RESPONSE_SIZE,
                "Process Found:\n"
                "  Name: %s\n"
                "  PID: %u\n"
                "  %s\n",
                procInfo.ProcessName,
                procInfo.ProcessId,
                procInfo.AdditionalInfo);

            pShared->ResponseLength = (LONG)strlen(pShared->ResponseBuffer);
        }
        else {
            RtlStringCbPrintfA(pShared->ResponseBuffer, MAX_RESPONSE_SIZE,
                "Process '%s' not found",
                pShared->TargetProcessName);
            pShared->ResponseLength = (LONG)strlen(pShared->ResponseBuffer);
        }
        break;
    }

    case CMD_READ_PROCESS_INFO:
    {
        PEPROCESS process = NULL;
        status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pShared->TargetPid, &process);

        if (NT_SUCCESS(status) && process) {
            PCHAR processName = GetProcessName(process);

            RtlStringCbPrintfA(pShared->ResponseBuffer, MAX_RESPONSE_SIZE,
                "Process Information:\n"
                "  PID: %u\n"
                "  Name: %s\n"
                "  EPROCESS: 0x%p\n",
                pShared->TargetPid,
                processName,
                process);

            pShared->ResponseLength = (LONG)strlen(pShared->ResponseBuffer);
            ObDereferenceObject(process);
        }
        else {
            RtlStringCbPrintfA(pShared->ResponseBuffer, MAX_RESPONSE_SIZE,
                "Process with PID %u not found",
                pShared->TargetPid);
            pShared->ResponseLength = (LONG)strlen(pShared->ResponseBuffer);
            status = STATUS_NOT_FOUND;
        }
        break;
    }

    case CMD_LIST_PROCESSES:
    {
        status = ListProcesses(pShared);
        break;
    }

    default:
        RtlStringCbPrintfA(pShared->ResponseBuffer, MAX_RESPONSE_SIZE,
            "Unknown command: %d", cmd);
        pShared->ResponseLength = (LONG)strlen(pShared->ResponseBuffer);
        status = STATUS_INVALID_PARAMETER;
        break;
    }

    return status;
}

// Worker thread
VOID ReaderWorkerThread(PVOID Context) {
    UNREFERENCED_PARAMETER(Context);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[READER] Worker thread started!\n");

    if (!g_SystemMapping || g_MappedSize < sizeof(SHARED_READER_DATA)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[READER] ERROR: Invalid mapping!\n");
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    PSHARED_READER_DATA pShared = (PSHARED_READER_DATA)g_SystemMapping;

    // Verify magic number
    if (pShared->MagicNumber != 0xDEADBEEF) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[READER] ERROR: Invalid magic number 0x%X!\n", pShared->MagicNumber);
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    // Update magic and set running flag
    pShared->MagicNumber = 0xCAFEBABE;
    InterlockedExchange(&pShared->ThreadRunning, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[READER] Thread ready for commands\n");

    // Main loop
    while (InterlockedCompareExchange(&g_ThreadShouldExit, 0, 0) == 0) {

        // Check for stop command
        if (pShared->Command == CMD_STOP_THREAD) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[READER] Stop command received\n");
            break;
        }

        // Check if command is ready
        if (InterlockedCompareExchange(&pShared->CommandReady, 0, 1) == 1) {
            // Mark as processing
            InterlockedExchange(&pShared->ProcessingCommand, 1);
            InterlockedExchange(&pShared->ResponseReady, 0);

            // Process the command
            NTSTATUS status = ProcessCommand(pShared);
            pShared->ResponseStatus = status;

            // Update statistics
            KeQuerySystemTime(&pShared->LastCommandTime);
            InterlockedIncrement(&pShared->CommandsProcessed);

            // Mark response as ready
            InterlockedExchange(&pShared->ProcessingCommand, 0);
            InterlockedExchange(&pShared->ResponseReady, 1);

            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[READER] Command processed: Status=0x%X, ResponseLen=%d\n",
                status, pShared->ResponseLength);
        }

        // Small delay to prevent CPU spinning
        LARGE_INTEGER timeout;
        timeout.QuadPart = -100000; // 10ms
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }

    // Clear running flag
    InterlockedExchange(&pShared->ThreadRunning, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[READER] Thread exiting. Commands processed: %d\n",
        pShared->CommandsProcessed);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[READER] ===== PROCESS READER COMMUNICATION DRIVER =====\n");

    NTSTATUS status;
    UNICODE_STRING sectionName;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&sectionName, SHARED_SECTION_NAME);

    InitializeObjectAttributes(
        &objAttr,
        &sectionName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,
        NULL
    );

    // Open the usermode-created section
    status = ZwOpenSection(
        &g_SectionHandle,
        SECTION_ALL_ACCESS,
        &objAttr
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[READER] Failed to open section: 0x%X\n", status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[READER] Make sure usermode app created it first!\n");
        return STATUS_SUCCESS;
    }

    // Get section object
    status = ObReferenceObjectByHandle(
        g_SectionHandle,
        SECTION_MAP_READ | SECTION_MAP_WRITE,
        NULL,
        KernelMode,
        &g_SectionObject,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[READER] Failed to reference section: 0x%X\n", status);
        ZwClose(g_SectionHandle);
        return STATUS_SUCCESS;
    }

    // Map in system space
    g_MappedSize = 0;
    status = MmMapViewInSystemSpace(
        g_SectionObject,
        &g_SystemMapping,
        &g_MappedSize
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[READER] Failed to map in system space: 0x%X\n", status);
        ObDereferenceObject(g_SectionObject);
        ZwClose(g_SectionHandle);
        return STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[READER] Mapped at 0x%p, size=%zu bytes\n", g_SystemMapping, g_MappedSize);

    // Create worker thread
    status = PsCreateSystemThread(
        &g_ThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        ReaderWorkerThread,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[READER] Failed to create thread: 0x%X\n", status);
        MmUnmapViewInSystemSpace(g_SystemMapping);
        ObDereferenceObject(g_SectionObject);
        ZwClose(g_SectionHandle);
        return STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[READER] Worker thread created successfully\n");

    if (g_ThreadHandle) {
        ZwClose(g_ThreadHandle);
        g_ThreadHandle = nullptr;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[READER] ===== DRIVER READY =====\n");

    return STATUS_SUCCESS;
}

// Entry point for KDMapper
extern "C" NTSTATUS CustomDriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    return DriverEntry(DriverObject, RegistryPath);
}
