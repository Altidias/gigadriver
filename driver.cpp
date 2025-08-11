extern "C" {
#include <ntifs.h>
#include <ntddk.h>
}

// Compatibility layer for different WDK versions
#ifdef POOL_FLAG_NON_PAGED
    // Newer WDK with ExAllocatePool2
#define ALLOCATE_NONPAGED_POOL(size, tag) \
        ExAllocatePool2(POOL_FLAG_NON_PAGED, size, tag)
#define FREE_POOL(ptr) ExFreePool(ptr)
#else
    // Older WDK with ExAllocatePoolWithTag
#pragma warning(push)
#pragma warning(disable: 4996) // Disable deprecation warning
#define ALLOCATE_NONPAGED_POOL(size, tag) \
        ExAllocatePoolWithTag(NonPagedPool, size, tag)
#define FREE_POOL(ptr) ExFreePoolWithTag(ptr, 'TSPS')
#pragma warning(pop)
#endif

#define SHARED_SECTION_NAME L"\\BaseNamedObjects\\MySharedSection"
#define CHUNK_SIZE (64 * 1024)  // 64KB chunks for efficiency

// Extended structure for full speed test
typedef struct _SHARED_DATA {
    // Control fields
    volatile LONG MagicNumber;       // 0xAABBCCDD from usermode, 0x12345678 from kernel
    volatile LONG StartFlag;         // 1 = start test, 0 = stop test
    volatile LONG ThreadRunning;     // 1 = kernel thread is running
    volatile LONG StopRequested;     // 1 = request kernel thread to exit completely

    // Speed test fields
    volatile LONG WriteIndex;        // Current write position in buffer
    volatile LONG ReadIndex;         // Current read position in buffer  
    volatile LONG64 BytesWritten;    // Total bytes written by kernel
    volatile LONG64 BytesRead;       // Total bytes read by usermode

    // Statistics
    LARGE_INTEGER StartTime;         // When test started
    LARGE_INTEGER LastUpdateTime;    // Last update timestamp
    volatile LONG BufferSize;        // Size of data buffer

    // Padding for alignment
    ULONG Reserved[8];
} SHARED_DATA, * PSHARED_DATA;

// Globals
HANDLE g_SectionHandle = nullptr;
PVOID g_SectionObject = nullptr;
PVOID g_SystemMapping = nullptr;
SIZE_T g_MappedSize = 0;
HANDLE g_ThreadHandle = nullptr;
volatile LONG g_ThreadShouldExit = 0;

// Generate test pattern
VOID GeneratePattern(PUCHAR buffer, ULONG size, ULONG seed)
{
    for (ULONG i = 0; i < size; i++) {
        buffer[i] = (UCHAR)((seed + i) & 0xFF);
    }
}

// Worker thread for speed test
VOID SpeedTestThread(PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SPEED] Worker thread started! Mapping=0x%p, Size=%zu\n",
        g_SystemMapping, g_MappedSize);

    if (!g_SystemMapping || g_MappedSize < sizeof(SHARED_DATA)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SPEED] ERROR: Invalid mapping!\n");
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    PSHARED_DATA pControl = (PSHARED_DATA)g_SystemMapping;
    PUCHAR pBuffer = (PUCHAR)g_SystemMapping + sizeof(SHARED_DATA);
    ULONG bufferSize = (ULONG)(g_MappedSize - sizeof(SHARED_DATA));

    // Verify magic number
    if (pControl->MagicNumber != 0xAABBCCDD && pControl->MagicNumber != 0x12345678) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SPEED] ERROR: Invalid magic number 0x%X!\n", pControl->MagicNumber);
        PsTerminateSystemThread(STATUS_UNSUCCESSFUL);
        return;
    }

    // Update magic and initialize
    pControl->MagicNumber = 0x12345678;
    pControl->BufferSize = bufferSize;
    InterlockedExchange(&pControl->ThreadRunning, 1);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SPEED] Thread running, buffer size=%u bytes\n", bufferSize);

    // Allocate pattern buffer using compatibility macro
    PUCHAR pattern = (PUCHAR)ALLOCATE_NONPAGED_POOL(CHUNK_SIZE, 'TSPS');
    if (!pattern) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SPEED] Failed to allocate pattern buffer\n");
        InterlockedExchange(&pControl->ThreadRunning, 0);
        PsTerminateSystemThread(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    // Generate initial pattern
    GeneratePattern(pattern, CHUNK_SIZE, 0);

    ULONG totalChunks = 0;
    ULONG patternSeed = 0;

    // Main loop
    while (InterlockedCompareExchange(&g_ThreadShouldExit, 0, 0) == 0) {

        // Check if we should stop completely
        if (InterlockedCompareExchange(&pControl->StopRequested, 0, 0) == 1) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                "[SPEED] Stop requested by usermode, exiting thread...\n");
            break;
        }

        // Check if test is running
        if (InterlockedCompareExchange(&pControl->StartFlag, 0, 0) == 0) {
            // Test not running, wait
            LARGE_INTEGER timeout;
            timeout.QuadPart = -1000000; // 100ms
            KeDelayExecutionThread(KernelMode, FALSE, &timeout);
            continue;
        }

        // Get current indices
        LONG writeIdx = pControl->WriteIndex;
        LONG readIdx = pControl->ReadIndex;

        // Validate indices
        if (writeIdx < 0 || writeIdx >(LONG)bufferSize) writeIdx = 0;
        if (readIdx < 0 || readIdx >(LONG)bufferSize) readIdx = 0;

        // Calculate available space in circular buffer
        LONG availableSpace;
        if (writeIdx >= readIdx) {
            availableSpace = bufferSize - writeIdx + readIdx;
        }
        else {
            availableSpace = readIdx - writeIdx;
        }

        // Leave 1KB gap to avoid full buffer condition
        if (availableSpace > 1024) {
            availableSpace -= 1024;

            // Determine how much to write (up to CHUNK_SIZE)
            ULONG bytesToWrite = min(availableSpace, CHUNK_SIZE);

            // Handle circular buffer wrap-around
            if (writeIdx + bytesToWrite > bufferSize) {
                // Write in two parts
                ULONG firstPart = bufferSize - writeIdx;
                ULONG secondPart = bytesToWrite - firstPart;

                // Update pattern for uniqueness
                GeneratePattern(pattern, bytesToWrite, patternSeed++);

                // Copy first part to end of buffer
                RtlCopyMemory(pBuffer + writeIdx, pattern, firstPart);

                // Copy second part to beginning of buffer
                if (secondPart > 0) {
                    RtlCopyMemory(pBuffer, pattern + firstPart, secondPart);
                }

                // Update write index
                InterlockedExchange(&pControl->WriteIndex, secondPart);
            }
            else {
                // Simple write without wrap-around
                GeneratePattern(pattern, bytesToWrite, patternSeed++);
                RtlCopyMemory(pBuffer + writeIdx, pattern, bytesToWrite);

                // Update write index
                LONG newWriteIdx = writeIdx + bytesToWrite;
                if (newWriteIdx >= (LONG)bufferSize) {
                    newWriteIdx = 0;
                }
                InterlockedExchange(&pControl->WriteIndex, newWriteIdx);
            }

            // Update bytes written counter
            InterlockedAdd64(&pControl->BytesWritten, bytesToWrite);

            // Update timestamp
            KeQuerySystemTime(&pControl->LastUpdateTime);

            totalChunks++;

            // Log progress periodically
            if ((totalChunks % 1000) == 0) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
                    "[SPEED] Written %u MB total\n",
                    (ULONG)(pControl->BytesWritten / (1024 * 1024)));
            }

        }
        else {
            // Buffer is nearly full, wait for reader
            LARGE_INTEGER timeout;
            timeout.QuadPart = -10000; // 1ms
            KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        }

        // Yield CPU periodically for better system responsiveness
        if ((totalChunks % 100) == 0) {
            LARGE_INTEGER timeout = { 0 };
            KeDelayExecutionThread(KernelMode, FALSE, &timeout);
        }
    }

    // Cleanup
    FREE_POOL(pattern);

    // Clear thread running flag
    InterlockedExchange(&pControl->ThreadRunning, 0);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SPEED] Thread exiting. Total bytes written: %lld\n",
        pControl->BytesWritten);

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
        "[SPEED] ===== FULL SPEED TEST DRIVER =====\n");

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
            "[SPEED] Failed to open section: 0x%X\n", status);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SPEED] Make sure usermode app created it first!\n");
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
            "[SPEED] Failed to reference section: 0x%X\n", status);
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
            "[SPEED] Failed to map in system space: 0x%X\n", status);
        ObDereferenceObject(g_SectionObject);
        ZwClose(g_SectionHandle);
        return STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SPEED] Mapped at 0x%p, size=%zu bytes\n", g_SystemMapping, g_MappedSize);

    // Verify and initialize
    PSHARED_DATA pControl = (PSHARED_DATA)g_SystemMapping;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SPEED] Initial state: Magic=0x%X, StartFlag=%d\n",
        pControl->MagicNumber, pControl->StartFlag);

    // Create worker thread
    status = PsCreateSystemThread(
        &g_ThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        SpeedTestThread,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
            "[SPEED] Failed to create thread: 0x%X\n", status);
        MmUnmapViewInSystemSpace(g_SystemMapping);
        ObDereferenceObject(g_SectionObject);
        ZwClose(g_SectionHandle);
        return STATUS_SUCCESS;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SPEED] Worker thread created successfully\n");

    if (g_ThreadHandle) {
        ZwClose(g_ThreadHandle);
        g_ThreadHandle = nullptr;
    }

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
        "[SPEED] ===== DRIVER READY FOR SPEED TEST =====\n");

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
