#include <windows.h>
#include <iostream>
#include <iomanip>
#include <thread>
#include <atomic>
#include <chrono>
#include <conio.h>

#define SECTION_SIZE (16 * 1024 * 1024)  // 16MB for better throughput testing
#define READ_CHUNK_SIZE (64 * 1024)      // 64KB read chunks

// Must match kernel structure EXACTLY
typedef struct _SHARED_DATA {
    // Control fields
    volatile LONG MagicNumber;
    volatile LONG StartFlag;
    volatile LONG ThreadRunning;
    volatile LONG StopRequested;

    // Speed test fields
    volatile LONG WriteIndex;
    volatile LONG ReadIndex;
    volatile LONG64 BytesWritten;
    volatile LONG64 BytesRead;

    // Statistics
    LARGE_INTEGER StartTime;
    LARGE_INTEGER LastUpdateTime;
    volatile LONG BufferSize;

    // Padding for alignment
    ULONG Reserved[8];
} SHARED_DATA, * PSHARED_DATA;

class SpeedTest {
private:
    HANDLE hSection;
    PVOID pBase;
    PSHARED_DATA pControl;
    PUCHAR pBuffer;
    std::atomic<bool> readerRunning;
    std::thread readerThread;
    std::thread statsThread;

    // Verify data pattern
    bool VerifyPattern(PUCHAR buffer, ULONG size, ULONG seed) {
        for (ULONG i = 0; i < size; i++) {
            if (buffer[i] != (UCHAR)((seed + i) & 0xFF)) {
                return false;
            }
        }
        return true;
    }

public:
    SpeedTest() : hSection(nullptr), pBase(nullptr), pControl(nullptr),
        pBuffer(nullptr), readerRunning(false) {
    }

    ~SpeedTest() {
        Cleanup();
    }

    bool Initialize() {
        std::cout << "[+] Creating shared memory section ("
            << (SECTION_SIZE / (1024 * 1024)) << " MB)..." << std::endl;

        // Create file mapping
        hSection = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE,
            0,
            SECTION_SIZE,
            L"Global\\MySharedSection"
        );

        if (!hSection) {
            std::cout << "[-] Failed to create section. Error: " << GetLastError() << std::endl;
            std::cout << "[!] Make sure you're running as Administrator!" << std::endl;
            return false;
        }

        if (GetLastError() == ERROR_ALREADY_EXISTS) {
            std::cout << "[*] Section already exists" << std::endl;
        }
        else {
            std::cout << "[+] Section created successfully" << std::endl;
        }

        // Map view
        pBase = MapViewOfFile(
            hSection,
            FILE_MAP_ALL_ACCESS,
            0, 0,
            SECTION_SIZE
        );

        if (!pBase) {
            std::cout << "[-] Failed to map view. Error: " << GetLastError() << std::endl;
            CloseHandle(hSection);
            hSection = nullptr;
            return false;
        }

        std::cout << "[+] Mapped at: 0x" << std::hex << pBase << std::dec << std::endl;

        // Initialize pointers
        pControl = (PSHARED_DATA)pBase;
        pBuffer = (PUCHAR)pBase + sizeof(SHARED_DATA);

        // Initialize control structure
        memset(pControl, 0, sizeof(SHARED_DATA));
        pControl->MagicNumber = 0xAABBCCDD;
        pControl->StartFlag = 0;
        pControl->ThreadRunning = 0;
        pControl->StopRequested = 0;
        pControl->WriteIndex = 0;
        pControl->ReadIndex = 0;
        pControl->BytesWritten = 0;
        pControl->BytesRead = 0;
        pControl->BufferSize = SECTION_SIZE - sizeof(SHARED_DATA);

        std::cout << "[+] Initialized with buffer size: "
            << (pControl->BufferSize / (1024 * 1024)) << " MB" << std::endl;

        return true;
    }

    void WaitForDriver() {
        std::cout << "\n[*] NOW load the kernel driver with KDMapper!" << std::endl;
        std::cout << "[*] Press any key after driver is loaded..." << std::endl;
        _getch();

        // Check if kernel modified the magic
        if (pControl->MagicNumber == 0x12345678) {
            std::cout << "[+] Kernel connected successfully!" << std::endl;
        }
        else {
            std::cout << "[!] Kernel may not have connected properly" << std::endl;
        }

        // Check if kernel thread is running
        if (pControl->ThreadRunning) {
            std::cout << "[+] Kernel thread is running!" << std::endl;
        }
        else {
            std::cout << "[!] Waiting for kernel thread..." << std::endl;
            for (int i = 0; i < 30; i++) {
                Sleep(100);
                if (pControl->ThreadRunning) {
                    std::cout << "[+] Kernel thread detected!" << std::endl;
                    break;
                }
            }
        }
    }

    void StartTest() {
        std::cout << "\n[+] Starting speed test..." << std::endl;

        // Reset counters
        pControl->BytesWritten = 0;
        pControl->BytesRead = 0;
        pControl->WriteIndex = 0;
        pControl->ReadIndex = 0;
        QueryPerformanceCounter(&pControl->StartTime);

        // Start reader thread
        readerRunning = true;
        readerThread = std::thread(&SpeedTest::ReaderThreadFunc, this);

        // Start stats thread
        statsThread = std::thread(&SpeedTest::StatsThreadFunc, this);

        // Signal kernel to start
        InterlockedExchange(&pControl->StartFlag, 1);
        std::cout << "[+] Test started! Press SPACE to stop..." << std::endl;
    }

    void StopTest() {
        std::cout << "\n[+] Stopping test..." << std::endl;

        // Stop kernel writing
        InterlockedExchange(&pControl->StartFlag, 0);

        // Stop reader thread
        readerRunning = false;
        if (readerThread.joinable()) {
            readerThread.join();
        }
        if (statsThread.joinable()) {
            statsThread.join();
        }

        // Print final stats
        PrintFinalStats();
    }

    void RequestDriverStop() {
        std::cout << "\n[+] Requesting kernel thread to stop..." << std::endl;
        InterlockedExchange(&pControl->StopRequested, 1);

        // Wait for thread to stop
        for (int i = 0; i < 50; i++) {
            Sleep(100);
            if (!pControl->ThreadRunning) {
                std::cout << "[+] Kernel thread stopped successfully!" << std::endl;
                return;
            }
        }
        std::cout << "[!] Kernel thread didn't stop in time" << std::endl;
    }

    void Cleanup() {
        if (pBase) {
            UnmapViewOfFile(pBase);
            pBase = nullptr;
            pControl = nullptr;
            pBuffer = nullptr;
        }
        if (hSection) {
            CloseHandle(hSection);
            hSection = nullptr;
        }
    }

private:
    void ReaderThreadFunc() {
        PUCHAR readBuffer = new UCHAR[READ_CHUNK_SIZE];
        ULONG bufferSize = pControl->BufferSize;
        bool verifyData = false;  // Set to true to verify data integrity (slower)

        while (readerRunning) {
            LONG writeIdx = pControl->WriteIndex;
            LONG readIdx = pControl->ReadIndex;

            // Calculate available data
            LONG availableData;
            if (writeIdx >= readIdx) {
                availableData = writeIdx - readIdx;
            }
            else {
                availableData = bufferSize - readIdx + writeIdx;
            }

            if (availableData > 0) {
                // Read up to READ_CHUNK_SIZE bytes
                ULONG readSize = min(availableData, READ_CHUNK_SIZE);

                // Handle circular buffer wrap-around
                if (readIdx + readSize > bufferSize) {
                    // Read in two parts
                    ULONG firstPart = bufferSize - readIdx;
                    ULONG secondPart = readSize - firstPart;

                    // Copy first part
                    memcpy(readBuffer, pBuffer + readIdx, firstPart);

                    // Copy second part
                    if (secondPart > 0) {
                        memcpy(readBuffer + firstPart, pBuffer, secondPart);
                    }

                    // Update read index
                    InterlockedExchange(&pControl->ReadIndex, secondPart);
                }
                else {
                    // Simple read without wrap-around
                    memcpy(readBuffer, pBuffer + readIdx, readSize);

                    // Update read index
                    LONG newReadIdx = readIdx + readSize;
                    if (newReadIdx >= bufferSize) {
                        newReadIdx = 0;
                    }
                    InterlockedExchange(&pControl->ReadIndex, newReadIdx);
                }

                // Update bytes read counter
                InterlockedAdd64(&pControl->BytesRead, readSize);

                // Optional: Verify data integrity
                if (verifyData && readSize >= 256) {
                    // Check first 256 bytes of pattern
                    bool valid = true;
                    for (int i = 1; i < 256; i++) {
                        if (readBuffer[i] != (UCHAR)((readBuffer[0] + i) & 0xFF)) {
                            valid = false;
                            break;
                        }
                    }
                    if (!valid) {
                        std::cout << "\n[!] Data verification failed!" << std::endl;
                    }
                }

            }
            else {
                // No data available, yield
                Sleep(0);
            }
        }

        delete[] readBuffer;
    }

    void StatsThreadFunc() {
        auto lastPrintTime = std::chrono::steady_clock::now();
        LONG64 lastBytesWritten = 0;
        LONG64 lastBytesRead = 0;

        while (readerRunning) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - lastPrintTime).count();

            if (elapsed >= 1000) {  // Print stats every second
                LONG64 currentBytesWritten = pControl->BytesWritten;
                LONG64 currentBytesRead = pControl->BytesRead;

                double writeMBps = ((currentBytesWritten - lastBytesWritten) / 1024.0 / 1024.0)
                    * (1000.0 / elapsed);
                double readMBps = ((currentBytesRead - lastBytesRead) / 1024.0 / 1024.0)
                    * (1000.0 / elapsed);

                // Calculate buffer usage
                LONG writeIdx = pControl->WriteIndex;
                LONG readIdx = pControl->ReadIndex;
                LONG bufferUsed;
                if (writeIdx >= readIdx) {
                    bufferUsed = writeIdx - readIdx;
                }
                else {
                    bufferUsed = pControl->BufferSize - readIdx + writeIdx;
                }
                double bufferUsage = (bufferUsed * 100.0) / pControl->BufferSize;

                std::cout << "\r[STATS] Write: " << std::fixed << std::setprecision(2)
                    << writeMBps << " MB/s | Read: " << readMBps
                    << " MB/s | Buffer: " << std::setprecision(1)
                    << bufferUsage << "% | Total: "
                    << (currentBytesWritten / (1024 * 1024)) << " MB written, "
                    << (currentBytesRead / (1024 * 1024)) << " MB read        ";

                lastBytesWritten = currentBytesWritten;
                lastBytesRead = currentBytesRead;
                lastPrintTime = now;
            }

            Sleep(100);
        }
    }

    void PrintFinalStats() {
        std::cout << "\n\n========== FINAL STATISTICS ==========" << std::endl;

        LARGE_INTEGER endTime, freq;
        QueryPerformanceCounter(&endTime);
        QueryPerformanceFrequency(&freq);

        double elapsedSeconds = (endTime.QuadPart - pControl->StartTime.QuadPart)
            / (double)freq.QuadPart;

        LONG64 totalWritten = pControl->BytesWritten;
        LONG64 totalRead = pControl->BytesRead;

        double avgWriteMBps = (totalWritten / 1024.0 / 1024.0) / elapsedSeconds;
        double avgReadMBps = (totalRead / 1024.0 / 1024.0) / elapsedSeconds;

        std::cout << "Test Duration: " << std::fixed << std::setprecision(2)
            << elapsedSeconds << " seconds" << std::endl;
        std::cout << "Total Written: " << (totalWritten / (1024 * 1024)) << " MB" << std::endl;
        std::cout << "Total Read: " << (totalRead / (1024 * 1024)) << " MB" << std::endl;
        std::cout << "Average Write Speed: " << avgWriteMBps << " MB/s" << std::endl;
        std::cout << "Average Read Speed: " << avgReadMBps << " MB/s" << std::endl;
        std::cout << "======================================" << std::endl;
    }
};

int main() {
    std::cout << "========== Full Kernel-to-Usermode Speed Test ==========" << std::endl;
    std::cout << "[*] This test measures actual data transfer speed via shared memory" << std::endl;

    SpeedTest test;

    // Initialize shared memory
    if (!test.Initialize()) {
        std::cout << "[-] Failed to initialize. Run as Administrator!" << std::endl;
        system("pause");
        return 1;
    }

    // Wait for driver
    test.WaitForDriver();

    // Main loop
    bool running = true;
    bool testRunning = false;

    std::cout << "\n[*] Commands:" << std::endl;
    std::cout << "    SPACE - Start/Stop speed test" << std::endl;
    std::cout << "    K     - Kill kernel thread (stop driver completely)" << std::endl;
    std::cout << "    Q     - Quit" << std::endl;
    std::cout << "\nPress SPACE to start the test..." << std::endl;

    while (running) {
        if (_kbhit()) {
            char key = _getch();

            if (key == ' ') {
                if (!testRunning) {
                    test.StartTest();
                    testRunning = true;
                }
                else {
                    test.StopTest();
                    testRunning = false;
                }
            }
            else if (key == 'k' || key == 'K') {
                if (testRunning) {
                    test.StopTest();
                    testRunning = false;
                }
                test.RequestDriverStop();
                std::cout << "[*] Kernel thread stop requested." << std::endl;
                std::cout << "[*] You can now safely unload or reload the driver." << std::endl;
            }
            else if (key == 'q' || key == 'Q') {
                if (testRunning) {
                    test.StopTest();
                    testRunning = false;
                }
                running = false;
            }
        }
        Sleep(50);
    }

    std::cout << "\n[+] Exiting..." << std::endl;
    return 0;
}
