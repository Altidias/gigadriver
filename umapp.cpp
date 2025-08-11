#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <conio.h>
#include <chrono>

#define SECTION_SIZE (64 * 1024)  // 64KB should be enough for process info

// Commands - must match kernel
typedef enum _READER_COMMAND {
    CMD_NONE = 0,
    CMD_GET_SYSTEM_VERSION = 1,
    CMD_FIND_PROCESS = 2,
    CMD_READ_PROCESS_INFO = 3,
    CMD_LIST_PROCESSES = 4,
    CMD_STOP_THREAD = 99
} READER_COMMAND;

// Must match kernel structure EXACTLY
typedef struct _SHARED_READER_DATA {
    // Control fields
    volatile LONG MagicNumber;
    volatile LONG ThreadRunning;

    // Command interface
    volatile LONG Command;
    volatile LONG CommandReady;
    volatile LONG ResponseReady;
    volatile LONG ProcessingCommand;

    // Command parameters
    CHAR TargetProcessName[256];
    ULONG TargetPid;

    // Response fields
    volatile LONG ResponseStatus;
    volatile LONG ResponseLength;

    // Statistics
    LARGE_INTEGER LastCommandTime;
    volatile LONG CommandsProcessed;

    // Response buffer
    CHAR ResponseBuffer[4096];

} SHARED_READER_DATA, * PSHARED_READER_DATA;

class ProcessReaderClient {
private:
    HANDLE hSection;
    PVOID pBase;
    PSHARED_READER_DATA pShared;
    bool connected;

public:
    ProcessReaderClient() : hSection(nullptr), pBase(nullptr),
        pShared(nullptr), connected(false) {
    }

    ~ProcessReaderClient() {
        Cleanup();
    }

    bool Initialize() {
        std::cout << "[+] Creating shared memory section..." << std::endl;

        // Create file mapping
        hSection = CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            NULL,
            PAGE_READWRITE,
            0,
            SECTION_SIZE,
            L"Global\\ProcessReaderSection"
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

        // Initialize shared structure
        pShared = (PSHARED_READER_DATA)pBase;
        memset(pShared, 0, sizeof(SHARED_READER_DATA));
        pShared->MagicNumber = 0xDEADBEEF;
        pShared->ThreadRunning = 0;
        pShared->Command = CMD_NONE;
        pShared->CommandReady = 0;
        pShared->ResponseReady = 0;
        pShared->ProcessingCommand = 0;
        pShared->CommandsProcessed = 0;

        std::cout << "[+] Shared memory initialized" << std::endl;
        return true;
    }

    void WaitForDriver() {
        std::cout << "\n[*] NOW load the kernel driver with KDMapper!" << std::endl;
        std::cout << "[*] Press any key after driver is loaded..." << std::endl;
        _getch();

        // Check if kernel modified the magic
        if (pShared->MagicNumber == 0xCAFEBABE) {
            std::cout << "[+] Kernel connected successfully!" << std::endl;
            connected = true;
        }
        else {
            std::cout << "[!] Kernel may not have connected properly" << std::endl;
            std::cout << "[!] Magic: 0x" << std::hex << pShared->MagicNumber << std::dec << std::endl;
        }

        // Check if kernel thread is running
        if (pShared->ThreadRunning) {
            std::cout << "[+] Kernel thread is running!" << std::endl;
        }
        else {
            std::cout << "[!] Waiting for kernel thread..." << std::endl;
            for (int i = 0; i < 30; i++) {
                Sleep(100);
                if (pShared->ThreadRunning) {
                    std::cout << "[+] Kernel thread detected!" << std::endl;
                    break;
                }
            }
        }
    }

    bool SendCommand(READER_COMMAND cmd, const char* processName = nullptr, ULONG pid = 0) {
        if (!connected) {
            std::cout << "[-] Not connected to kernel driver!" << std::endl;
            return false;
        }

        // Wait if previous command is still processing
        int waitCount = 0;
        while (pShared->ProcessingCommand && waitCount < 50) {
            Sleep(100);
            waitCount++;
        }

        if (pShared->ProcessingCommand) {
            std::cout << "[-] Previous command still processing!" << std::endl;
            return false;
        }

        // Set command parameters
        pShared->Command = cmd;

        if (processName) {
            strncpy_s(pShared->TargetProcessName, sizeof(pShared->TargetProcessName),
                processName, _TRUNCATE);
        }

        if (pid > 0) {
            pShared->TargetPid = pid;
        }

        // Clear previous response
        pShared->ResponseReady = 0;
        pShared->ResponseLength = 0;

        // Signal command ready
        InterlockedExchange(&pShared->CommandReady, 1);

        std::cout << "[*] Command sent, waiting for response..." << std::endl;

        // Wait for response
        auto startTime = std::chrono::steady_clock::now();
        while (!pShared->ResponseReady) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - startTime).count();

            if (elapsed > 5) {
                std::cout << "[-] Timeout waiting for response!" << std::endl;
                return false;
            }

            Sleep(50);
        }

        // Display response
        if (pShared->ResponseStatus == 0) { // STATUS_SUCCESS
            std::cout << "[+] Response received (Status: SUCCESS, Length: "
                << pShared->ResponseLength << " bytes)" << std::endl;
        }
        else {
            std::cout << "[!] Response received (Status: 0x" << std::hex
                << pShared->ResponseStatus << std::dec
                << ", Length: " << pShared->ResponseLength << " bytes)" << std::endl;
        }

        if (pShared->ResponseLength > 0) {
            std::cout << "\n===== RESPONSE DATA =====\n" << std::endl;
            std::cout << pShared->ResponseBuffer << std::endl;
            std::cout << "\n========================\n" << std::endl;
        }

        return true;
    }

    void GetSystemVersion() {
        std::cout << "\n[*] Getting system version..." << std::endl;
        SendCommand(CMD_GET_SYSTEM_VERSION);
    }

    void FindProcess() {
        std::string processName;
        std::cout << "\n[*] Enter process name to find (e.g., notepad.exe): ";
        std::getline(std::cin, processName);

        if (!processName.empty()) {
            std::cout << "[*] Searching for: " << processName << std::endl;
            SendCommand(CMD_FIND_PROCESS, processName.c_str());
        }
    }

    void GetProcessInfo() {
        ULONG pid;
        std::cout << "\n[*] Enter PID to get info: ";
        std::cin >> pid;
        std::cin.ignore(); // Clear the newline

        if (pid > 0) {
            std::cout << "[*] Getting info for PID: " << pid << std::endl;
            SendCommand(CMD_READ_PROCESS_INFO, nullptr, pid);
        }
    }

    void ListProcesses() {
        std::cout << "\n[*] Listing running processes..." << std::endl;
        SendCommand(CMD_LIST_PROCESSES);
    }

    void ShowStatistics() {
        if (!connected) {
            std::cout << "[-] Not connected!" << std::endl;
            return;
        }

        std::cout << "\n===== STATISTICS =====" << std::endl;
        std::cout << "Commands Processed: " << pShared->CommandsProcessed << std::endl;
        std::cout << "Thread Running: " << (pShared->ThreadRunning ? "Yes" : "No") << std::endl;
        std::cout << "======================" << std::endl;
    }

    void StopKernelThread() {
        std::cout << "\n[*] Sending stop command to kernel thread..." << std::endl;
        SendCommand(CMD_STOP_THREAD);

        // Wait for thread to stop
        for (int i = 0; i < 30; i++) {
            Sleep(100);
            if (!pShared->ThreadRunning) {
                std::cout << "[+] Kernel thread stopped successfully!" << std::endl;
                connected = false;
                return;
            }
        }
        std::cout << "[!] Kernel thread didn't stop in time" << std::endl;
    }

    void Cleanup() {
        if (pBase) {
            UnmapViewOfFile(pBase);
            pBase = nullptr;
            pShared = nullptr;
        }
        if (hSection) {
            CloseHandle(hSection);
            hSection = nullptr;
        }
        connected = false;
    }

    bool IsConnected() const { return connected; }
};

void ShowMenu() {
    std::cout << "\n========== PROCESS READER MENU ==========" << std::endl;
    std::cout << "1. Get System Version" << std::endl;
    std::cout << "2. Find Process by Name" << std::endl;
    std::cout << "3. Get Process Info by PID" << std::endl;
    std::cout << "4. List Running Processes" << std::endl;
    std::cout << "5. Show Statistics" << std::endl;
    std::cout << "S. Stop Kernel Thread" << std::endl;
    std::cout << "Q. Quit" << std::endl;
    std::cout << "==========================================" << std::endl;
    std::cout << "Enter choice: ";
}

int main() {
    std::cout << "========== Kernel Process Reader Client ==========" << std::endl;
    std::cout << "[*] This tool communicates with the kernel driver via shared memory" << std::endl;

    ProcessReaderClient client;

    // Initialize shared memory
    if (!client.Initialize()) {
        std::cout << "[-] Failed to initialize. Run as Administrator!" << std::endl;
        system("pause");
        return 1;
    }

    // Wait for driver
    client.WaitForDriver();

    if (!client.IsConnected()) {
        std::cout << "[-] Failed to connect to kernel driver!" << std::endl;
        std::cout << "[*] Make sure the driver is loaded with KDMapper" << std::endl;
        system("pause");
        return 1;
    }

    // Main menu loop
    bool running = true;
    while (running) {
        ShowMenu();

        char choice;
        std::cin >> choice;
        std::cin.ignore(); // Clear the newline

        switch (choice) {
        case '1':
            client.GetSystemVersion();
            break;

        case '2':
            client.FindProcess();
            break;

        case '3':
            client.GetProcessInfo();
            break;

        case '4':
            client.ListProcesses();
            break;

        case '5':
            client.ShowStatistics();
            break;

        case 's':
        case 'S':
            client.StopKernelThread();
            std::cout << "[*] You can now safely unload the driver" << std::endl;
            break;

        case 'q':
        case 'Q':
            running = false;
            break;

        default:
            std::cout << "[!] Invalid choice!" << std::endl;
            break;
        }

        if (running && choice != '5') {
            std::cout << "\nPress any key to continue..." << std::endl;
            _getch();
        }
    }

    std::cout << "\n[+] Exiting..." << std::endl;
    return 0;
}
