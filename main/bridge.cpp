#include <windows.h>
#include <iostream>
#include <string>
#include "vmmdll.h"
#include "leechcore.h"
#include "injection.h"

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cerr << "Usage: injector_bridge.exe <target_process> <payload.dll>" << std::endl;
        std::cerr << "Example: injector_bridge.exe notepad.exe test_payload.dll" << std::endl;
        return -1;
    }

    const char* targetProcess = argv[1];
    const char* payloadPath = argv[2];

    std::cout << "[+] Initializing MemProcFS via LiveCloudKd (hvmm.sys)..." << std::endl;

    LPCSTR vmmArgv[] = { "", "-device", "hvmm://id=0,m=0" };
    VMM_HANDLE hVMM = VMMDLL_Initialize(3, vmmArgv);
    if (!hVMM) {
        std::cerr << "[-] Failed to initialize VMM. Is hvmm.sys loaded on the Host?" << std::endl;
        std::cerr << "[-] Ensure you are running as Administrator." << std::endl;
        return -1;
    }
    std::cout << "[+] Successfully hooked into Hyper-V Guest Memory!" << std::endl;

    // Find target process
    DWORD pid = 0;
    std::cout << "[+] Searching for " << targetProcess << " inside the Guest VM..." << std::endl;

    for (int attempt = 0; attempt < 120; attempt++) {
        if (VMMDLL_PidGetFromName(hVMM, targetProcess, &pid)) break;
        if (attempt == 0) std::cout << "    Waiting for process to start..." << std::endl;
        Sleep(1000);
    }

    if (pid == 0) {
        std::cerr << "[-] Timeout: " << targetProcess << " not found after 120 seconds." << std::endl;
        VMMDLL_Close(hVMM);
        return -1;
    }
    std::cout << "[+] Found " << targetProcess << " PID: " << pid << std::endl;

    // Inject
    bool success = Injection::injectDll(hVMM, pid, targetProcess, payloadPath);

    std::cout << "[+] Shutting down VMM..." << std::endl;
    VMMDLL_Close(hVMM);
    return success ? 0 : -1;
}
