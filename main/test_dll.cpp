#include <windows.h>
#include <string>
#include <fstream>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        // Create a log file on the C: drive to prove execution
        HANDLE hFile = CreateFileA("C:\\injected_test.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            const char* msg = "SUCCESS: The test DLL was successfully injected and DllMain ran inside the target process!\r\n";
            WriteFile(hFile, msg, strlen(msg), &written, NULL);
            CloseHandle(hFile);
        }
        
        // Also pop a message box (might cause issues if thread doesn't pump, but for notepad it's fine)
        // MessageBoxA(NULL, "Injected Successfully!", "Injector Test", MB_OK);
    }
    return TRUE;
}
