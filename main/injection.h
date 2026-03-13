#pragma once
#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "vmmdll.h"
#include "pe_mapper.h"
#include "shellcode.h"

namespace Injection {

// Find a code cave in a module's executable sections
static ULONG64 findCodeCave(VMM_HANDLE hVMM, DWORD pid, const char* moduleName, DWORD requiredSize) {
    ULONG64 base = VMMDLL_ProcessGetModuleBaseU(hVMM, pid, moduleName);
    if (!base) return 0;

    GuestPEInfo pe;
    if (!pe.read(hVMM, pid, base)) return 0;

    return pe.findCodeCave(hVMM, pid, requiredSize);
}

// Try multiple modules to find a code cave
static ULONG64 findAnyCave(VMM_HANDLE hVMM, DWORD pid, const char* targetExe, DWORD requiredSize) {
    const char* candidates[] = { targetExe, "ntdll.dll", "kernel32.dll", "kernelbase.dll" };
    for (auto mod : candidates) {
        std::cout << "    Trying " << mod << "..." << std::endl;
        ULONG64 cave = findCodeCave(hVMM, pid, mod, requiredSize);
        if (cave) {
            std::cout << "    Found code cave in " << mod << " at 0x"
                      << std::hex << cave << std::dec << std::endl;
            return cave;
        }
    }
    return 0;
}

// Try multiple modules to find a data cave
static ULONG64 findAnyDataCave(VMM_HANDLE hVMM, DWORD pid, const char* targetExe, DWORD requiredSize) {
    const char* candidates[] = { targetExe, "ntdll.dll", "kernel32.dll", "kernelbase.dll" };
    for (auto mod : candidates) {
        std::cout << "    Trying " << mod << "..." << std::endl;
        ULONG64 base = VMMDLL_ProcessGetModuleBaseU(hVMM, pid, mod);
        if (!base) continue;

        GuestPEInfo pe;
        if (!pe.read(hVMM, pid, base)) continue;

        ULONG64 cave = pe.findDataCave(hVMM, pid, requiredSize);
        if (cave) {
            std::cout << "    Found data cave in " << mod << " at 0x"
                      << std::hex << cave << std::dec << std::endl;
            return cave;
        }
    }
    return 0;
}

// State for inline hook installation and restoration
struct InlineHookState {
    ULONG64 targetFuncAddr;      // Address of the OS function we are hooking (e.g., Sleep)
    uint8_t originalBytes[14];   // The original instructions we overwrite
    std::string funcName;
};

// Install an Inline Hook (Absolute 14-byte JMP) at the target address
static bool installInlineHook(VMM_HANDLE hVMM, DWORD pid, ULONG64 targetFuncAddr, ULONG64 shellcodeAddr, InlineHookState& outState) {
    outState.targetFuncAddr = targetFuncAddr;
    
    // Read and save the original 14 bytes so we can restore them later
    if (!VMMDLL_MemRead(hVMM, pid, targetFuncAddr, outState.originalBytes, 14)) {
        std::cerr << "    [-] Failed to read original bytes at 0x" << std::hex << targetFuncAddr << std::dec << std::endl;
        return false;
    }

    // Assembly for a 64-bit absolute jump:
    // FF 25 00 00 00 00        jmp [rip+0]
    // <8-byte address>         (The address to jump to)
    uint8_t jmpStub[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *(ULONG64*)(jmpStub + 6) = shellcodeAddr;

    // Write the JMP instruction over the target function
    if (!VMMDLL_MemWrite(hVMM, pid, targetFuncAddr, jmpStub, 14)) {
        std::cerr << "    [-] Failed to write inline hook at 0x" << std::hex << targetFuncAddr << std::dec << std::endl;
        return false;
    }

    return true;
}

// Restore original bytes to remove the inline hook
static bool restoreInlineHook(VMM_HANDLE hVMM, DWORD pid, InlineHookState& state) {
    if (!VMMDLL_MemWrite(hVMM, pid, state.targetFuncAddr, state.originalBytes, 14)) {
        std::cerr << "    [-] Failed to restore original bytes at 0x" << std::hex << state.targetFuncAddr << std::dec << std::endl;
        return false;
    }
    return true;
}

// Verify a write by reading back and comparing
static bool verifyWrite(VMM_HANDLE hVMM, DWORD pid, ULONG64 addr, const uint8_t* expected, DWORD size) {
    std::vector<uint8_t> readback(size);
    if (!VMMDLL_MemRead(hVMM, pid, addr, readback.data(), size)) {
        std::cerr << "    [VERIFY] Failed to read back at 0x" << std::hex << addr << std::dec << std::endl;
        return false;
    }
    if (memcmp(readback.data(), expected, size) != 0) {
        std::cerr << "    [VERIFY] Mismatch at 0x" << std::hex << addr << std::dec << std::endl;
        std::cerr << "    Expected: ";
        for (DWORD i = 0; i < (size < 16 ? size : 16); i++)
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)expected[i] << " ";
        std::cerr << std::endl << "    Got:      ";
        for (DWORD i = 0; i < (size < 16 ? size : 16); i++)
            std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)readback[i] << " ";
        std::cerr << std::dec << std::endl;
        return false;
    }
    return true;
}

// Check if the target process is still alive
static bool isProcessAlive(VMM_HANDLE hVMM, DWORD pid) {
    DWORD checkPid = 0;
    // Try reading any memory from the process
    uint8_t buf[1];
    return VMMDLL_MemRead(hVMM, pid, VMMDLL_ProcessGetModuleBaseU(hVMM, pid, "ntdll.dll"),
                          buf, 1);
}

// Poll a signal address until it becomes non-zero, with timeout
static ULONG64 waitForSignal(VMM_HANDLE hVMM, DWORD pid, ULONG64 signalAddr, DWORD timeoutMs = 30000) {
    DWORD elapsed = 0;
    ULONG64 value = 0;
    while (elapsed < timeoutMs) {
        if (VMMDLL_MemRead(hVMM, pid, signalAddr, (PBYTE)&value, 8) && value != 0) {
            return value;
        }
        // Periodic status check
        if (elapsed > 0 && elapsed % 5000 == 0) {
            if (!isProcessAlive(hVMM, pid)) {
                std::cerr << "    [!] Target process appears to have died!" << std::endl;
                return 0;
            }
            std::cout << "    Still waiting... (" << elapsed/1000 << "s)" << std::endl;
        }
        Sleep(50);
        elapsed += 50;
    }
    return 0;
}

// Main injection function
static bool injectDll(VMM_HANDLE hVMM, DWORD pid, const char* targetExe, const char* dllPath) {
    // --- Step 1: Load and parse the DLL from host disk ---
    std::cout << "[+] Loading payload DLL from host: " << dllPath << std::endl;
    PEFile pe;
    if (!pe.load(dllPath)) {
        std::cerr << "[-] Failed to load/parse DLL: " << dllPath << std::endl;
        return false;
    }
    std::cout << "    Image size: 0x" << std::hex << pe.imageSize() << std::dec << std::endl;
    std::cout << "    Entry point RVA: 0x" << std::hex << pe.entryPointRVA() << std::dec << std::endl;

    // Hyper-V mapping can aggressively page out unused setup memory during the first 1-2 seconds of process launch.
    // Give the guest VM and hypervisor a brief moment to map the newly launched process working set.
    std::cout << "[+] Delaying 3 seconds to allow guest process physical memory to settle..." << std::endl;
    Sleep(3000);

    // --- Step 2: Find a code cave for shellcode and data cave for signal ---
    std::cout << "[+] Searching for code cave in guest process..." << std::endl;
    ULONG64 caveAddr = findAnyCave(hVMM, pid, targetExe, Shellcode::CODE_CAVE_REQUIRED);
    if (!caveAddr) {
        std::cerr << "[-] No suitable code cave found in any module." << std::endl;
        return false;
    }
    std::cout << "[+] Searching for data cave in guest process for signaling..." << std::endl;
    ULONG64 signalAddr = findAnyDataCave(hVMM, pid, targetExe, 8);
    if (!signalAddr) {
        std::cerr << "[-] No suitable data cave found in any module." << std::endl;
        return false;
    }

    // --- Step 3: Find a function to Inline Hook ---
    std::cout << "[+] Resolving OS function for inline hooking..." << std::endl;
    InlineHookState hookState;
    ULONG64 targetAddr = VMMDLL_ProcessGetProcAddressU(hVMM, pid, "user32.dll", "PeekMessageW");
    if (!targetAddr) {
        std::cerr << "[-] Failed to resolve PeekMessageW in guest user32.dll." << std::endl;
        return false;
    }
    hookState.funcName = "PeekMessageW";
    hookState.targetFuncAddr = targetAddr;
    
    std::cout << "    Target: user32.dll!PeekMessageW @ 0x" << std::hex << targetAddr << std::dec << std::endl;

    // --- Step 4: Resolve VirtualAlloc in the guest ---
    ULONG64 vaVirtualAlloc = VMMDLL_ProcessGetProcAddressU(hVMM, pid, "kernel32.dll", "VirtualAlloc");
    if (!vaVirtualAlloc) {
        std::cerr << "[-] Failed to resolve VirtualAlloc in guest." << std::endl;
        return false;
    }
    std::cout << "    VirtualAlloc @ 0x" << std::hex << vaVirtualAlloc << std::dec << std::endl;

    // --- Step 4b: Map image and resolve imports BEFORE VirtualAlloc shellcode ---
    // We do this now while MemProcFS's module map is still fresh.
    // The cache refreshes after VirtualAlloc will invalidate the module map,
    // causing VMMDLL_ProcessGetProcAddressU to fail for import resolution.
    // Import resolution doesn't depend on the allocation base address — it only
    // looks up function addresses in the guest's loaded DLLs.
    std::cout << "[+] Pre-resolving imports (module map is fresh)..." << std::endl;
    auto image = pe.mapImage();

    if (!pe.resolveImports(image, hVMM, pid, 0)) {
        std::cerr << "[!] Some imports failed to resolve (continuing anyway)." << std::endl;
    }

    // --- Step 4c: Calculate preferred allocation address ---
    // Allocating near existing modules reuses page table entries that MemProcFS
    // can already walk. A distant allocation (different PML4 entry) creates new
    // page table pages whose physical addresses may not be discoverable via DMA.
    ULONG64 preferredAlloc = 0;
    {
        ULONG64 targetBase = VMMDLL_ProcessGetModuleBaseU(hVMM, pid, targetExe);
        if (targetBase) {
            GuestPEInfo targetPE;
            if (targetPE.read(hVMM, pid, targetBase)) {
                ULONG64 moduleEnd = targetBase + targetPE.ntHdr.OptionalHeader.SizeOfImage;
                preferredAlloc = (moduleEnd + 0xFFFF) & ~(ULONG64)0xFFFF;
                std::cout << "    Preferred alloc near module end: 0x" << std::hex
                          << preferredAlloc << std::dec << std::endl;
            }
        }
    }

    // --- Step 5: Write VirtualAlloc shellcode to code cave ---
    std::cout << "[+] Stage 1: Allocating memory in guest..." << std::endl;

    // Zero out the signal
    ULONG64 zero = 0;
    if (!VMMDLL_MemWrite(hVMM, pid, signalAddr, (PBYTE)&zero, 8)) {
        std::cerr << "    [-] Failed to zero signal address." << std::endl;
        return false;
    }

    // Shellcode tries preferredAlloc first, falls back to NULL.
    auto sc1 = Shellcode::VirtualAllocShellcode::build(signalAddr, pe.imageSize(), vaVirtualAlloc, hookState.targetFuncAddr, preferredAlloc);
    
    if (!VMMDLL_MemWrite(hVMM, pid, caveAddr, sc1.data(), (DWORD)sc1.size())) {
        std::cerr << "[-] Failed to write shellcode to code cave." << std::endl;
        return false;
    }

    // Verify shellcode was written
    if (!verifyWrite(hVMM, pid, caveAddr, sc1.data(), (DWORD)sc1.size())) {
        std::cerr << "[-] Shellcode verification failed!" << std::endl;
        return false;
    }

    // --- Step 6: Install Inline Hook ---
    std::cout << "    Installing Inline Hook on " << hookState.funcName << "..." << std::endl;
    if (!installInlineHook(hVMM, pid, hookState.targetFuncAddr, caveAddr, hookState)) {
        std::cerr << "[-] Failed to install Inline hook." << std::endl;
        return false;
    }
    std::cout << "    Hook installed." << std::endl;

    // --- Step 7: Wait for VirtualAlloc to execute ---
    std::cout << "[+] Waiting for shellcode execution (interact with the guest app)..." << std::endl;
    ULONG64 allocBase = waitForSignal(hVMM, pid, signalAddr, 60000);

    // Restore the original bytes immediately so the game doesn't crash when the shellcode jumps back to Sleep
    restoreInlineHook(hVMM, pid, hookState);
    std::cout << "    Original " << hookState.funcName << " bytes restored." << std::endl;

    // Release the spinning shellcode thread so it can safely jump back to the original function
    ULONG64 resumeSignal = 2;
    VMMDLL_MemWrite(hVMM, pid, signalAddr, (PBYTE)&resumeSignal, 8);

    if (!allocBase) {
        std::cerr << "[-] Timeout waiting for VirtualAlloc shellcode." << std::endl;
        // Clean up code cave
        std::vector<uint8_t> zeros(Shellcode::CODE_CAVE_REQUIRED, 0);
        VMMDLL_MemWrite(hVMM, pid, caveAddr, zeros.data(), (DWORD)zeros.size());
        return false;
    }
    std::cout << "[+] Memory allocated in guest at: 0x" << std::hex << allocBase << std::dec << std::endl;

    // Force a complete refresh of the memory translation maps since we just dynamically
    // altered the guest's virtual memory layout from inside a hook.
    VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_ALL, 1);
    VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_FREQ_MEM, 1);
    
    // Give MemProcFS and the guest OS more time to sync the new memory allocations.
    // The shellcode touches every page to force faults, but MemProcFS needs time to
    // discover the new physical pages through page table walks.
    Sleep(1000);
    
    // Refresh again to be completely sure the new pages are mapped in VMM
    VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_ALL, 1);
    Sleep(500);
    VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_ALL, 1);
    
    // --- Step 8: Apply relocations (needs allocBase) and write to guest ---
    std::cout << "[+] Finalizing DLL image..." << std::endl;

    std::cout << "    Applying relocations (delta: 0x" << std::hex
              << (LONG64)(allocBase - pe.preferredBase()) << std::dec << ")..." << std::endl;
    if (!pe.applyRelocations(image, allocBase)) {
        std::cerr << "[-] Failed to apply relocations." << std::endl;
        return false;
    }

    std::cout << "    Writing image to guest..." << std::endl;
    
    // Helper lambda: write a page to guest memory with physical address fallback.
    // Strategy:
    //   1. Try virtual write (fast path, works for already-cached pages)
    //   2. On failure, force cache refresh and retry virtual write
    //   3. On failure, translate VA→PA via VMMDLL_MemVirt2Phys, then write
    //      directly to physical memory using PID=(DWORD)-1
    auto writeToGuest = [&](ULONG64 destAddr, const uint8_t* srcData, DWORD size, const char* label) -> bool {
        // Attempt 1: Direct virtual write (works if pages are already in cache)
        if (VMMDLL_MemWrite(hVMM, pid, destAddr, (PBYTE)srcData, size)) {
            return true;
        }

        // Attempt 2: Refresh everything and retry virtual write
        VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_ALL, 1);
        VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_FREQ_MEM, 1);
        Sleep(100);
        
        // Force fresh page table walk via uncached read
        std::vector<uint8_t> dummy(size);
        DWORD bytesRead = 0;
        VMMDLL_MemReadEx(hVMM, pid, destAddr, dummy.data(), size, &bytesRead,
                         VMMDLL_FLAG_NOCACHE | VMMDLL_FLAG_NOCACHEPUT);
        
        if (VMMDLL_MemWrite(hVMM, pid, destAddr, (PBYTE)srcData, size)) {
            std::cout << "      [OK] " << label << " succeeded after cache refresh" << std::endl;
            return true;
        }

        // Attempt 3: Physical address fallback
        // Translate each 4K page within this chunk to its physical address
        // and write directly to physical memory, bypassing virtual translation.
        std::cout << "      [PHYS] " << label << " virtual write failed, trying physical write..." << std::endl;
        
        for (DWORD pageOff = 0; pageOff < size; pageOff += 0x1000) {
            DWORD pageSize = 0x1000;
            if (pageOff + pageSize > size) pageSize = size - pageOff;
            
            ULONG64 va = destAddr + pageOff;
            ULONG64 pa = 0;
            
            // Try multiple times to resolve the physical address
            bool resolved = false;
            for (int attempt = 0; attempt < 5; attempt++) {
                if (VMMDLL_MemVirt2Phys(hVMM, pid, va, &pa) && pa != 0) {
                    resolved = true;
                    break;
                }
                // Refresh and retry
                VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_ALL, 1);
                Sleep(300 * (attempt + 1));
            }
            
            if (!resolved) {
                std::cerr << "      [-] Cannot resolve VA 0x" << std::hex << va 
                          << " to physical address" << std::dec << std::endl;
                return false;
            }
            
            // Write directly to physical memory (PID = -1)
            if (!VMMDLL_MemWrite(hVMM, (DWORD)-1, pa, (PBYTE)(srcData + pageOff), pageSize)) {
                std::cerr << "      [-] Physical write to PA 0x" << std::hex << pa 
                          << " failed" << std::dec << std::endl;
                return false;
            }
        }
        std::cout << "      [OK] " << label << " succeeded via physical write" << std::endl;
        return true;
    };

    // Write the entire mapped image page-by-page for maximum reliability.
    DWORD totalSize = (DWORD)image.size();
    std::cout << "    Writing 0x" << std::hex << totalSize << std::dec
              << " bytes page-by-page to 0x" << std::hex << allocBase << std::dec << std::endl;

    // Upfront cache refresh
    VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_ALL, 1);
    VMMDLL_ConfigSet(hVMM, VMMDLL_OPT_REFRESH_FREQ_MEM, 1);
    Sleep(200);

    for (DWORD offset = 0; offset < totalSize; offset += 0x1000) {
        DWORD chunkSize = 0x1000;
        if (offset + chunkSize > totalSize) chunkSize = totalSize - offset;

        char label[64];
        snprintf(label, sizeof(label), "page +0x%X", offset);

        if (!writeToGuest(allocBase + offset, image.data() + offset, chunkSize, label)) {
            return false;
        }
    }
    std::cout << "    DLL mapped successfully." << std::endl;

    // --- Step 9: Execute DllMain ---
    if (pe.entryPointRVA() == 0) {
        std::cout << "[+] No entry point, skipping DllMain." << std::endl;
        std::cout << "[+] Injection complete! DLL at: 0x" << std::hex << allocBase << std::dec << std::endl;
        return true;
    }

    std::cout << "[+] Stage 2: Triggering DllMain..." << std::endl;
    ULONG64 entryPoint = allocBase + pe.entryPointRVA();
    std::cout << "    Entry point: 0x" << std::hex << entryPoint << std::dec << std::endl;

    // Zero signal for stage 2
    VMMDLL_MemWrite(hVMM, pid, signalAddr, (PBYTE)&zero, 8);

    auto sc2 = Shellcode::DllMainShellcode::build(signalAddr, allocBase, entryPoint, hookState.targetFuncAddr);

    if (!VMMDLL_MemWrite(hVMM, pid, caveAddr, sc2.data(), (DWORD)sc2.size())) {
        std::cerr << "[-] Failed to write DllMain shellcode." << std::endl;
        return false;
    }

    // Install hook again
    if (!installInlineHook(hVMM, pid, hookState.targetFuncAddr, caveAddr, hookState)) {
        std::cerr << "[-] Failed to install Inline hook for DllMain." << std::endl;
        return false;
    }

    std::cout << "[+] Waiting for DllMain execution..." << std::endl;
    ULONG64 dllMainResult = waitForSignal(hVMM, pid, signalAddr, 60000);

    // Restore hook
    restoreInlineHook(hVMM, pid, hookState);

    // Release the spinning shellcode thread
    ULONG64 resumeSignal2 = 2;
    VMMDLL_MemWrite(hVMM, pid, signalAddr, (PBYTE)&resumeSignal2, 8);
    // Give the thread a moment to jump out of the code cave before zeroing it
    Sleep(50); 
    
    // We intentionally DO NOT clean up the code cave here. 
    // Threads escaping the inline hook might still be executing the final 'jmp rax'
    // instruction. Zeroing the code cave could cause access violations.

    if (!dllMainResult) {
        std::cerr << "[-] Timeout waiting for DllMain. DLL mapped but not initialized." << std::endl;
        std::cout << "[+] DLL mapped at: 0x" << std::hex << allocBase << std::dec << std::endl;
        return false;
    }

    std::cout << "[+] DllMain executed successfully!" << std::endl;
    std::cout << "[+] Injection complete! DLL base: 0x" << std::hex << allocBase << std::dec << std::endl;
    return true;
}

} // namespace Injection
