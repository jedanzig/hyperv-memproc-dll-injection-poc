#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
#include "vmmdll.h"

namespace CodeCave {

// Multi-module code cave search
struct CaveInfo {
    ULONG64 address;
    DWORD size;
    std::string moduleName;
    std::string sectionName;
    bool executable;
    bool writable;
};

// Search for code caves across candidate modules
class CaveFinder {
private:
    std::vector<CaveInfo>FoundCaves;
    VMM_HANDLE hVMM;
    DWORD pid;
    
public:
    CaveFinder(VMM_HANDLE vm, DWORD processId) : hVMM(vm), pid(processId) {}
    
    // Find executable caves suitable for shellcode placement
    bool FindExecutableCaves(const std::vector<const char*>& moduleNames, DWORD minSize) {
        std::cout << "[CaveFinder] Searching for executable caves (min size: " << minSize << ")" << std::endl;
        
        for (const char* modName : moduleNames) {
            ULONG64 moduleBase = VMMDLL_ProcessGetModuleBaseU(hVMM, pid, modName);
            if (!moduleBase) {
                std::cout << "  [-] Module '" << modName << "' not found, skipping" << std::endl;
                continue;
            }
            
            std::cout << "  [+] Scanning module: " << modName << " at 0x" 
                      << std::hex << moduleBase << std::dec << std::endl;
            
            // Read module headers
            uint8_t peHeaders[0x1000];
            if (!VMMDLL_MemRead(hVMM, pid, moduleBase, peHeaders, sizeof(peHeaders))) {
                continue;
            }
            
            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)peHeaders;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            
            IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(peHeaders + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) continue;
            
            IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION(nt);
            DWORD numSections = nt->FileHeader.NumberOfSections;
            
            // Scan executable sections for runs of padding bytes.
            for (DWORD i = 0; i < numSections; i++) {
                IMAGE_SECTION_HEADER* sect = &sections[i];
                
                // Only check executable sections
                if (!(sect->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                    continue;
                }
                
                ULONG64 sectionStart = moduleBase + sect->VirtualAddress;
                DWORD sectionSize = sect->Misc.VirtualSize;
                
                std::cout << "    [*] Scanning section: " << std::string((char*)sect->Name, 8) 
                          << " (RVA: 0x" << std::hex << sect->VirtualAddress 
                          << ", Size: 0x" << sectionSize << std::dec << ")" << std::endl;
                
                // Read section data in chunks
                const DWORD CHUNK_SIZE = 0x10000; // 64KB chunks
                std::vector<uint8_t> buffer(CHUNK_SIZE);
                
                for (DWORD offset = 0; offset < sectionSize; offset += CHUNK_SIZE) {
                    DWORD readSize = min(CHUNK_SIZE, sectionSize - offset);
                    if (!VMMDLL_MemRead(hVMM, pid, sectionStart + offset, buffer.data(), readSize)) {
                        continue;
                    }
                    
                    // Find runs of null bytes (potential code caves)
                    DWORD runStart = 0;
                    DWORD runLength = 0;
                    
                    for (DWORD j = 0; j < readSize; j++) {
                        if (buffer[j] == 0x00 || buffer[j] == 0xCC || buffer[j] == 0x90) {
                            if (runLength == 0) {
                                runStart = j;
                            }
                            runLength++;
                        } else {
                            if (runLength >= minSize) {
                                CaveInfo cave{};
                                cave.address = sectionStart + offset + runStart;
                                cave.size = runLength;
                                cave.moduleName = modName;
                                cave.sectionName = std::string((char*)sect->Name, 8);
                                cave.executable = true;
                                cave.writable = (sect->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                                
                                FoundCaves.push_back(cave);
                                
                                std::cout << "      [FOUND] Cave at 0x" << std::hex << cave.address 
                                          << " (size: 0x" << cave.size << ")" << std::dec << std::endl;
                            }
                            runLength = 0;
                        }
                    }
                    
                    // Check final run
                    if (runLength >= minSize) {
                        CaveInfo cave{};
                        cave.address = sectionStart + offset + runStart;
                        cave.size = runLength;
                        cave.moduleName = modName;
                        cave.sectionName = std::string((char*)sect->Name, 8);
                        cave.executable = true;
                        cave.writable = (sect->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;
                        
                        FoundCaves.push_back(cave);
                        
                        std::cout << "      [FOUND] Cave at 0x" << std::hex << cave.address 
                                  << " (size: 0x" << cave.size << ")" << std::dec << std::endl;
                    }
                }
            }
        }
        
        std::cout << "[CaveFinder] Found " << FoundCaves.size() << " executable caves" << std::endl;
        return !FoundCaves.empty();
    }
    
    // Select a preferred cave (ntdll -> kernel32 -> kernelbase -> fallback)
    CaveInfo* GetBestCave(DWORD requiredSize) {
        // Priority order for stable, frequently loaded modules.
        const char* priorities[] = { "ntdll.dll", "kernel32.dll", "kernelbase.dll" };
        
        for (const char* preferredModule : priorities) {
            for (auto& cave : FoundCaves) {
                if (cave.size >= requiredSize && cave.executable) {
                    // Case-insensitive comparison
                    std::string caveMod = cave.moduleName;
                    std::transform(caveMod.begin(), caveMod.end(), caveMod.begin(), ::tolower);
                    
                    std::string pref = preferredModule;
                    std::transform(pref.begin(), pref.end(), pref.begin(), ::tolower);
                    
                    if (caveMod == pref) {
                        std::cout << "[CaveFinder] Selected cave in " << cave.moduleName 
                                  << " at 0x" << std::hex << cave.address << std::dec << std::endl;
                        return &cave;
                    }
                }
            }
        }
        
        // Fallback: any cave that fits
        for (auto& cave : FoundCaves) {
            if (cave.size >= requiredSize && cave.executable) {
                std::cout << "[CaveFinder] Selected fallback cave in " << cave.moduleName 
                          << " at 0x" << std::hex << cave.address << std::dec << std::endl;
                return &cave;
            }
        }
        
        std::cerr << "[CaveFinder] No suitable cave found for size " << requiredSize << std::endl;
        return nullptr;
    }
    
    // Print all discovered caves
    void PrintAllCaves() const {
        std::cout << "\n[CaveFinder] All Found Caves:" << std::endl;
        std::cout << "=============================" << std::endl;
        
        for (size_t i = 0; i < FoundCaves.size(); i++) {
            const auto& cave = FoundCaves[i];
            std::cout << "[" << i << "] " << cave.moduleName << "!" << cave.sectionName
                      << " @ 0x" << std::hex << cave.address 
                      << " (size: 0x" << cave.size << ")"
                      << " [" << (cave.executable ? "X" : "-")
                      << (cave.writable ? "W" : "-") << "]" << std::dec << std::endl;
        }
    }
    
    // Verify that a cave still contains mostly padding bytes
    bool VerifyCave(const CaveInfo& cave) const {
        std::vector<uint8_t> buffer(cave.size);
        if (!VMMDLL_MemRead(hVMM, pid, cave.address, buffer.data(), cave.size)) {
            return false;
        }
        
        // Check if still mostly null/padding bytes
        size_t nullCount = 0;
        for (uint8_t byte : buffer) {
            if (byte == 0x00 || byte == 0xCC || byte == 0x90) {
                nullCount++;
            }
        }
        
        // At least 80% should still be padding
        return (nullCount * 100 / cave.size) >= 80;
    }
    
    size_t GetCaveCount() const { return FoundCaves.size(); }
    
    const std::vector<CaveInfo>& GetAllCaves() const { return FoundCaves; }
};

} 
