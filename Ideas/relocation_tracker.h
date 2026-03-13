#pragma once
#include <windows.h>
#include <vector>
#include <unordered_set>
#include <iostream>

// Relocation tracking for reliability and debugging
namespace RelocationTracker {

struct RelocationEntry {
    DWORD rva;
    WORD type;
    ULONG64 originalValue;
    ULONG64 relocatedValue;
    bool applied;
};

class RelocationMap {
private:
    std::vector<RelocationEntry> entries;
    std::unordered_set<DWORD> relocatedRVAs;
    
public:
    // Parse and store relocations before applying
    bool ParseRelocations(const std::vector<uint8_t>& img, IMAGE_NT_HEADERS64* nt) {
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        
        if (dir.VirtualAddress == 0 || dir.Size == 0) {
            std::cout << "      [Reloc] No relocation directory present" << std::endl;
            return true; // Not an error - RIP-relative code may not need relocs
        }
        
        DWORD offset = 0;
        int blockCount = 0;
        
        while (offset < dir.Size) {
            auto* block = (IMAGE_BASE_RELOCATION*)(img.data() + dir.VirtualAddress + offset);
            
            if (block->SizeOfBlock == 0 || block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION)) {
                std::cerr << "      [Reloc] Invalid block size: " << block->SizeOfBlock << std::endl;
                break;
            }
            
            DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* relocEntries = (WORD*)((BYTE*)block + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < numEntries; i++) {
                WORD type = relocEntries[i] >> 12;
                WORD off = relocEntries[i] & 0xFFF;
                DWORD rva = block->VirtualAddress + off;
                
                // Skip padding entries
                if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }
                
                // Validate RVA bounds
                if (type == IMAGE_REL_BASED_DIR64 && rva + 8 > img.size()) {
                    std::cerr << "      [Reloc] DIR64 reloc out of bounds: RVA 0x" 
                              << std::hex << rva << std::dec << std::endl;
                    return false;
                }
                
                if (type == IMAGE_REL_BASED_HIGHLOW && rva + 4 > img.size()) {
                    std::cerr << "      [Reloc] HIGHLOW reloc out of bounds: RVA 0x" 
                              << std::hex << rva << std::dec << std::endl;
                    return false;
                }
                
                // Store relocation entry
                RelocationEntry entry{};
                entry.rva = rva;
                entry.type = type;
                entry.applied = false;
                
                // Read original value before relocation
                if (type == IMAGE_REL_BASED_DIR64) {
                    entry.originalValue = *(ULONG64*)(img.data() + rva);
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    entry.originalValue = *(DWORD*)(img.data() + rva);
                }
                
                entries.push_back(entry);
            }
            
            blockCount++;
            offset += block->SizeOfBlock;
        }
        
        std::cout << "      [Reloc] Parsed " << entries.size() << " relocations from " 
                  << blockCount << " blocks" << std::endl;
        return true;
    }
    
    // Apply relocations and record resulting values
    bool ApplyRelocations(std::vector<uint8_t>& img, ULONG64 preferredBase, ULONG64 actualBase) {
        LONG64 delta = (LONG64)(actualBase - preferredBase);
        
        if (delta == 0) {
            std::cout << "      [Reloc] Delta is 0, no adjustment needed" << std::endl;
            return true;
        }
        
        std::cout << "      [Reloc] Applying delta: 0x" << std::hex << delta << std::dec 
                  << " to " << entries.size() << " relocations" << std::endl;
        
        size_t successCount = 0;
        size_t dir64Count = 0;
        size_t highlowCount = 0;
        
        for (auto& entry : entries) {
            if (entry.type == IMAGE_REL_BASED_DIR64) {
                ULONG64* pValue = (ULONG64*)(img.data() + entry.rva);
                *pValue += delta;
                entry.relocatedValue = *pValue;
                entry.applied = true;
                relocatedRVAs.insert(entry.rva);
                dir64Count++;
                successCount++;
                
            } else if (entry.type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* pValue = (DWORD*)(img.data() + entry.rva);
                *pValue += (DWORD)delta;
                entry.relocatedValue = *pValue;
                entry.applied = true;
                relocatedRVAs.insert(entry.rva);
                highlowCount++;
                successCount++;
                
            } else {
                std::cerr << "      [Reloc] Unsupported relocation type: " << entry.type 
                          << " at RVA 0x" << std::hex << entry.rva << std::dec << std::endl;
            }
        }
        
        std::cout << "      [Reloc] Applied " << successCount << " relocations ("
                  << "DIR64: " << dir64Count << ", HIGHLOW: " << highlowCount << ")" << std::endl;
        
        return successCount == entries.size();
    }
    
    // Verify relocations were applied as recorded
    bool VerifyRelocations(const std::vector<uint8_t>& img, ULONG64 actualBase) const {
        size_t verifyErrors = 0;
        
        for (const auto& entry : entries) {
            if (!entry.applied) {
                std::cerr << "      [Reloc] Entry at RVA 0x" << std::hex << entry.rva 
                          << " was never applied!" << std::dec << std::endl;
                verifyErrors++;
                continue;
            }
            
            ULONG64 currentValue = 0;
            if (entry.type == IMAGE_REL_BASED_DIR64) {
                currentValue = *(ULONG64*)(img.data() + entry.rva);
            } else if (entry.type == IMAGE_REL_BASED_HIGHLOW) {
                currentValue = *(DWORD*)(img.data() + entry.rva);
            }
            
            if (currentValue != entry.relocatedValue) {
                std::cerr << "      [Reloc] Verification failed at RVA 0x" << std::hex << entry.rva
                          << ": expected 0x" << entry.relocatedValue 
                          << " but found 0x" << currentValue << std::dec << std::endl;
                verifyErrors++;
            }
        }
        
        if (verifyErrors == 0) {
            std::cout << "      [Reloc] All " << entries.size() << " relocations verified successfully" << std::endl;
        }
        
        return verifyErrors == 0;
    }
    
    // Check if an RVA was relocated (useful for debugging)
    bool IsRelocated(DWORD rva) const {
        return relocatedRVAs.find(rva) != relocatedRVAs.end();
    }
    
    size_t GetRelocationCount() const { return entries.size(); }
    
    // Print a detailed relocation summary
    void DumpRelocations() const {
        std::cout << "\n      [Reloc] Detailed Relocation Map:" << std::endl;
        std::cout << "      =================================" << std::endl;
        
        for (size_t i = 0; i < std::min(entries.size(), size_t(20)); i++) {
            const auto& entry = entries[i];
            std::cout << "      [" << i << "] RVA: 0x" << std::hex << entry.rva
                      << " Type: " << entry.type
                      << " Original: 0x" << entry.originalValue
                      << " Relocated: 0x" << entry.relocatedValue
                      << " Applied: " << (entry.applied ? "Yes" : "No") << std::dec << std::endl;
        }
        
        if (entries.size() > 20) {
            std::cout << "      ... (" << (entries.size() - 20) << " more entries)" << std::endl;
        }
    }
};

} // namespace RelocationTracker
