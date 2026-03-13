#pragma once
#include <windows.h>
#include <vector>
#include <string>
#include <fstream>
#include <cstring>
#include "vmmdll.h"

// Reads a DLL from host disk and provides PE structure access
struct PEFile {
    std::vector<uint8_t> raw;
    IMAGE_DOS_HEADER* dos = nullptr;
    IMAGE_NT_HEADERS64* nt = nullptr;
    IMAGE_SECTION_HEADER* sections = nullptr;

    bool load(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file) return false;
        size_t sz = (size_t)file.tellg();
        if (sz < sizeof(IMAGE_DOS_HEADER)) return false;
        file.seekg(0);
        raw.resize(sz);
        file.read((char*)raw.data(), sz);
        if (!file) return false;

        dos = (IMAGE_DOS_HEADER*)raw.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sz) return false;

        nt = (IMAGE_NT_HEADERS64*)(raw.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;

        sections = IMAGE_FIRST_SECTION(nt);
        return true;
    }

    DWORD imageSize() const { return nt->OptionalHeader.SizeOfImage; }
    DWORD entryPointRVA() const { return nt->OptionalHeader.AddressOfEntryPoint; }
    ULONG64 preferredBase() const { return nt->OptionalHeader.ImageBase; }
    DWORD numSections() const { return nt->FileHeader.NumberOfSections; }
    DWORD sectionAlignment() const { return nt->OptionalHeader.SectionAlignment; }
    DWORD fileAlignment() const { return nt->OptionalHeader.FileAlignment; }

    // Map the PE into a flat image buffer (as it would appear in memory)
    std::vector<uint8_t> mapImage() const {
        std::vector<uint8_t> img(imageSize(), 0);
        // Copy headers
        DWORD hdrsz = nt->OptionalHeader.SizeOfHeaders;
        if (hdrsz > raw.size()) hdrsz = (DWORD)raw.size();
        memcpy(img.data(), raw.data(), hdrsz);
        // Copy sections
        for (DWORD i = 0; i < numSections(); i++) {
            DWORD rawSz = sections[i].SizeOfRawData;
            DWORD rawPtr = sections[i].PointerToRawData;
            DWORD va = sections[i].VirtualAddress;
            if (rawPtr + rawSz > raw.size()) rawSz = (DWORD)(raw.size() - rawPtr);
            if (va + rawSz > img.size()) continue;
            if (rawSz > 0 && rawPtr > 0)
                memcpy(img.data() + va, raw.data() + rawPtr, rawSz);
        }
        return img;
    }

    // Apply base relocations to a mapped image buffer
    bool applyRelocations(std::vector<uint8_t>& img, ULONG64 actualBase) const {
        LONG64 delta = (LONG64)(actualBase - preferredBase());
        if (delta == 0) return true;

        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (dir.VirtualAddress == 0 || dir.Size == 0) return true;

        DWORD offset = 0;
        int blockCount = 0;
        
        while (offset < dir.Size) {
            auto* block = (IMAGE_BASE_RELOCATION*)(img.data() + dir.VirtualAddress + offset);
            
            if (block->SizeOfBlock == 0) {
                std::cerr << "      [?] Stopping relocation loop: Hit a block with SizeOfBlock == 0 at offset " 
                          << std::dec << offset << std::endl;
                break;
            }
            
            DWORD numEntries = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* entries = (WORD*)((BYTE*)block + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < numEntries; i++) {
                WORD type = entries[i] >> 12;
                WORD off = entries[i] & 0xFFF;
                DWORD rva = block->VirtualAddress + off;
                
                if (type == IMAGE_REL_BASED_DIR64) {
                    if (rva + 8 > img.size()) {
                        std::cerr << "      [-] Reloc out of bounds! RVA: 0x" << std::hex << rva << std::dec << std::endl;
                        return false;
                    }
                    *(ULONG64*)(img.data() + rva) += delta;
                } else if (type == IMAGE_REL_BASED_HIGHLOW) {
                    if (rva + 4 > img.size()) {
                        std::cerr << "      [-] Reloc out of bounds! RVA: 0x" << std::hex << rva << std::dec << std::endl;
                        return false;
                    }
                    *(DWORD*)(img.data() + rva) += (DWORD)delta;
                } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    // padding, skip
                }
            }
            
            offset += block->SizeOfBlock;
            blockCount++;
        }
        
        return true;
    }

    // Resolve imports by reading function addresses from the guest VM
    bool resolveImports(std::vector<uint8_t>& img, VMM_HANDLE hVMM, DWORD pid, ULONG64 actualBase) const {
        auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (dir.VirtualAddress == 0 || dir.Size == 0) return true;

        auto* desc = (IMAGE_IMPORT_DESCRIPTOR*)(img.data() + dir.VirtualAddress);
        while (desc->Name != 0) {
            const char* modName = (const char*)(img.data() + desc->Name);
            
            char modNameLower[256] = {0};
            for (int i = 0; modName[i] && i < 255; i++) {
                modNameLower[i] = (modName[i] >= 'A' && modName[i] <= 'Z') ? (modName[i] + 32) : modName[i];
            }

            DWORD thunkRVA = desc->FirstThunk;
            DWORD origThunkRVA = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;

            while (true) {
                IMAGE_THUNK_DATA64* origThunk = (IMAGE_THUNK_DATA64*)(img.data() + origThunkRVA);
                IMAGE_THUNK_DATA64* thunk = (IMAGE_THUNK_DATA64*)(img.data() + thunkRVA);

                if (origThunk->u1.AddressOfData == 0) break;

                ULONG64 funcAddr = 0;
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                    // Ordinal import - not supported in this POC
                    std::cerr << "    [!] Ordinal import from " << modName << " not supported" << std::endl;
                } else {
                    auto* hint = (IMAGE_IMPORT_BY_NAME*)(img.data() + (DWORD)(origThunk->u1.AddressOfData));
                    funcAddr = VMMDLL_ProcessGetProcAddressU(hVMM, pid, modNameLower, hint->Name);
                    if (funcAddr == 0) {
                        funcAddr = VMMDLL_ProcessGetProcAddressU(hVMM, pid, modName, hint->Name);
                    }
                    if (funcAddr == 0) {
                        std::cerr << "    [!] Failed to resolve: " << modName << "!" << hint->Name << std::endl;
                    }
                }

                thunk->u1.Function = funcAddr;
                origThunkRVA += sizeof(IMAGE_THUNK_DATA64);
                thunkRVA += sizeof(IMAGE_THUNK_DATA64);
            }
            desc++;
        }
        return true;
    }
};

// Read PE section headers from a module loaded in the guest VM
struct GuestPEInfo {
    ULONG64 base;
    IMAGE_DOS_HEADER dosHdr;
    IMAGE_NT_HEADERS64 ntHdr;
    std::vector<IMAGE_SECTION_HEADER> sections;

    bool read(VMM_HANDLE hVMM, DWORD pid, ULONG64 moduleBase) {
        base = moduleBase;
        if (!VMMDLL_MemRead(hVMM, pid, base, (PBYTE)&dosHdr, sizeof(dosHdr))) return false;
        if (dosHdr.e_magic != IMAGE_DOS_SIGNATURE) return false;

        if (!VMMDLL_MemRead(hVMM, pid, base + dosHdr.e_lfanew, (PBYTE)&ntHdr, sizeof(ntHdr))) return false;
        if (ntHdr.Signature != IMAGE_NT_SIGNATURE) return false;

        DWORD numSec = ntHdr.FileHeader.NumberOfSections;
        sections.resize(numSec);
        ULONG64 secAddr = base + dosHdr.e_lfanew + sizeof(IMAGE_NT_HEADERS64);
        if (!VMMDLL_MemRead(hVMM, pid, secAddr, (PBYTE)sections.data(),
                            numSec * sizeof(IMAGE_SECTION_HEADER))) return false;
        return true;
    }

    ULONG64 findCodeCave(VMM_HANDLE hVMM, DWORD pid, DWORD requiredSize) const {
        for (const auto& sec : sections) {
            char name[9] = {0};
            memcpy(name, sec.Name, 8);
            if (!(sec.Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;

            DWORD virtSz = sec.Misc.VirtualSize;
            DWORD rawSz = sec.SizeOfRawData;
            DWORD alignedSz = (virtSz > 0) ? 
                              ((virtSz + ntHdr.OptionalHeader.SectionAlignment - 1) & ~(ntHdr.OptionalHeader.SectionAlignment - 1)) :
                              ((rawSz + ntHdr.OptionalHeader.SectionAlignment - 1) & ~(ntHdr.OptionalHeader.SectionAlignment - 1));

            DWORD searchSize = alignedSz;
            if (searchSize == 0) continue;

            std::vector<uint8_t> buffer(searchSize, 0xFF);
            for (DWORD offset = 0; offset < searchSize; offset += 0x1000) {
                DWORD chunk = 0x1000;
                if (offset + chunk > searchSize) chunk = searchSize - offset;
                VMMDLL_MemRead(hVMM, pid, base + sec.VirtualAddress + offset, buffer.data() + offset, chunk);
            }

            DWORD consecutive = 0;
            DWORD matchOffset = 0;
            for (DWORD i = 0; i < searchSize; i++) {
                if (buffer[i] == 0x00 || buffer[i] == 0xCC) {
                    if (consecutive == 0) matchOffset = i;
                    consecutive++;
                    
                    if (consecutive >= requiredSize + 16) {
                        ULONG64 caveAddr = base + sec.VirtualAddress + matchOffset;
                        ULONG64 alignedCave = (caveAddr + 15) & ~15ULL;
                        if (alignedCave + requiredSize <= base + sec.VirtualAddress + searchSize) {
                            uint8_t testByte = buffer[matchOffset]; // Write back the same byte
                            if (VMMDLL_MemWrite(hVMM, pid, alignedCave, &testByte, 1)) {
                                return alignedCave;
                            }
                            // If write failed, reset and keep searching
                            consecutive = 0;
                        }
                    }
                } else {
                    consecutive = 0;
                }
            }
        }
        return 0;
    }

    ULONG64 findDataCave(VMM_HANDLE hVMM, DWORD pid, DWORD requiredSize) const {
        for (const auto& sec : sections) {
            if (!(sec.Characteristics & IMAGE_SCN_MEM_WRITE)) continue;

            DWORD virtSz = sec.Misc.VirtualSize;
            DWORD rawSz = sec.SizeOfRawData;
            DWORD alignedSz = (virtSz > 0) ? 
                              ((virtSz + ntHdr.OptionalHeader.SectionAlignment - 1) & ~(ntHdr.OptionalHeader.SectionAlignment - 1)) :
                              ((rawSz + ntHdr.OptionalHeader.SectionAlignment - 1) & ~(ntHdr.OptionalHeader.SectionAlignment - 1));

            DWORD searchSize = alignedSz;
            if (searchSize == 0) continue;

            std::vector<uint8_t> buffer(searchSize, 0xFF);
            for (DWORD offset = 0; offset < searchSize; offset += 0x1000) {
                DWORD chunk = 0x1000;
                if (offset + chunk > searchSize) chunk = searchSize - offset;
                VMMDLL_MemRead(hVMM, pid, base + sec.VirtualAddress + offset, buffer.data() + offset, chunk);
            }

            DWORD consecutive = 0;
            DWORD matchOffset = 0;
            for (DWORD i = 0; i < searchSize; i++) {
                if (buffer[i] == 0x00) {
                    if (consecutive == 0) matchOffset = i;
                    consecutive++;
                    
                    if (consecutive >= requiredSize + 8) {
                        ULONG64 caveAddr = base + sec.VirtualAddress + matchOffset;
                        ULONG64 alignedCave = (caveAddr + 7) & ~7ULL;
                        if (alignedCave + requiredSize <= base + sec.VirtualAddress + searchSize) {
                            return alignedCave;
                        }
                    }
                } else {
                    consecutive = 0;
                }
            }
        }
        return 0;
    }
};
