#pragma once
#include <windows.h>
#include <cstdint>

namespace HookShellcode {

// Full-context preserving hook shellcode inspired by Ring-1
// This saves ALL registers including SIMD/FPU state before calling detour
constexpr uint8_t FullContextStub[] = {
    // Push all GPRs
    0x50,                               // push rax
    0x51,                               // push rcx
    0x52,                               // push rdx
    0x53,                               // push rbx
    0x55,                               // push rbp
    0x56,                               // push rsi
    0x57,                               // push rdi
    0x41, 0x50,                         // push r8
    0x41, 0x51,                         // push r9
    0x41, 0x52,                         // push r10
    0x41, 0x53,                         // push r11
    0x41, 0x54,                         // push r12
    0x41, 0x55,                         // push r13
    0x41, 0x56,                         // push r14
    0x41, 0x57,                         // push r15
    0x9C,                               // pushfq (save RFLAGS)
    
    // Align stack and allocate space for FPU/SSE state (512 bytes)
    0x48, 0x89, 0xE3,                   // mov rbx, rsp (save frame pointer)
    0x48, 0x83, 0xE4, 0xF0,             // and rsp, 0xFFFFFFFFFFFFFFF0h (align to 16 bytes)
    0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00, // sub rsp, 200h (512 bytes for fxsave)
    
    // Save FPU/SSE state
    0x0F, 0xAE, 0x04, 0x24,             // fxsave [rsp]
    
    // Prepare arguments (context pointer in RCX)
    0x48, 0x8D, 0x8B, 0x10, 0x02, 0x00, 0x00, // lea rcx, [rbx+210h] (pointer to saved context)
    
    // Reserve shadow space for x64 calling convention
    0x48, 0x83, 0xEC, 0x20,             // sub rsp, 20h
    
    // Call detour function (address will be patched at 0x4A offset)
    0x48, 0xB8,                         // mov rax, <detour_address>
    0xBE, 0xEE, 0x01, 0x23, 0xFF, 0xED, 0x38, 0x1E, // MAGIC: 0x1E38EDFF2301EEBC (to be replaced)
    0xFF, 0xD0,                         // call rax
    
    // Clean up shadow space
    0x48, 0x83, 0xC4, 0x20,             // add rsp, 20h
    
    // Check return value - if 0, skip original function
    0x85, 0xC0,                         // test eax, eax
    0x74, 0x26,                         // jz skip_original (offset adjusted below)
    
    // Restore FPU/SSE state
    0x0F, 0xAE, 0x0C, 0x24,             // fxrstor [rsp]
    
    // Restore stack pointer
    0x48, 0x89, 0xDC,                   // mov rsp, rbx
    
    // Restore RFLAGS and GPRs
    0x9D,                               // popfq
    0x41, 0x5F,                         // pop r15
    0x41, 0x5E,                         // pop r14
    0x41, 0x5D,                         // pop r13
    0x41, 0x5C,                         // pop r12
    0x41, 0x5B,                         // pop r11
    0x41, 0x5A,                         // pop r10
    0x41, 0x59,                         // pop r9
    0x41, 0x58,                         // pop r8
    0x5F,                               // pop rdi
    0x5E,                               // pop rsi
    0x5D,                               // pop rbp
    0x5B,                               // pop rbx
    0x5A,                               // pop rdx
    0x59,                               // pop rcx
    0x58,                               // pop rax
    
    // Jump to relocated original instructions (address will be patched)
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp [rip+0]
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // trampoline address (8 bytes)
    
    // skip_original label (if detour returns 0)
    0x0F, 0xAE, 0x0C, 0x24,             // fxrstor [rsp]
    0x48, 0x89, 0xDC,                   // mov rsp, rbx
    0x9D,                               // popfq
    0x41, 0x5F,                         // pop r15
    0x41, 0x5E,                         // pop r14
    0x41, 0x5D,                         // pop r13
    0x41, 0x5C,                         // pop r12
    0x41, 0x5B,                         // pop r11
    0x41, 0x5A,                         // pop r10
    0x41, 0x59,                         // pop r9
    0x41, 0x58,                         // pop r8
    0x5F,                               // pop rdi
    0x5E,                               // pop rsi
    0x5D,                               // pop rbp
    0x5B,                               // pop rbx
    0x5A,                               // pop rdx
    0x59,                               // pop rcx
    0x58,                               // pop rax
    0xC3                                // ret (skip original, return to caller)
};

constexpr size_t DETOUR_ADDRESS_OFFSET = 0x4A;   // Offset where detour address is patched
constexpr size_t TRAMPOLINE_ADDRESS_OFFSET = 0x9A; // Offset where trampoline address is patched
constexpr uint64_t MAGIC_VALUE = 0x1E38EDFF2301EEBCULL;

// Saved context structure (matches stack layout in shellcode)
struct SavedContext {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t rflags;
    uint8_t fpu_state[512];  // FXSAVE area
};

// Install a full-context hook with Ring-1 style preservation
inline bool InstallFullContextHook(
    VMM_HANDLE hVMM,
    DWORD pid,
    ULONG64 targetAddress,
    ULONG64 detourAddress,
    uint8_t* outOriginalBytes,
    size_t originalBytesSize)
{
    // Allocate shellcode buffer
    std::vector<uint8_t> shellcode(FullContextStub, FullContextStub + sizeof(FullContextStub));
    
    // Patch detour address in shellcode
    *reinterpret_cast<uint64_t*>(&shellcode[DETOUR_ADDRESS_OFFSET]) = detourAddress;
    
    // Read original bytes from target
    if (!VMMDLL_MemRead(hVMM, pid, targetAddress, outOriginalBytes, originalBytesSize)) {
        return false;
    }

    return true;
}

// Calculate instruction length for proper relocation (simplified)
inline int GetInstructionLength(const uint8_t* code) {
    // This is a simplified version - in production use a proper disassembler like Zydis
    // Ring-1 uses sophisticated instruction relocation
    
    // Common x64 instruction patterns
    if (code[0] == 0x48 && (code[1] >= 0x83 && code[1] <= 0x8B)) {
        return 3; // mov, add, sub with REX.W
    }
    if (code[0] == 0xFF && code[1] == 0x25) {
        return 6; // jmp [rip+disp32]
    }
    if (code[0] == 0xE8 || code[0] == 0xE9) {
        return 5; // call/jmp rel32
    }
    
    return 1; // Default (UNSAFE - use proper disassembler!)
}

}
