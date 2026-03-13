#pragma once
#include <windows.h>
#include <cstdint>
#include <vector>
#include "vmmdll.h"

namespace HookShellcode {

// Full-context preserving hook shellcode inspired by Ring-1
// This saves ALL registers including SIMD/FPU state before calling detour.
//
// Offset map (verified by byte count):
//   0x00  push all GPRs + pushfq
//   0x18  stack align + fxsave
//   0x35  mov rax, imm64       <- DETOUR_ADDRESS_OFFSET = 0x37 (imm starts after 2-byte opcode)
//   0x3F  call rax
//   0x47  jz skip_original     <- rel8 offset = 0x2D (targets 0x76)
//   0x49  fxrstor + restore GPRs
//   0x68  jmp [rip+0]          <- TRAMPOLINE_ADDRESS_OFFSET = 0x6E (8-byte slot after 6-byte opcode)
//   0x76  skip_original: fxrstor + restore GPRs + ret
//   Total: 0x96 bytes
constexpr uint8_t FullContextStub[] = {
    // Push all GPRs
    0x50,                               // [00] push rax
    0x51,                               // [01] push rcx
    0x52,                               // [02] push rdx
    0x53,                               // [03] push rbx
    0x55,                               // [04] push rbp
    0x56,                               // [05] push rsi
    0x57,                               // [06] push rdi
    0x41, 0x50,                         // [07] push r8
    0x41, 0x51,                         // [09] push r9
    0x41, 0x52,                         // [0B] push r10
    0x41, 0x53,                         // [0D] push r11
    0x41, 0x54,                         // [0F] push r12
    0x41, 0x55,                         // [11] push r13
    0x41, 0x56,                         // [13] push r14
    0x41, 0x57,                         // [15] push r15
    0x9C,                               // [17] pushfq (save RFLAGS)

    // Align stack and allocate space for FPU/SSE state (512 bytes)
    0x48, 0x89, 0xE3,                   // [18] mov rbx, rsp (save frame pointer)
    0x48, 0x83, 0xE4, 0xF0,             // [1B] and rsp, 0xFFFFFFFFFFFFFFF0h (align to 16 bytes)
    0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00, // [1F] sub rsp, 200h (512 bytes for fxsave)

    // Save FPU/SSE state
    0x0F, 0xAE, 0x04, 0x24,             // [26] fxsave [rsp]

    // Prepare arguments (context pointer in RCX)
    0x48, 0x8D, 0x8B, 0x10, 0x02, 0x00, 0x00, // [2A] lea rcx, [rbx+210h] (pointer to saved context)

    // Reserve shadow space for x64 calling convention
    0x48, 0x83, 0xEC, 0x20,             // [31] sub rsp, 20h

    // Call detour function
    0x48, 0xB8,                         // [35] mov rax, imm64  (opcode; imm at 0x37 = DETOUR_ADDRESS_OFFSET)
    0xBE, 0xEE, 0x01, 0x23, 0xFF, 0xED, 0x38, 0x1E, // [37] placeholder (MAGIC_VALUE, patched at runtime)
    0xFF, 0xD0,                         // [3F] call rax

    // Clean up shadow space
    0x48, 0x83, 0xC4, 0x20,             // [41] add rsp, 20h

    // Check return value — if 0, skip to skip_original (0x76); offset = 0x76 - 0x49 = 0x2D
    0x85, 0xC0,                         // [45] test eax, eax
    0x74, 0x2D,                         // [47] jz skip_original

    // --- Run original path ---
    // Restore FPU/SSE state
    0x0F, 0xAE, 0x0C, 0x24,             // [49] fxrstor [rsp]

    // Restore stack pointer
    0x48, 0x89, 0xDC,                   // [4D] mov rsp, rbx

    // Restore RFLAGS and GPRs
    0x9D,                               // [50] popfq
    0x41, 0x5F,                         // [51] pop r15
    0x41, 0x5E,                         // [53] pop r14
    0x41, 0x5D,                         // [55] pop r13
    0x41, 0x5C,                         // [57] pop r12
    0x41, 0x5B,                         // [59] pop r11
    0x41, 0x5A,                         // [5B] pop r10
    0x41, 0x59,                         // [5D] pop r9
    0x41, 0x58,                         // [5F] pop r8
    0x5F,                               // [61] pop rdi
    0x5E,                               // [62] pop rsi
    0x5D,                               // [63] pop rbp
    0x5B,                               // [64] pop rbx
    0x5A,                               // [65] pop rdx
    0x59,                               // [66] pop rcx
    0x58,                               // [67] pop rax

    // Jump to relocated original instructions (trampoline)
    0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // [68] jmp [rip+0]  (6-byte opcode)
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, // [6E] trampoline address (TRAMPOLINE_ADDRESS_OFFSET)

    // --- skip_original label [76]: detour returned 0, skip original function ---
    0x0F, 0xAE, 0x0C, 0x24,             // [76] fxrstor [rsp]
    0x48, 0x89, 0xDC,                   // [7A] mov rsp, rbx
    0x9D,                               // [7D] popfq
    0x41, 0x5F,                         // [7E] pop r15
    0x41, 0x5E,                         // [80] pop r14
    0x41, 0x5D,                         // [82] pop r13
    0x41, 0x5C,                         // [84] pop r12
    0x41, 0x5B,                         // [86] pop r11
    0x41, 0x5A,                         // [88] pop r10
    0x41, 0x59,                         // [8A] pop r9
    0x41, 0x58,                         // [8C] pop r8
    0x5F,                               // [8E] pop rdi
    0x5E,                               // [8F] pop rsi
    0x5D,                               // [90] pop rbp
    0x5B,                               // [91] pop rbx
    0x5A,                               // [92] pop rdx
    0x59,                               // [93] pop rcx
    0x58,                               // [94] pop rax
    0xC3                                // [95] ret (return to caller, original skipped)
};  // Total: 0x96 = 150 bytes

// Verified offsets (computed from byte count above)
constexpr size_t DETOUR_ADDRESS_OFFSET    = 0x37;  // 8-byte imm in: mov rax, imm64
constexpr size_t TRAMPOLINE_ADDRESS_OFFSET = 0x6E;  // 8-byte slot after: jmp [rip+0]
constexpr uint64_t MAGIC_VALUE = 0x1E38EDFF2301EEBCULL;

// Saved context structure (matches stack layout in shellcode)
struct SavedContext {
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rdi, rsi, rbp, rbx, rdx, rcx, rax;
    uint64_t rflags;
    uint8_t fpu_state[512];  // FXSAVE area
};

// Install a full-context hook with Ring-1 style preservation.
//
// Writes FullContextStub to shellcodeAddress in the guest, patches in the
// detour and trampoline addresses, then overwrites targetAddress with a
// 14-byte absolute JMP stub to redirect execution into the shellcode.
//
// trampolineAddress must point to a buffer in the guest that already contains
// the relocated original instructions (the bytes overwritten at targetAddress,
// fixed up for their new location). Building that buffer requires a length-
// disassembler — see GetInstructionLength below.
inline bool InstallFullContextHook(
    VMM_HANDLE hVMM,
    DWORD pid,
    ULONG64 targetAddress,
    ULONG64 detourAddress,
    ULONG64 shellcodeAddress,
    ULONG64 trampolineAddress,
    uint8_t* outOriginalBytes,
    size_t originalBytesSize)
{
    // Read and save original bytes before overwriting
    if (!VMMDLL_MemRead(hVMM, pid, targetAddress, outOriginalBytes, (DWORD)originalBytesSize)) {
        return false;
    }

    // Build shellcode from template and patch in runtime addresses
    std::vector<uint8_t> shellcode(FullContextStub, FullContextStub + sizeof(FullContextStub));
    *reinterpret_cast<uint64_t*>(&shellcode[DETOUR_ADDRESS_OFFSET])    = detourAddress;
    *reinterpret_cast<uint64_t*>(&shellcode[TRAMPOLINE_ADDRESS_OFFSET]) = trampolineAddress;

    // Write shellcode to code cave in guest
    if (!VMMDLL_MemWrite(hVMM, pid, shellcodeAddress, shellcode.data(), (DWORD)shellcode.size())) {
        return false;
    }

    // Install 14-byte absolute JMP at target: FF 25 00 00 00 00 <8-byte addr>
    uint8_t hookStub[14] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
    *reinterpret_cast<uint64_t*>(hookStub + 6) = shellcodeAddress;
    if (!VMMDLL_MemWrite(hVMM, pid, targetAddress, hookStub, sizeof(hookStub))) {
        return false;
    }

    return true;
}

// Calculate instruction length for proper relocation (simplified pattern match).
//
// This covers the handful of prologue patterns that commonly appear at the start
// of NTDLL/Win32 exports (MOV, JMP, CALL). It is intentionally minimal because
// the PoC only hooks well-known system functions whose prologues are predictable.
//
// For a production trampoline that must handle arbitrary targets, replace this
// with a proper length-disassembler. Zydis (https://github.com/zyantific/zydis)
// is the recommended choice — it is header-only-friendly, actively maintained,
// and handles all x64 encoding edge cases. hde64 is a lighter alternative if
// binary size is a constraint. Neither was integrated here to keep the PoC
// dependency-free and focused on the DMA injection mechanism itself.
inline int GetInstructionLength(const uint8_t* code) {
    if (code[0] == 0x48 && (code[1] >= 0x83 && code[1] <= 0x8B)) {
        return 3; // REX.W + MOV/ADD/SUB (common prologue pattern)
    }
    if (code[0] == 0xFF && code[1] == 0x25) {
        return 6; // jmp [rip+disp32]
    }
    if (code[0] == 0xE8 || code[0] == 0xE9) {
        return 5; // call/jmp rel32
    }
    return 1; // Unrecognised — extend patterns or replace with Zydis
}

} // namespace HookShellcode
