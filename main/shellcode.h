#pragma once
#include <windows.h>
#include <vector>
#include <cstring>

// x64 shellcode templates for DMA-based injection via inline hooking.
// These are called when a hooked function is invoked. They do their work,
// then return 0 (xor eax,eax; ret). The host restores the original function
// bytes after the signal is set, so only 1-2 calls see the dummy return.

namespace Shellcode {

// Stage 1: VirtualAlloc shellcode (Inline hook version)
//
// Tries preferred address first (near existing modules to reuse page table
// entries that MemProcFS can already walk), falls back to NULL.
//
// Assembly:
//   push rcx / rdx / r8 / r9
//   mov r10, <signal_addr>       ; check if already executed
//   cmp qword [r10], 0
//   jne .skip
//   sub rsp, 0x28                ; shadow space
//   mov rcx, <preferred_addr>    ; VirtualAlloc(preferred,
//   mov edx, <size>              ;   size,
//   mov r8d, 0x3000              ;   MEM_COMMIT|MEM_RESERVE,
//   mov r9d, 0x40                ;   PAGE_EXECUTE_READWRITE)
//   mov rax, <VirtualAlloc>
//   call rax
//   test rax, rax
//   jnz .alloc_ok
//   xor ecx, ecx                ; fallback: VirtualAlloc(NULL, ...)
//   mov edx, <size>
//   mov r8d, 0x3000
//   mov r9d, 0x40
//   mov rax, <VirtualAlloc>
//   call rax
// .alloc_ok:
//   test rax, rax
//   je .store_result
//   <touch every page>
// .store_result:
//   mov r10, <signal_addr>
//   mov [r10], rax
//   add rsp, 0x28
// .skip:
//   pop r9 / r8 / rdx / rcx
//   <spin wait for host to restore hook>
//   jmp <original_func>

struct VirtualAllocShellcode {
    // Patch offsets into the shellcode byte array
    static constexpr size_t SIGNAL_ADDR_1   = 0x08;  // 8 bytes
    static constexpr size_t PREFERRED_ADDR  = 0x26;  // 8 bytes
    static constexpr size_t SIZE_PATCH_1    = 0x32;  // 4 bytes (DWORD)
    static constexpr size_t VA_ADDR_PATCH_1 = 0x44;  // 8 bytes
    static constexpr size_t SIZE_PATCH_2    = 0x62;  // 4 bytes (DWORD)
    static constexpr size_t VA_ADDR_PATCH_2 = 0x74;  // 8 bytes
    static constexpr size_t SIZE_PATCH_3    = 0x87;  // 4 bytes (DWORD)
    static constexpr size_t SIGNAL_ADDR_2   = 0x9F;  // 8 bytes
    static constexpr size_t SIGNAL_ADDR_3   = 0xB6;  // 8 bytes
    static constexpr size_t ORIG_FUNC       = 0xCA;  // 8 bytes

    static std::vector<uint8_t> build(ULONG64 signalAddr, DWORD allocSize,
                                       ULONG64 virtualAllocAddr, ULONG64 originalFuncAddr,
                                       ULONG64 preferredAddr) {
        std::vector<uint8_t> sc = {
            // push rcx
            0x51,                                        // +0x00
            // push rdx
            0x52,                                        // +0x01
            // push r8
            0x41, 0x50,                                  // +0x02
            // push r9
            0x41, 0x51,                                  // +0x04

            // mov r10, imm64 (signal addr)
            0x49, 0xBA, 0,0,0,0,0,0,0,0,               // +0x06 (10 bytes)
            // cmp qword [r10], 0
            0x49, 0x83, 0x3A, 0x00,                     // +0x10 (4 bytes)
            // jne near .skip (6-byte near jump to +0xAE)
            // 0xAE - 0x1A = 0x94
            0x0F, 0x85, 0x94, 0x00, 0x00, 0x00,        // +0x14 (6 bytes)

            // sub rsp, 0x28
            0x48, 0x83, 0xEC, 0x28,                     // +0x1A (4 bytes)

            // r11d = 100 (loop counter)
            0x41, 0xBB, 0x64, 0x00, 0x00, 0x00,        // +0x1E (6 bytes)

            // mov rbx, imm64 (preferred alloc addr)
            0x48, 0xBB, 0,0,0,0,0,0,0,0,               // +0x24 (10 bytes)

            // .alloc_loop:
            // mov rcx, rbx
            0x48, 0x89, 0xD9,                           // +0x2E (3 bytes)
            // mov edx, imm32 (alloc size)
            0xBA, 0,0,0,0,                              // +0x31 (5 bytes)
            // mov r8d, 0x3000  (MEM_COMMIT | MEM_RESERVE)
            0x41, 0xB8, 0x00, 0x30, 0x00, 0x00,        // +0x36 (6 bytes)
            // mov r9d, 0x40  (PAGE_EXECUTE_READWRITE)
            0x41, 0xB9, 0x40, 0x00, 0x00, 0x00,        // +0x3C (6 bytes)
            // mov rax, imm64 (VirtualAlloc addr)
            0x48, 0xB8, 0,0,0,0,0,0,0,0,               // +0x42 (10 bytes)
            // call rax
            0xFF, 0xD0,                                  // +0x4C (2 bytes)

            // test rax, rax
            0x48, 0x85, 0xC0,                           // +0x4E (3 bytes)
            // jnz .alloc_ok
            0x75, 0x2B,                                  // +0x51 (2 bytes)

            // add rbx, 0x100000 (1MB)
            0x48, 0x81, 0xC3, 0x00, 0x00, 0x10, 0x00,   // +0x53 (7 bytes)
            // dec r11d
            0x41, 0xFF, 0xCB,                           // +0x5A (3 bytes)
            // jnz .alloc_loop (-0x31 = 0xCF)
            0x75, 0xCF,                                  // +0x5D (2 bytes)

            // --- Attempt 2: NULL address (let OS choose) ---
            // xor ecx, ecx
            0x31, 0xC9,                                  // +0x5F (2 bytes)
            // mov edx, imm32 (alloc size)
            0xBA, 0,0,0,0,                              // +0x61 (5 bytes)
            // mov r8d, 0x3000
            0x41, 0xB8, 0x00, 0x30, 0x00, 0x00,        // +0x66 (6 bytes)
            // mov r9d, 0x40
            0x41, 0xB9, 0x40, 0x00, 0x00, 0x00,        // +0x6C (6 bytes)
            // mov rax, imm64 (VirtualAlloc addr)
            0x48, 0xB8, 0,0,0,0,0,0,0,0,               // +0x72 (10 bytes)
            // call rax
            0xFF, 0xD0,                                  // +0x7C (2 bytes)

            // .alloc_ok:
            // test rax, rax
            0x48, 0x85, 0xC0,                           // +0x7E (3 bytes)
            // je .store_result
            0x74, 0x1A,                                  // +0x81 (2 bytes)

            // --- Touch every page to force physical commit ---
            // mov rcx, rax
            0x48, 0x89, 0xC1,                           // +0x83 (3 bytes)
            // mov edx, imm32 (alloc size)
            0xBA, 0,0,0,0,                              // +0x86 (5 bytes)
            // .loop:
            // mov byte ptr [rcx], 1
            0xC6, 0x01, 0x01,                           // +0x8B (3 bytes)
            // add rcx, 0x1000
            0x48, 0x81, 0xC1, 0x00, 0x10, 0x00, 0x00,   // +0x8E (7 bytes)
            // sub edx, 0x1000
            0x81, 0xEA, 0x00, 0x10, 0x00, 0x00,         // +0x95 (6 bytes)
            // jg .loop (-0x12)
            0x7F, 0xEE,                                  // +0x9B (2 bytes)

            // .store_result:
            // mov r10, imm64 (signal addr)
            0x49, 0xBA, 0,0,0,0,0,0,0,0,               // +0x9D (10 bytes)
            // mov [r10], rax
            0x49, 0x89, 0x02,                           // +0xA7 (3 bytes)
            // add rsp, 0x28
            0x48, 0x83, 0xC4, 0x28,                     // +0xAA (4 bytes)

            // .skip:
            // pop r9
            0x41, 0x59,                                  // +0xAE (2 bytes)
            // pop r8
            0x41, 0x58,                                  // +0xB0 (2 bytes)
            // pop rdx
            0x5A,                                        // +0xB2 (1 byte)
            // pop rcx
            0x59,                                        // +0xB3 (1 byte)

            // --- INLINE HOOK SAFESTATE ---
            // .spin_wait:
            // mov r10, imm64 (signal addr)
            0x49, 0xBA, 0,0,0,0,0,0,0,0,               // +0xB4 (10 bytes)
            // cmp qword [r10], 2        ; Wait for injector to signal restoration
            0x49, 0x83, 0x3A, 0x02,                     // +0xBE (4 bytes)
            // je .resume
            0x74, 0x04,                                  // +0xC2 (2 bytes)
            // pause                     ; Optimize CPU usage during spin
            0xF3, 0x90,                                  // +0xC4 (2 bytes)
            // jmp .spin_wait
            0xEB, 0xEC,                                  // +0xC6 (2 bytes)

            // .resume:
            // mov rax, <original_func>
            0x48, 0xB8, 0,0,0,0,0,0,0,0,                 // +0xC8 (10 bytes)
            // jmp rax                   ; Jump back to the restored function
            0xFF, 0xE0,                                  // +0xD2 (2 bytes)
        };
        // Total: 0xD4 = 212 bytes

        memcpy(sc.data() + SIGNAL_ADDR_1, &signalAddr, 8);
        memcpy(sc.data() + PREFERRED_ADDR, &preferredAddr, 8);
        memcpy(sc.data() + SIZE_PATCH_1, &allocSize, 4);
        memcpy(sc.data() + VA_ADDR_PATCH_1, &virtualAllocAddr, 8);
        memcpy(sc.data() + SIZE_PATCH_2, &allocSize, 4);
        memcpy(sc.data() + VA_ADDR_PATCH_2, &virtualAllocAddr, 8);
        memcpy(sc.data() + SIZE_PATCH_3, &allocSize, 4);
        memcpy(sc.data() + SIGNAL_ADDR_2, &signalAddr, 8);
        memcpy(sc.data() + SIGNAL_ADDR_3, &signalAddr, 8);
        memcpy(sc.data() + ORIG_FUNC, &originalFuncAddr, 8);
        return sc;
    }
};


// Stage 2: DllMain shellcode (IAT hook version)
//
// Assembly:
//   push rcx
//   push rdx
//   push r8
//   push r9
//   mov r10, <signal_addr>
//   cmp qword [r10], 0
//   jne .skip
//   sub rsp, 0x28
//   mov rcx, <dll_base>          ; hinstDLL
//   mov edx, 1                   ; DLL_PROCESS_ATTACH
//   xor r8d, r8d                 ; lpReserved = NULL
//   mov rax, <entry_point>
//   call rax
//   mov r10, <signal_addr>
//   mov qword [r10], 1           ; signal completion
//   add rsp, 0x28
// .skip:
//   pop r9
//   pop r8
//   pop rdx
//   pop rcx
//   mov rax, <original_func>
//   jmp rax

struct DllMainShellcode {
    static constexpr size_t SIGNAL_ADDR_1  = 0x08;  // 8 bytes
    static constexpr size_t DLL_BASE_PATCH = 0x1C;   // 8 bytes
    static constexpr size_t ENTRY_PATCH    = 0x2E;   // 8 bytes
    static constexpr size_t SIGNAL_ADDR_2  = 0x3A;   // 8 bytes

    static std::vector<uint8_t> build(ULONG64 signalAddr, ULONG64 dllBase,
                                       ULONG64 entryPoint, ULONG64 originalFuncAddr) {
        std::vector<uint8_t> sc = {
            // push rcx
            0x51,                                        // +0x00
            // push rdx
            0x52,                                        // +0x01
            // push r8
            0x41, 0x50,                                  // +0x02
            // push r9
            0x41, 0x51,                                  // +0x04

            // mov r10, imm64 (signal addr)
            0x49, 0xBA, 0,0,0,0,0,0,0,0,               // +0x06 (10 bytes)
            // cmp qword [r10], 0
            0x49, 0x83, 0x3A, 0x00,                     // +0x10 (4 bytes)
            // jne .skip (+0x37 to 0x4D)
            0x75, 0x37,                                  // +0x14 (2 bytes)
            
            // sub rsp, 0x28
            0x48, 0x83, 0xEC, 0x28,                     // +0x16 (4 bytes)
            // mov rcx, imm64 (dll base = hinstDLL)
            0x48, 0xB9, 0,0,0,0,0,0,0,0,               // +0x1A (10 bytes)
            // mov edx, 1  (DLL_PROCESS_ATTACH)
            0xBA, 0x01, 0x00, 0x00, 0x00,               // +0x24 (5 bytes)
            // xor r8d, r8d  (lpReserved = NULL)
            0x45, 0x31, 0xC0,                           // +0x29 (3 bytes)
            // mov rax, imm64 (entry point)
            0x48, 0xB8, 0,0,0,0,0,0,0,0,               // +0x2C (10 bytes)
            // call rax
            0xFF, 0xD0,                                  // +0x36 (2 bytes)
            
            // mov r10, imm64 (signal addr)
            0x49, 0xBA, 0,0,0,0,0,0,0,0,               // +0x38 (10 bytes)
            // mov qword [r10], 1
            0x49, 0xC7, 0x02, 0x01, 0x00, 0x00, 0x00,  // +0x42 (7 bytes)
            // add rsp, 0x28
            0x48, 0x83, 0xC4, 0x28,                     // +0x49 (4 bytes)
            
            // .skip:
            // pop r9
            0x41, 0x59,                                  // +0x4D (2 bytes)
            // pop r8
            0x41, 0x58,                                  // +0x4F (2 bytes)
            // pop rdx
            0x5A,                                        // +0x51 (1 byte)
            // pop rcx
            0x59,                                        // +0x52 (1 byte)

            // --- INLINE HOOK SAFESTATE ---
            // .spin_wait:
            // mov r10, imm64 (signal addr)
            0x49, 0xBA, 0,0,0,0,0,0,0,0,               // +0x53 (10 bytes)
            // cmp qword [r10], 2        ; Wait for injector to signal restoration
            0x49, 0x83, 0x3A, 0x02,                     // +0x5D (4 bytes)
            // je .resume
            0x74, 0x04,                                  // +0x61 (2 bytes)
            // pause                     ; Optimize CPU usage during spin
            0xF3, 0x90,                                  // +0x63 (2 bytes)
            // jmp .spin_wait
            0xEB, 0xEC,                                  // +0x65 (2 bytes)
            
            // .resume:
            // mov rax, <original_func>
            0x48, 0xB8, 0,0,0,0,0,0,0,0,                 // +0x67 (10 bytes)
            // jmp rax                   ; Jump back to the restored function
            0xFF, 0xE0,                                  // +0x71 (2 bytes)
        };
        // Total: 0x73 = 115 bytes

        memcpy(sc.data() + SIGNAL_ADDR_1, &signalAddr, 8);
        memcpy(sc.data() + DLL_BASE_PATCH, &dllBase, 8);
        memcpy(sc.data() + ENTRY_PATCH, &entryPoint, 8);
        memcpy(sc.data() + SIGNAL_ADDR_2, &signalAddr, 8);
        memcpy(sc.data() + 0x55, &signalAddr, 8); // Spin wait signal check patch
        memcpy(sc.data() + 0x69, &originalFuncAddr, 8); // Resume jmp patch
        return sc;
    }
};

// Inline hook: 12-byte JMP stub that overwrites a function's prologue
//   mov rax, <target>   ; 48 B8 + 8 bytes = 10 bytes
//   jmp rax              ; FF E0 = 2 bytes
static constexpr size_t INLINE_HOOK_SIZE = 12;

static std::vector<uint8_t> buildInlineHook(ULONG64 targetAddr) {
    std::vector<uint8_t> hook = {
        0x48, 0xB8, 0,0,0,0,0,0,0,0,  // mov rax, imm64
        0xFF, 0xE0,                      // jmp rax
    };
    memcpy(hook.data() + 2, &targetAddr, 8);
    return hook;
}

// Layout in code cave
static constexpr DWORD CODE_CAVE_REQUIRED = 0x100; // 256 bytes total (VirtualAlloc shellcode is 212)
static constexpr DWORD SIGNAL_OFFSET = 0x80;      // Signal at cave + 0x80

} // namespace Shellcode
