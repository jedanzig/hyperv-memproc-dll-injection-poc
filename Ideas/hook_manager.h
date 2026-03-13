#pragma once
#include <windows.h>
#include <vector>
#include <unordered_map>
#include <memory>
#include <string>
#include <iomanip>
#include <iostream>
#include "vmmdll.h"

namespace HookManager {

// Supported hook types
enum class HookType {
    INLINE_JMP,           // Simple 14-byte absolute JMP
    FULL_CONTEXT,         // Full CPU state preservation (Ring-1 style)
    TRAMPOLINE            // With original instruction relocation
};

// Hook lifecycle state
enum class HookState {
    INITIALIZED,          // Created but not installed
    INSTALLED,            // Successfully installed
    ACTIVE,              // Currently active and can be called
    SUSPENDED,           // Temporarily disabled
    FAILED,              // Installation or verification failed
    RESTORED             // Removed and original bytes restored
};

// Hook metadata and runtime state
struct HookInfo {
    ULONG64 targetAddress;
    ULONG64 detourAddress;
    ULONG64 trampolineAddress;    // Address of relocated original instructions
    ULONG64 shellcodeAddress;     // Address of hook shellcode (if used)
    
    HookType type;
    HookState state;
    std::string name;             // For debugging
    
    uint8_t originalBytes[32];    // Original instructions (up to 32 bytes)
    size_t originalBytesSize;
    
    uint8_t hookBytes[32];        // The hook we installed
    size_t hookBytesSize;
    
    uint8_t currentBytes[32];     // Last known state (for verification)
    
    DWORD pid;
    VMM_HANDLE hVMM;
    
    uint64_t installTime;         // Timestamp of installation
    uint32_t callCount;           // How many times hook was hit (if tracked)
    bool verified;                // Whether hook was verified after install
    
    HookInfo() : 
        targetAddress(0), detourAddress(0), trampolineAddress(0), shellcodeAddress(0),
        type(HookType::INLINE_JMP), state(HookState::INITIALIZED),
        originalBytesSize(0), hookBytesSize(0),
        pid(0), hVMM(nullptr), installTime(0), callCount(0), verified(false) {
        memset(originalBytes, 0, sizeof(originalBytes));
        memset(hookBytes, 0, sizeof(hookBytes));
        memset(currentBytes, 0, sizeof(currentBytes));
    }
};

class HookRegistry {
private:
    std::unordered_map<ULONG64, std::unique_ptr<HookInfo>> hooks;
    std::unordered_map<std::string, ULONG64> hooksByName;
    bool globalVerificationEnabled;
    
public:
    HookRegistry() : globalVerificationEnabled(true) {}
    
    // Register a hook (separate from installation)
    HookInfo* RegisterHook(
        const std::string& name,
        ULONG64 targetAddress,
        ULONG64 detourAddress,
        HookType type,
        VMM_HANDLE hVMM,
        DWORD pid)
    {
        // Check if hook already exists
        if (hooks.find(targetAddress) != hooks.end()) {
            std::cerr << "[HookMgr] Hook already registered at 0x" 
                      << std::hex << targetAddress << std::dec << std::endl;
            return nullptr;
        }
        
        auto hook = std::make_unique<HookInfo>();
        hook->name = name;
        hook->targetAddress = targetAddress;
        hook->detourAddress = detourAddress;
        hook->type = type;
        hook->hVMM = hVMM;
        hook->pid = pid;
        hook->state = HookState::INITIALIZED;
        
        std::cout << "[HookMgr] Registered hook '" << name << "' at 0x" 
                  << std::hex << targetAddress << std::dec << std::endl;
        
        HookInfo* pHook = hook.get();
        hooks[targetAddress] = std::move(hook);
        hooksByName[name] = targetAddress;
        
        return pHook;
    }
    
    // Install a registered hook and optionally verify it
    bool InstallHook(const std::string& name) {
        auto it = hooksByName.find(name);
        if (it == hooksByName.end()) {
            std::cerr << "[HookMgr] Hook '" << name << "' not found" << std::endl;
            return false;
        }
        
        return InstallHook(it->second);
    }
    
    bool InstallHook(ULONG64 targetAddress) {
        auto it = hooks.find(targetAddress);
        if (it == hooks.end()) {
            return false;
        }
        
        HookInfo* hook = it->second.get();
        
        // Read original bytes
        uint8_t originalBytes[32];
        size_t bytesToRead = (hook->type == HookType::INLINE_JMP) ? 14 : 32;
        
        if (!VMMDLL_MemRead(hook->hVMM, hook->pid, hook->targetAddress, 
                            originalBytes, bytesToRead)) {
            std::cerr << "[HookMgr] Failed to read original bytes for hook '" 
                      << hook->name << "'" << std::endl;
            hook->state = HookState::FAILED;
            return false;
        }
        
        // Save original bytes
        memcpy(hook->originalBytes, originalBytes, bytesToRead);
        hook->originalBytesSize = bytesToRead;
        
        // Build hook based on type
        uint8_t hookBytes[32];
        size_t hookSize = 0;
        
        if (hook->type == HookType::INLINE_JMP) {
            // 14-byte absolute JMP: FF 25 00 00 00 00 [8-byte address]
            hookBytes[0] = 0xFF;
            hookBytes[1] = 0x25;
            *(DWORD*)(hookBytes + 2) = 0;
            *(ULONG64*)(hookBytes + 6) = hook->detourAddress;
            hookSize = 14;
        }
        
        // Save hook bytes for later verification
        memcpy(hook->hookBytes, hookBytes, hookSize);
        hook->hookBytesSize = hookSize;
        
        // Install the hook
        if (!VMMDLL_MemWrite(hook->hVMM, hook->pid, hook->targetAddress, 
                             hookBytes, hookSize)) {
            std::cerr << "[HookMgr] Failed to write hook for '" << hook->name << "'" << std::endl;
            hook->state = HookState::FAILED;
            return false;
        }
        
        hook->installTime = GetTickCount64();
        hook->state = HookState::INSTALLED;
        
        std::cout << "[HookMgr] Installed hook '" << hook->name << "' at 0x" 
                  << std::hex << hook->targetAddress << std::dec << std::endl;
        
        // Verify installation if enabled.
        if (globalVerificationEnabled) {
            return VerifyHook(targetAddress);
        }
        
        return true;
    }
    
    // Verify that the installed hook bytes are intact
    bool VerifyHook(ULONG64 targetAddress) {
        auto it = hooks.find(targetAddress);
        if (it == hooks.end()) return false;
        
        HookInfo* hook = it->second.get();
        
        if (hook->state != HookState::INSTALLED && hook->state != HookState::ACTIVE) {
            return false;
        }
        
        uint8_t readBytes[32];
        if (!VMMDLL_MemRead(hook->hVMM, hook->pid, hook->targetAddress, 
                            readBytes, hook->hookBytesSize)) {
            std::cerr << "[HookMgr] Failed to read back hook '" << hook->name << "'" << std::endl;
            return false;
        }
        
        if (memcmp(readBytes, hook->hookBytes, hook->hookBytesSize) != 0) {
            std::cerr << "[HookMgr] Hook verification FAILED for '" << hook->name << "'" << std::endl;
            std::cerr << "    Expected: ";
            for (size_t i = 0; i < hook->hookBytesSize; i++) {
                std::cerr << std::hex << std::setw(2) << std::setfill('0') 
                          << (int)hook->hookBytes[i] << " ";
            }
            std::cerr << std::endl << "    Got:      ";
            for (size_t i = 0; i < hook->hookBytesSize; i++) {
                std::cerr << std::hex << std::setw(2) << std::setfill('0') 
                          << (int)readBytes[i] << " ";
            }
            std::cerr << std::dec << std::endl;
            
            hook->state = HookState::FAILED;
            hook->verified = false;
            return false;
        }
        
        hook->verified = true;
        hook->state = HookState::ACTIVE;
        memcpy(hook->currentBytes, readBytes, hook->hookBytesSize);
        
        std::cout << "[HookMgr] Hook '" << hook->name << "' verified successfully" << std::endl;
        return true;
    }
    
    // Restore original target bytes
    bool RestoreHook(const std::string& name) {
        auto it = hooksByName.find(name);
        if (it == hooksByName.end()) return false;
        return RestoreHook(it->second);
    }
    
    bool RestoreHook(ULONG64 targetAddress) {
        auto it = hooks.find(targetAddress);
        if (it == hooks.end()) return false;
        
        HookInfo* hook = it->second.get();
        
        if (!VMMDLL_MemWrite(hook->hVMM, hook->pid, hook->targetAddress,
                             hook->originalBytes, hook->originalBytesSize)) {
            std::cerr << "[HookMgr] Failed to restore hook '" << hook->name << "'" << std::endl;
            return false;
        }
        
        hook->state = HookState::RESTORED;
        std::cout << "[HookMgr] Restored original bytes for hook '" << hook->name << "'" << std::endl;
        return true;
    }
    
    // Verify every registered hook
    bool VerifyAllHooks() {
        std::cout << "[HookMgr] Verifying all hooks..." << std::endl;
        int total = 0, passed = 0, failed = 0;
        
        for (auto& pair : hooks) {
            total++;
            if (VerifyHook(pair.first)) {
                passed++;
            } else {
                failed++;
            }
        }
        
        std::cout << "[HookMgr] Verification complete: " << passed << "/" << total 
                  << " passed, " << failed << " failed" << std::endl;
        
        return failed == 0;
    }
    
    // Get hook by name or address
    HookInfo* GetHook(const std::string& name) {
        auto it = hooksByName.find(name);
        if (it == hooksByName.end()) return nullptr;
        return hooks[it->second].get();
    }
    
    HookInfo* GetHook(ULONG64 address) {
        auto it = hooks.find(address);
        if (it == hooks.end()) return nullptr;
        return it->second.get();
    }
    
    // Print hook statistics
    void PrintStats() {
        std::cout << "\n[HookMgr] Hook Statistics:" << std::endl;
        std::cout << "==========================" << std::endl;
        std::cout << "Total hooks: " << hooks.size() << std::endl;
        
        int installed = 0, active = 0, failed = 0, restored = 0;
        for (const auto& pair : hooks) {
            switch (pair.second->state) {
                case HookState::INSTALLED: installed++; break;
                case HookState::ACTIVE: active++; break;
                case HookState::FAILED: failed++; break;
                case HookState::RESTORED: restored++; break;
            }
        }
        
        std::cout << "  Installed: " << installed << std::endl;
        std::cout << "  Active:    " << active << std::endl;
        std::cout << "  Failed:    " << failed << std::endl;
        std::cout << "  Restored:  " << restored << std::endl;
    }
    
    // Cleanup - restore all hooks
    ~HookRegistry() {
        std::cout << "[HookMgr] Cleaning up all hooks..." << std::endl;
        for (auto& pair : hooks) {
            if (pair.second->state == HookState::ACTIVE || 
                pair.second->state == HookState::INSTALLED) {
                RestoreHook(pair.first);
            }
        }
    }
};

} // namespace HookManager
