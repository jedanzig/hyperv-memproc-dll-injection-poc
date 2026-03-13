# InjectorBridge (PoC)

Proof-of-concept Windows C++ injector bridge that uses DMA-based memory access (MemProcFS/LeechCore via Hyper-V) to map and execute a DLL inside a guest VM process — without touching the guest's kernel or using standard Windows injection APIs from within the guest.

This repository is intentionally scoped for demonstration and learning. It is not production-hardened.

## How It Works

InjectorBridge operates entirely from the **host** machine, reaching into a Hyper-V guest's physical memory through DMA:

1. **Connect** — Initializes MemProcFS with the `hvmm://` device to access guest physical memory via LiveCloudKd/hvmm.sys.
2. **Locate** — Walks the guest's process list to find the target process by name and resolves module bases/exports inside the guest.
3. **Stage 1 (Allocate)** — Finds a code cave in an existing guest module, writes shellcode that calls `VirtualAlloc`, and installs a temporary inline hook on a frequently-called function (`PeekMessageW`) so the shellcode executes in-context when the guest app next calls that function. The shellcode signals the allocation address back to the host via a shared memory flag, then spins until the host restores the original function bytes.
4. **Map** — Parses the payload DLL on the host, maps it into a flat image, resolves imports against the guest's loaded modules, applies base relocations, and writes the final image page-by-page into the freshly allocated guest memory (with physical-address fallback for pages MemProcFS can't virtually address yet).
5. **Stage 2 (Execute)** — A second shellcode + inline hook cycle calls `DllMain(DLL_PROCESS_ATTACH)` on the mapped image, completing the injection.

All hook installations are temporary — original bytes are restored as soon as each stage signals completion.

## Repository Layout

**Main** (current build path):

- `main/bridge.cpp` — CLI entry point and VMM lifecycle
- `main/injection.h` — Main injection pipeline (staging, mapping, relocations, signaling)
- `main/pe_mapper.h` — PE parsing, image mapping, import/relocation helpers
- `main/shellcode.h` — Shellcode builders/constants used by the injection stages
- `main/test_dll.cpp` — Test payload DLL (`DllMain` writes `C:\injected_test.txt` as proof of execution)

**Ideas** (not currently wired into `injector_bridge`):

- `Ideas/hook_manager.h` — Hook registry/state model and verification helpers
- `Ideas/code_cave_finder.h` — Multi-module cave scanning helpers
- `Ideas/relocation_tracker.h` — Relocation parsing/tracking utilities
- `Ideas/hook_shellcode.h` — Full-context hook shellcode prototype

## Dependencies

This project depends on [MemProcFS](https://github.com/ufrisk/MemProcFS), [LeechCore](https://github.com/ufrisk/LeechCore), and [LiveCloudKd](https://github.com/gerhart01/LiveCloudKd) (for the Hyper-V DMA driver). These are **not included** in this repository — you must download them separately.

### Setup

1. Download the latest [MemProcFS release](https://github.com/ufrisk/MemProcFS/releases) (or build from source).

2. Copy the required **headers** into `main/dependencies/`:
   ```
   main/dependencies/
   ├── vmmdll.h
   └── leechcore.h
   ```

3. Copy the required **libraries** into `libs/`:
   ```
   libs/
   ├── vmm.lib
   └── leechcore.lib
   ```

4. Download [LiveCloudKd](https://github.com/gerhart01/LiveCloudKd/releases) and place the following **runtime files** next to the built executable:
   ```
   build-vs2022/Release/
   ├── hvmm.sys              # Hyper-V memory access driver
   ├── hvlib.dll              # LiveCloudKd library
   ├── leechcore_device_hvmm.dll  # LeechCore HVMM device plugin
   ├── vmm.dll                # MemProcFS core
   ├── leechcore.dll          # LeechCore core
   ├── dbghelp.dll            # Symbol support
   └── symsrv.dll             # Symbol server support
   ```
   These are only needed at runtime — the project compiles without them.

> If your MemProcFS SDK lives elsewhere, you can point CMake to it without copying files:
> ```powershell
> cmake -S . -B build-vs2022 -G "Visual Studio 17 2022" -A x64 \
>       -DMEMPROC_INCLUDE_DIR="C:/path/to/memprocfs/includes" \
>       -DMEMPROC_LIB_DIR="C:/path/to/memprocfs/libs"
> ```

## Build

Requirements:

- Windows
- Visual Studio 2022 (or MSVC toolchain compatible with CMake)
- CMake 3.20+
- MemProcFS headers and libraries (see [Dependencies](#dependencies))

```powershell
cmake -S . -B build-vs2022 -G "Visual Studio 17 2022" -A x64
cmake --build build-vs2022 --config Release
```

## Usage

```powershell
# Run from an elevated (Administrator) prompt on the Hyper-V host
injector_bridge.exe <target_process> <payload.dll>

# Example
injector_bridge.exe notepad.exe test_payload.dll
```

The injector will wait up to 120 seconds for the target process to appear in the guest VM. Once found, it maps and executes the payload. The test DLL writes `C:\injected_test.txt` inside the guest as proof of execution.

## Detection Surface

Understanding *why* this technique is stealthy — and where it isn't — is as important as the implementation itself.

### What guest-side tooling does NOT see

| Vector | Why it's blind |
|--------|---------------|
| Guest kernel (SSDT hooks, PatchGuard) | The injector runs entirely on the **host**. No syscalls are made from within the guest. |
| Guest ETW / kernel callbacks | `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine` — none are triggered because no new thread is created and the DLL is never loaded through the Windows loader. |
| Guest AV / EDR user-mode hooks | NTDLL is not used for the allocation or mapping. `VirtualAlloc` is called via inline hook shellcode executing in the context of an existing thread — the EDR's IAT/inline hooks on `NtAllocateVirtualMemory` are bypassed because the call originates from shellcode in a code cave, not from a monitored call stack. |
| PE loader telemetry | The DLL is mapped manually. It never appears in `InMemoryOrderModuleList` (PEB module list) or triggers `LdrLoadDll` notifications. |
| Standard memory scanners (scanning for MZ headers) | Headers can be zeroed post-mapping trivially. |

### What can still detect this

| Vector | Notes |
|--------|-------|
| Host-side hypervisor introspection | A VMI (Virtual Machine Introspection) solution running at the hypervisor level would see the DMA writes. This is the same layer this tool operates on. |
| Anomalous `PeekMessageW` return values | The hook causes `PeekMessageW` to return 0 for 1–2 calls during shellcode execution. A behaviour-based rule watching for unexpected message pump failures could flag this. |
| Executable memory not backed by a file | The allocated region is `PAGE_EXECUTE_READWRITE` with no mapped file backing. Tools like PE-sieve or Moneta that scan for unbacked executable memory regions will find it. |
| Physical memory forensics | The DLL image exists in guest physical memory and is visible to any tool that can read raw RAM (including MemProcFS itself). |

The core stealth property is the **trust boundary**: all writes originate from the host, so any detection mechanism that relies solely on guest OS visibility is structurally blind to this class of attack.

## License

This project is licensed under the [MIT License](LICENSE).

MemProcFS, LeechCore, and LiveCloudKd are third-party projects with their own licenses — see their respective repositories for terms.

## Disclaimer

This code is for **educational and authorized security research purposes only**. Do not use it against systems you do not own or have explicit permission to test.
