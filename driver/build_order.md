# THE_CHAMBER driver build order

This document records the compile and link order for the driver. It
complements the existing `build.ps1` and is not a traditional WDK
`sources` file.

## Compile order

1. `the_chamber.c` -- driver entry, IOCTL dispatch, global state
2. `svm_bringup.c` -- SVM capability checks and per-CPU bring-up
3. `svm_vmcb.c` -- VMCB control and state-save area setup
4. `npt.c` -- nested page tables
5. `vmexit.c` -- VMEXIT handler (`vmexit_handler`)
6. `vmrun.asm` -- MASM-x64 launcher, assembled via `ml64.exe`

## Notes

- `vmrun.asm` is assembled with `ml64.exe` (for example
  `ml64.exe /c /Fo vmrun.obj vmrun.asm`). The resulting `vmrun.obj` is
  linked alongside the C objects.
- `vmrun.asm` exports `svm_launch` (PUBLIC) and imports `vmexit_handler`
  (EXTERN) from `vmexit.c`, so `vmexit.c` must be present at link time.
- The C sources share `the_chamber.h`; keep the `PER_CPU_CTX` layout in
  sync with the hardcoded offsets in `vmrun.asm`.
- `build.ps1` remains the authoritative build script; this file only
  documents the intended order for reference.
