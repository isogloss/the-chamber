/* stealth.h -- module self-concealment API.
 * Apply during successful driver init; revert during unload. */
#pragma once
#include <ntddk.h>

NTSTATUS stealth_apply(PDRIVER_OBJECT drv);
NTSTATUS stealth_revert(PDRIVER_OBJECT drv);
