/* integrity.h -- Phase 7.2 HV code-integrity self-check.
 *
 * A guest-side DPC fires every 5 seconds and issues a VMMCALL with the
 * code CHAMBER_HCALL_SELF_INTEGRITY. The HV handles the hcall in root
 * (host) context -- where its own code is mapped through the normal
 * kernel VA (NOT through NPT, which §7.1 hides) -- hashes its code
 * pages via FNV-1a, stores the hash on first call, compares on
 * subsequent calls, and writes the pass/fail verdict into a shared
 * status page that both host and guest see.
 *
 * The guest DPC reads the shared status page after the VMMCALL
 * returns; on mismatch it calls KeBugCheck(0xDEADC0DE) to crash the
 * box deterministically (attacker-controlled memory corruption of HV
 * code is terminal; no "clever" recovery).
 *
 * Shared status page. A single non-paged page allocated at HV init,
 * identity-mapped in NPT (same PA == GVA physical frame; both guest
 * and host see it). The guest only reads it; the HV only writes it.
 * No locking needed -- the write is a single aligned ULONG, torn
 * writes are impossible on x86-64 for 4-byte writes to aligned
 * addresses.
 *
 * Hash algorithm. FNV-1a 64-bit is the choice: small code, no table,
 * unkeyed (we're defending against passive corruption, not an active
 * adversary who can observe the hash); CRC-64 would also work. The
 * HV's SizeOfImage captured from the KLDR entry at init bounds the
 * walk. */

#ifndef THE_CHAMBER_INTEGRITY_H
#define THE_CHAMBER_INTEGRITY_H

#include "the_chamber.h"

/* VMMCALL sub-code dispatched by handle_vmmcall. Guest DPC issues this
 * periodically; host hashes its own code and writes the result. */
#define CHAMBER_HCALL_SELF_INTEGRITY  4

/* Layout of the shared status page. One instance, 4 KiB nonpaged, PA
 * identity-mapped in NPT so guest reads == host reads. */
typedef struct _CHAMBER_INTEGRITY_STATUS {
    /* Must be set to 1 by the HV on every call; the DPC reads it to
     * confirm the HV responded. Cleared to 0 before the VMMCALL and
     * checked after. A zero after the VMMCALL means the HV silently
     * ignored the hcall, which itself is a failure. */
    volatile ULONG hv_responded;

    /* 1 => most recent check failed (hash mismatch). 0 => OK. Read by
     * the guest DPC after VMMCALL returns; on 1 the DPC bugchecks. */
    volatile ULONG integrity_failed;

    /* FNV-1a 64-bit hash of the HV code region at the previous call.
     * Written by the HV, read for debugging. */
    volatile ULONGLONG last_hash;

    /* Monotonic call counter. HV increments every time. */
    volatile ULONGLONG call_count;

    UCHAR pad[4096 - sizeof(ULONG)*2 - sizeof(ULONGLONG)*2];
} CHAMBER_INTEGRITY_STATUS, *PCHAMBER_INTEGRITY_STATUS;

/* Called once from DriverEntry, after npt_init and svm_init but
 * BEFORE svm_launch, so the shared page is identity-mapped by the
 * initial NPT walk. Allocates the shared page (non-paged), captures
 * the HV image range from the DRIVER_OBJECT, and arms a 5-second
 * periodic DPC that issues the VMMCALL.  Returns failure only if the
 * allocation fails -- never fatal to Phase 7.2's absence (operator
 * can skip integrity by not calling this). */
NTSTATUS integrity_init(PDRIVER_OBJECT drv);

/* Called from UnloadRoutine BEFORE any svm teardown. Cancels the DPC
 * timer, waits for any in-flight DPC via KeFlushQueuedDpcs, and frees
 * the shared page. */
void     integrity_shutdown(void);

/* HV-side hcall handler, called from handle_vmmcall. Runs in root
 * context (where HV code is mapped through the normal kernel VA, so
 * reading it is a plain memory access, NOT a guest access going
 * through NPT). First call captures known_hash; subsequent calls
 * compare and set integrity_failed on mismatch. */
void     integrity_handle_hcall(void);

#endif /* THE_CHAMBER_INTEGRITY_H */
