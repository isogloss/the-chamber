/* flt_filter.c -- INTENTIONALLY A NO-OP (WAVE 8.5).
 *
 * Earlier waves attached a minifilter so a sample opening \Device\Ndis
 * directly (rather than through iphlpapi) would see the same MAC
 * rewrite the IC-side already performed. Two defects made that path
 * dead weight:
 *
 *   1. FLT is the wrong framework. NDIS IOCTLs ride the
 *      IRP_MJ_DEVICE_CONTROL path against the NDIS driver object, not
 *      against a mounted file-system volume. FltMgr dispatches callbacks
 *      only for I/O that traverses a volume's filter stack; an open
 *      against \Device\Ndis never enters that stack at all, so the
 *      pre-op callback never fires for the operations this filter
 *      claimed to cover.
 *
 *   2. The InstanceSetup here returned STATUS_FLT_DO_NOT_ATTACH for
 *      every volume, so even the FS-side callbacks were unreachable.
 *      The pre-op / post-op code was therefore unused and only widened
 *      the attack surface (FltMgr still mounts a filter object we
 *      register, visible through `fltmc instances`).
 *
 * The MAC-rewrite path the earlier filter aimed at is handled on the
 * IC-return side (syscall_rewrite.c, OID_802_3_* in the stats IOCTL
 * post-op), which is the actual dispatch point for samples that call
 * IOCTL_NDIS_QUERY_GLOBAL_STATS through any user-mode shim. For a
 * sample that bypasses NDIS entirely (TDI / WSK raw sockets), the
 * registry-mirror path in cm_filter.c already covers the identity
 * fields.
 *
 * To close Wave 8.5 residual "flt-no-op-attach" without forcing
 * every caller to change, cfp_flt_register is kept as an exported
 * symbol and returns STATUS_SUCCESS without calling FltRegisterFilter.
 * cfp_flt_unregister_now is a no-op. The driver image therefore holds
 * no FltMgr runtime reference and no minifilter object exists for
 * `fltmc instances` to enumerate.
 */

#include "fingerprint_cfg.h"

NTSTATUS
cfp_flt_register(PDRIVER_OBJECT drv)
{
    UNREFERENCED_PARAMETER(drv);
    /* No FltRegisterFilter call: see header comment for why. The
     * caller (entry.c DriverEntry) treats a non-success return as
     * non-fatal and continues, so returning SUCCESS here preserves
     * the Wave-7 dispatch order without also attaching a dead
     * minifilter. */
    return STATUS_SUCCESS;
}

void
cfp_flt_unregister_now(void)
{
    /* Nothing to tear down: cfp_flt_register never registered a
     * filter. Kept as an exported symbol so the caller's symmetric
     * register / unregister pair in entry.c and the bail-after-flt
     * teardown path both still link without a sweep. */
}
