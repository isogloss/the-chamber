using System;
using TheChamber.Services;

namespace TheChamber.Model;

/// <summary>
/// Expanded view of CHAMBER_CFG v2. Every field is computed by
/// <see cref="SeedService.DeriveAll"/>; nothing here is user-editable.
/// Field layout mirrors the C struct byte-for-byte for the convenience
/// of <see cref="CfgPatcher"/>.
/// </summary>
public sealed class DerivedIdentity
{
    // --- Master seed (byte-exact copy written to CHAMBER_CFG_V2.seed[32]).
    // The HV driver's identity_apply derives CPU-identity values
    // (cpu_signature, microcode_rev, platform_id, TSC ratio/freq, APIC ID
    // base, ext_feat bits) directly from this seed via chamber_derive, so
    // these fields would return constant bytes across randomize if the
    // slot were zeroed. ---
    public byte[] Seed { get; set; } = new byte[32];

    // --- HV identity ---
    public string ServiceName { get; set; } = "";
    public string DeviceSuffix { get; set; } = "";
    public uint[] PoolTags { get; set; } = new uint[6];
    public ulong VmmcallMagic { get; set; }
    public ulong CfgMagicOverride { get; set; }
    public byte RenameDonorIndex { get; set; }
    public uint GuestAsid { get; set; }
    public uint SectionScrambleSeed { get; set; }
    public ulong DriverNonce { get; set; }

    // --- Machine identity ---
    public string ComputerName { get; set; } = "";
    public Guid MachineGuid { get; set; }
    public long InstallDateFiletime { get; set; }
    public string ProductId { get; set; } = "";
    public byte[] DigitalProductId { get; set; } = Array.Empty<byte>();
    public string CpuBrandString { get; set; } = "";
    public Guid SmbiosSystemUuid { get; set; }
    public string BaseboardSerial { get; set; } = "";
    public string ChassisSerial { get; set; } = "";
    public string BiosVendor { get; set; } = "";
    public string BiosVersion { get; set; } = "";
    public MacAddress[] MacAddresses { get; set; } = Array.Empty<MacAddress>();
    public string[] DiskSerials { get; set; } = Array.Empty<string>();
    public uint[] VolumeSerials { get; set; } = Array.Empty<uint>();
    public uint GpuVenDev { get; set; }
    public byte[] EdidNonce { get; set; } = Array.Empty<byte>();

    // --- Toggles (bit layout == CHAMBER_CFG_V2.toggles) ---
    public uint Toggles { get; set; }

    public string GpuVendorPretty()
    {
        var ven = (ushort)(GpuVenDev >> 16);
        var dev = (ushort)GpuVenDev;
        var name = ven switch
        {
            0x10DE => "NVIDIA",
            0x1002 => "AMD",
            0x8086 => "Intel",
            _ => "?",
        };
        return $"{name}  VEN_{ven:X4}&DEV_{dev:X4}";
    }
}
