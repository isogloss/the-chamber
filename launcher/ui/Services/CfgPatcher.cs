using System;
using System.Buffers.Binary;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using TheChamber.Model;

namespace TheChamber.Services;

/// <summary>
/// Locates the 632-byte CHAMBER_CFG_V2 blob inside a driver image by
/// scanning for its magic-version-length triple, overwrites it with the
/// derived identity, recomputes the PE checksum, writes the result to
/// a seed-named file under %ProgramFiles%\The Chamber\, and re-signs
/// the result with the launcher's cached self-signed cert (Subject
/// "The Chamber"; see <see cref="AuthenticodeSigner"/>).
///
/// The image bytes come in as a parameter so this layer doesn't care
/// whether the driver was resource-embedded or copied in from somewhere
/// else. Re-signing is invoked by the launcher separately after the
/// patch completes.
/// </summary>
public sealed class CfgPatcher
{
    private readonly AuthenticodeSigner _signer = new();

    /// <summary>
    /// Re-sign a patched driver (or the shim DLL) in place with the
    /// launcher's cached code-signing cert. Must be called after the
    /// CFG patch and PE-checksum rewrite, otherwise <c>NtLoadDriver</c>
    /// rejects the file for an invalid Authenticode signature while
    /// test-signing is on.
    /// </summary>
    public Task ResignAsync(string filePath) => _signer.SignAsync(filePath);

    // Must match driver/the_chamber.h and design Section 3.
    public const uint CfgMagicV2 = 0x32474643; // 'CFG2'
    public const uint CfgVersion = 2;
    public const int CfgTotalLength = 632;

    // Field offsets (from design Section 3; also the comment-block in the
    // C header once Agent B lands his edit).
    private const int OffMagic = 0;
    private const int OffVersion = 4;
    private const int OffTotalLength = 8;
    private const int OffSeed = 12;
    private const int OffToggles = 44;
    private const int OffServiceName = 48;
    private const int OffDeviceSuffix = 60;
    private const int OffPoolTags = 72;
    private const int OffVmmcallMagic = 96;
    private const int OffCfgMagicOverride = 104;
    private const int OffRenameDonor = 112;
    private const int OffGuestAsid = 116;
    private const int OffSectionScramble = 120;
    private const int OffDriverNonce = 124;
    private const int OffComputerName = 132;
    private const int OffMachineGuid = 148;
    private const int OffInstallDate = 164;
    private const int OffProductId = 172;
    private const int OffDigitalProductId = 196;
    private const int OffCpuBrand = 360;
    private const int OffSmbiosUuid = 408;
    private const int OffBaseboardSerial = 424;
    private const int OffChassisSerial = 440;
    private const int OffBiosVendor = 456;
    private const int OffBiosVersion = 472;
    private const int OffMacAddrs = 488;
    private const int OffDiskSerials = 512;
    private const int OffVolumeSerials = 592;
    private const int OffGpuVenDev = 608;
    private const int OffEdidNonce = 612;

    public string InstallRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        "The Chamber");

    public string ComputeTargetPath(string serviceName)
    {
        Directory.CreateDirectory(InstallRoot);
        // The on-disk filename varies per seed; the service name is already
        // seed-derived and alphanumeric so we reuse it.
        return Path.Combine(InstallRoot, serviceName + ".sys");
    }

    /// <summary>
    /// Result of a successful <see cref="PatchAndWriteAsync"/>: the on-disk
    /// path of the patched driver, plus a stand-alone copy of the 632-byte
    /// CHAMBER_CFG_V2 blob exactly as it was written into the driver's
    /// <c>.cfg</c> section. The second field is what
    /// <see cref="DriverLoader.InstallAndLoadFingerprintAsync"/> writes
    /// under <c>Services\&lt;fp_svc&gt;\Parameters\CfgBlob</c> so the
    /// fingerprint driver sees byte-identical identity bytes.
    /// </summary>
    public readonly record struct PatchResult(string Path, byte[] CfgBlob);

    /// <summary>
    /// Patches the CHAMBER_CFG_V2 blob inside <paramref name="driverImage"/>
    /// (in place in a working copy) with values from <paramref name="id"/>,
    /// recomputes the PE checksum, writes the result to <paramref name="target"/>,
    /// and returns the path written together with the final CFG blob bytes.
    /// </summary>
    public async Task<PatchResult> PatchAndWriteAsync(byte[] driverImage, DerivedIdentity id, string target)
    {
        var work = (byte[])driverImage.Clone();

        if (work.Length == 0)
        {
            // Build-time stub: no driver embedded yet. Write a tiny marker
            // file so the rest of the pipeline can tell the patch stage
            // ran but had nothing to work against. The returned CFG blob
            // is still byte-exact so the second driver's registry CFG
            // path is still populated — useful for launcher-only dry runs.
            var stub = new byte[CfgTotalLength];
            BinaryPrimitives.WriteUInt32LittleEndian(stub.AsSpan(OffMagic), CfgMagicV2);
            BinaryPrimitives.WriteUInt32LittleEndian(stub.AsSpan(OffVersion), CfgVersion);
            BinaryPrimitives.WriteUInt32LittleEndian(stub.AsSpan(OffTotalLength), (uint)CfgTotalLength);
            WriteFields(stub.AsSpan(0, CfgTotalLength), id);
            await WriteStubAsync(target, id).ConfigureAwait(false);
            return new PatchResult(target, stub);
        }

        var offset = FindCfgOffset(work);
        if (offset < 0)
        {
            throw new InvalidDataException(
                "CHAMBER_CFG_V2 magic not found in driver image. " +
                "The driver was built without a seedable .cfg section.");
        }

        var span = work.AsSpan(offset, CfgTotalLength);
        WriteFields(span, id);

        // Snapshot the final blob BEFORE we re-checksum the whole image —
        // the checksum lives in the PE header, not in the CFG blob, so
        // this copy is byte-identical to what the fingerprint driver
        // consumes.
        var cfgCopy = span.ToArray();

        RecomputePeChecksum(work);

        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        var tmp = target + ".tmp";
        await File.WriteAllBytesAsync(tmp, work).ConfigureAwait(false);
        File.Move(tmp, target, overwrite: true);
        return new PatchResult(target, cfgCopy);
    }

    public int FindCfgOffset(ReadOnlySpan<byte> image)
    {
        // Linear scan with the magic-triple sentinel: (magic==CFG2) &&
        // (version==2) && (total_length==632). The driver is small and the
        // blob is uniquely identifiable, so false positives are negligible.
        for (int i = 0; i + CfgTotalLength <= image.Length; i += 4)
        {
            var m = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(i, 4));
            if (m != CfgMagicV2) continue;
            if (i + 12 > image.Length) break;
            var v = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(i + 4, 4));
            var l = BinaryPrimitives.ReadUInt32LittleEndian(image.Slice(i + 8, 4));
            if (v == CfgVersion && l == CfgTotalLength)
            {
                return i;
            }
        }
        return -1;
    }

    private static void WriteFields(Span<byte> cfg, DerivedIdentity id)
    {
        // Master seed copied into the kernel image. identity_apply in
        // driver/identity.c derives CPU-identity values (cpu_signature,
        // microcode_rev, platform_id, TSC ratio/freq, APIC ID base,
        // extended feature bits, per-vCPU TSC_AUX) from this slot via
        // chamber_derive. Zeroing it would stop those fields from
        // varying across randomize -- the whole point of the seed.
        if (id.Seed.Length != 32)
            throw new InvalidOperationException(
                $"DerivedIdentity.Seed must be 32 bytes; got {id.Seed.Length}");
        id.Seed.AsSpan().CopyTo(cfg.Slice(OffSeed, 32));

        BinaryPrimitives.WriteUInt32LittleEndian(cfg.Slice(OffToggles), id.Toggles);

        WriteAsciiFixed(cfg.Slice(OffServiceName, 12), id.ServiceName);
        WriteAsciiFixed(cfg.Slice(OffDeviceSuffix, 12), id.DeviceSuffix);

        for (int i = 0; i < 6; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(cfg.Slice(OffPoolTags + i * 4), id.PoolTags[i]);
        }

        BinaryPrimitives.WriteUInt64LittleEndian(cfg.Slice(OffVmmcallMagic), id.VmmcallMagic);
        BinaryPrimitives.WriteUInt64LittleEndian(cfg.Slice(OffCfgMagicOverride), id.CfgMagicOverride);

        cfg[OffRenameDonor] = id.RenameDonorIndex;
        cfg[OffRenameDonor + 1] = 0;
        cfg[OffRenameDonor + 2] = 0;
        cfg[OffRenameDonor + 3] = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(cfg.Slice(OffGuestAsid), id.GuestAsid);
        BinaryPrimitives.WriteUInt32LittleEndian(cfg.Slice(OffSectionScramble), id.SectionScrambleSeed);
        BinaryPrimitives.WriteUInt64LittleEndian(cfg.Slice(OffDriverNonce), id.DriverNonce);

        WriteAsciiFixed(cfg.Slice(OffComputerName, 16), id.ComputerName);

        // Guid.ToByteArray returns the standard mixed-endian serialization
        // that the DMI blob also uses, so we forward it verbatim.
        id.MachineGuid.ToByteArray().AsSpan().CopyTo(cfg.Slice(OffMachineGuid, 16));
        BinaryPrimitives.WriteInt64LittleEndian(cfg.Slice(OffInstallDate), id.InstallDateFiletime);
        WriteAsciiFixed(cfg.Slice(OffProductId, 24), id.ProductId);

        id.DigitalProductId.AsSpan(0, Math.Min(164, id.DigitalProductId.Length))
            .CopyTo(cfg.Slice(OffDigitalProductId, 164));

        WriteAsciiFixed(cfg.Slice(OffCpuBrand, 48), id.CpuBrandString);

        id.SmbiosSystemUuid.ToByteArray().AsSpan().CopyTo(cfg.Slice(OffSmbiosUuid, 16));

        WriteAsciiFixed(cfg.Slice(OffBaseboardSerial, 16), id.BaseboardSerial);
        WriteAsciiFixed(cfg.Slice(OffChassisSerial, 16), id.ChassisSerial);
        WriteAsciiFixed(cfg.Slice(OffBiosVendor, 16), id.BiosVendor);
        WriteAsciiFixed(cfg.Slice(OffBiosVersion, 16), id.BiosVersion);

        // mac_addrs[6][4]: byte 0 = OUI pool index, bytes 1-3 = NIC bytes.
        for (int i = 0; i < 6 && i < id.MacAddresses.Length; i++)
        {
            var m = id.MacAddresses[i];
            // Locate the pool index for this OUI; the SeedService picked it
            // from the same pool so this lookup is cheap.
            byte idx = 0;
            for (byte j = 0; j < SeedService.OuiPool.Length; j++)
            {
                var pool = SeedService.OuiPool[j].Bytes;
                if (pool[0] == m.Oui.Bytes[0] && pool[1] == m.Oui.Bytes[1] && pool[2] == m.Oui.Bytes[2])
                {
                    idx = j;
                    break;
                }
            }
            var slot = cfg.Slice(OffMacAddrs + i * 4, 4);
            slot[0] = idx;
            slot[1] = m.Nic[0];
            slot[2] = m.Nic[1];
            slot[3] = m.Nic[2];
        }

        // disk_serials[20][4]: 4-byte seed tag per slot. Design doc notes
        // the full 20-char serial is re-derived at return-rewrite time by
        // the per-process interceptor; the launcher only stores the index.
        for (int i = 0; i < 20 && i < id.DiskSerials.Length; i++)
        {
            var tag = Encoding.ASCII.GetBytes(id.DiskSerials[i]);
            var slot = cfg.Slice(OffDiskSerials + i * 4, 4);
            // First 4 bytes of the serial act as the stable tag.
            slot[0] = tag.Length > 0 ? tag[0] : (byte)0;
            slot[1] = tag.Length > 1 ? tag[1] : (byte)0;
            slot[2] = tag.Length > 2 ? tag[2] : (byte)0;
            slot[3] = tag.Length > 3 ? tag[3] : (byte)0;
        }

        for (int i = 0; i < 4 && i < id.VolumeSerials.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(
                cfg.Slice(OffVolumeSerials + i * 4, 4),
                id.VolumeSerials[i]);
        }

        BinaryPrimitives.WriteUInt32LittleEndian(cfg.Slice(OffGpuVenDev), id.GpuVenDev);

        id.EdidNonce.AsSpan(0, Math.Min(16, id.EdidNonce.Length))
            .CopyTo(cfg.Slice(OffEdidNonce, 16));
    }

    private static void WriteAsciiFixed(Span<byte> dst, string s)
    {
        dst.Clear();
        var bytes = Encoding.ASCII.GetBytes(s);
        var take = Math.Min(bytes.Length, dst.Length - 1); // keep NUL
        bytes.AsSpan(0, take).CopyTo(dst);
    }

    private async Task WriteStubAsync(string target, DerivedIdentity id)
    {
        // A 1-byte marker plus a JSON sidecar so the operator window has
        // something to display and the patcher's log line stays truthful.
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        await File.WriteAllBytesAsync(target, new byte[] { 0 }).ConfigureAwait(false);
        var side = Path.ChangeExtension(target, ".cfg.txt");
        var text = new StringBuilder();
        text.AppendLine("# CHAMBER_CFG v2 — patch stub (driver bytes not yet embedded)");
        text.AppendLine($"service_name        {id.ServiceName}");
        text.AppendLine($"device_suffix       {id.DeviceSuffix}");
        text.AppendLine($"guest_asid          0x{id.GuestAsid:X4}");
        text.AppendLine($"vmmcall_magic       0x{id.VmmcallMagic:X16}");
        text.AppendLine($"computer_name       {id.ComputerName}");
        text.AppendLine($"machine_guid        {id.MachineGuid}");
        text.AppendLine($"product_id          {id.ProductId}");
        text.AppendLine($"cpu_brand           {id.CpuBrandString}");
        text.AppendLine($"smbios_uuid         {id.SmbiosSystemUuid}");
        text.AppendLine($"bios_vendor         {id.BiosVendor}");
        text.AppendLine($"bios_version        {id.BiosVersion}");
        text.AppendLine($"gpu_ven_dev         0x{id.GpuVenDev:X8}");
        text.AppendLine($"toggles             0x{id.Toggles:X8}");
        await File.WriteAllTextAsync(side, text.ToString()).ConfigureAwait(false);
    }

    // --- PE checksum via ImageHlp!CheckSumMappedFile ---

    [DllImport("imagehlp.dll", SetLastError = true, ExactSpelling = true)]
    private static extern IntPtr CheckSumMappedFile(
        IntPtr baseAddress,
        uint fileLength,
        out uint headerSum,
        out uint checkSum);

    private static void RecomputePeChecksum(byte[] image)
    {
        if (image.Length < 0x100) return;

        var handle = GCHandle.Alloc(image, GCHandleType.Pinned);
        try
        {
            var p = handle.AddrOfPinnedObject();
            var r = CheckSumMappedFile(p, (uint)image.Length, out _, out var newSum);
            if (r == IntPtr.Zero) return; // Not a PE. Leave bytes alone.

            // Locate PE header: offset 0x3C holds e_lfanew.
            var peOff = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C, 4));
            if (peOff < 0 || peOff + 0x58 > image.Length) return;
            // CheckSum field is at Optional Header offset 0x40, Optional
            // Header starts at peOff + 0x18 (signature + file header).
            var checkOff = peOff + 0x58;
            BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(checkOff, 4), newSum);
        }
        finally
        {
            handle.Free();
        }
    }
}
