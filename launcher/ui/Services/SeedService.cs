using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using TheChamber.Model;

namespace TheChamber.Services;

/// <summary>
/// Owns the 32-byte master seed that drives every seed-derived identity
/// field in the system. The seed is persisted to
/// <c>%AppData%\TheChamber\seed.bin</c> under DPAPI (CurrentUser scope) so
/// a given Windows profile sees the same identity across reboots and
/// re-launches. The seed only re-rolls when the user clicks "Randomize
/// seed" in the UI; `LoadOrCreateAsync` never re-rolls on its own.
///
/// The derive() function mirrors the C implementation in
/// <c>driver/crypt.c</c> byte-for-byte: SHA-256 over <c>seed || field</c>
/// for outlen &lt;= 32, chained with the literal ASCII continuation tag
/// "continue" for longer expansions. SHA-256 here is the .NET 8 CNG
/// provider, which is a thin wrapper around BCrypt's
/// <c>BCRYPT_SHA256_ALGORITHM</c>.
/// </summary>
public sealed class SeedService
{
    // File format v1 (plaintext, pre-DPAPI):
    //   magic    : 4 bytes "CHSD"
    //   version  : u32 = 1
    //   seed     : 32 bytes
    //   id_salt  : u32  (machine-identity group salt)
    //   hv_salt  : u32  (HV-identity group salt)
    //   toggles  : u32  (CHAMBER_CFG_V2.toggles)
    // Total 52 bytes plaintext, DPAPI-wrapped on disk.
    private const uint MagicBytes = 0x44534843; // 'CHSD' little-endian
    private const uint FormatVersion = 1;
    private const int SeedLen = 32;
    private const int PlaintextLen = 4 + 4 + SeedLen + 4 + 4 + 4;

    private static readonly byte[] ContinueTag = Encoding.ASCII.GetBytes("continue");

    private byte[] _seed = new byte[SeedLen];
    private uint _identitySalt;
    private uint _hvSalt;

    /// <summary>
    /// Toggle bitfield, preserved across sessions. Bit layout matches
    /// CHAMBER_CFG_V2.toggles exactly.
    /// </summary>
    public uint Toggles { get; set; } =
        (1u << 0)                  // ci_state_spoof
        | (1u << 1)                // machine_identity_spoof
        | (1u << 3) | (1u << 4) | (1u << 5)
        | (1u << 6) | (1u << 7) | (1u << 8) // all six pool-tag randomize bits
        | (1u << 9);               // tpm_absent_spoof

    public string SeedHex => Convert.ToHexString(_seed);

    public uint IdentitySalt => _identitySalt;
    public uint HvSalt => _hvSalt;

    public string StatePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "TheChamber",
        "seed.bin");

    public async Task LoadOrCreateAsync()
    {
        try
        {
            if (File.Exists(StatePath))
            {
                var wrapped = await File.ReadAllBytesAsync(StatePath).ConfigureAwait(false);
                var plain = DpapiUnprotect(wrapped);
                if (TryDeserialize(plain))
                {
                    return;
                }
            }
        }
        catch (CryptographicException)
        {
            // Profile change or corrupt blob: fall through to fresh seed.
        }
        catch (IOException)
        {
        }

        // First-run or unrecoverable blob -> fresh seed. This is the only
        // path that mints a new seed automatically, and it only runs when
        // there is nothing on disk; a user re-roll is the only other mint.
        Randomize();
        await SaveAsync().ConfigureAwait(false);
    }

    public async Task SaveAsync()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(StatePath)!);
        var plain = Serialize();
        var wrapped = DpapiProtect(plain);
        var tmp = StatePath + ".tmp";
        await File.WriteAllBytesAsync(tmp, wrapped).ConfigureAwait(false);
        // atomic replace so a crash during write leaves the previous blob
        // intact; otherwise a half-written seed.bin wipes the identity.
        File.Move(tmp, StatePath, overwrite: true);
    }

    /// <summary>
    /// Mint a fresh 32-byte seed from the OS CSPRNG, reset group salts.
    /// Call ONLY on explicit "Randomize all" user action.
    /// </summary>
    public void Randomize()
    {
        RandomNumberGenerator.Fill(_seed);
        _identitySalt = 0;
        _hvSalt = 0;
    }

    public void BumpIdentitySalt() => _identitySalt++;
    public void BumpHvSalt() => _hvSalt++;

    /// <summary>
    /// Overwrite the master seed from a 64-char hex string; resets both
    /// group salts to zero (an external seed carries no salt history).
    /// Returns false if <paramref name="hex"/> is not exactly 32 bytes.
    /// </summary>
    public bool SetSeedHex(string hex)
    {
        if (hex is null || hex.Length != 64) return false;
        byte[] parsed;
        try { parsed = Convert.FromHexString(hex); }
        catch (FormatException) { return false; }
        if (parsed.Length != SeedLen) return false;
        Array.Copy(parsed, _seed, SeedLen);
        _identitySalt = 0;
        _hvSalt = 0;
        return true;
    }

    /// <summary>
    /// Pure derive: out = SHA256(seed || field) truncated/extended with
    /// chained SHA256(h_i || "continue") to outlen bytes.
    /// </summary>
    public void Derive(string field, Span<byte> outbuf)
    {
        var fieldBytes = Encoding.ASCII.GetBytes(field);
        DeriveRaw(_seed, fieldBytes, outbuf);
    }

    /// <summary>
    /// Group-salted derive: the ASCII field name sent into SHA-256 is
    /// <c>"g1:{group}.{salt}:{field}"</c> exactly, matching
    /// <c>derive_g()</c> in the design doc Section 4.4.
    /// </summary>
    public void DeriveGroup(string group, uint salt, string field, Span<byte> outbuf)
    {
        var composed = $"g1:{group}.{salt}:{field}";
        Derive(composed, outbuf);
    }

    private static void DeriveRaw(ReadOnlySpan<byte> seed, ReadOnlySpan<byte> field, Span<byte> outbuf)
    {
        Span<byte> h = stackalloc byte[32];

        // h0 = SHA256(seed || field)
        var buf = new byte[seed.Length + field.Length];
        seed.CopyTo(buf);
        field.CopyTo(buf.AsSpan(seed.Length));
        SHA256.HashData(buf, h);

        int written = 0;
        while (written < outbuf.Length)
        {
            var take = Math.Min(32, outbuf.Length - written);
            h.Slice(0, take).CopyTo(outbuf.Slice(written, take));
            written += take;
            if (written >= outbuf.Length)
            {
                break;
            }
            // h_{i+1} = SHA256(h_i || "continue")
            var chain = new byte[32 + ContinueTag.Length];
            h.CopyTo(chain);
            ContinueTag.CopyTo(chain.AsSpan(32));
            SHA256.HashData(chain, h);
        }
    }

    /// <summary>
    /// Expand the seed into every CHAMBER_CFG v2 field and cache the result
    /// in a <see cref="DerivedIdentity"/>. Pure; no side-effects.
    /// </summary>
    public DerivedIdentity DeriveAll()
    {
        var d = new DerivedIdentity();

        // Copy the master seed into the derived identity so CfgPatcher can
        // write it into CHAMBER_CFG_V2.seed[32]. The HV's identity_apply
        // derives CPU identity from that slot directly.
        d.Seed = (byte[])_seed.Clone();

        // --- HV identity (group "hv") ---
        d.ServiceName = DeriveServiceName();
        d.DeviceSuffix = DeriveDeviceSuffix();
        d.PoolTags = DerivePoolTags();
        d.VmmcallMagic = DeriveU64("hv", _hvSalt, "vmmcall_magic");
        d.CfgMagicOverride = DeriveU64("hv", _hvSalt, "cfg_magic_override");
        d.RenameDonorIndex = (byte)(DeriveU32("hv", _hvSalt, "rename_donor") % (uint)DonorPool.Length);
        d.GuestAsid = 0x1000u + (DeriveU32("hv", _hvSalt, "guest_asid") & 0x6FFFu);
        d.SectionScrambleSeed = DeriveU32("hv", _hvSalt, "section_scramble");
        d.DriverNonce = DeriveU64("hv", _hvSalt, "driver_nonce");

        // --- Machine identity (group "identity") ---
        d.ComputerName = DeriveComputerName();
        d.MachineGuid = DeriveGuidV4("identity", _identitySalt, "machine_guid");
        d.InstallDateFiletime = DeriveInstallDateFiletime();
        d.ProductId = DeriveProductId();
        d.DigitalProductId = DeriveDigitalProductId();
        d.CpuBrandString = DeriveCpuBrand();
        d.SmbiosSystemUuid = DeriveGuidV4("identity", _identitySalt, "smbios_uuid");
        d.BaseboardSerial = DeriveSerial("baseboard_serial");
        d.ChassisSerial = DeriveSerial("chassis_serial");
        d.BiosVendor = DerivePick("bios_vendor", BiosVendors);
        d.BiosVersion = DeriveBiosVersion();
        d.MacAddresses = DeriveMacs();
        d.DiskSerials = DeriveDiskSerials();
        d.VolumeSerials = DeriveVolumeSerials();
        d.GpuVenDev = DerivePickU32("gpu_ven_dev", GpuVenDevPool);
        d.EdidNonce = DeriveBytes("identity", _identitySalt, "edid_nonce", 16);

        d.Toggles = Toggles;
        return d;
    }

    // --- Field formatters, verbatim per design Section 4.3 ---

    private string DeriveServiceName()
    {
        Span<byte> raw = stackalloc byte[16];
        DeriveGroup("hv", _hvSalt, "service_name", raw);
        var cs = "abcdefghijklmnopqrstuvwxyz";
        var cs2 = "abcdefghijklmnopqrstuvwxyz0123456789";
        var sb = new StringBuilder(12);
        sb.Append(cs[raw[0] % cs.Length]);
        for (int i = 1; i < 8; i++)
        {
            sb.Append(cs2[raw[i] % cs2.Length]);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Independent service name for the second (fingerprint) driver.
    /// Derived from the same master seed under a distinct field so the two
    /// services never collide, and so a seed re-roll changes both names
    /// together. The alphabet matches <see cref="DeriveServiceName"/>.
    /// Exposed because <c>App.xaml.cs</c> hands it directly to
    /// <see cref="DriverLoader.InstallAndLoadFingerprintAsync"/>; nothing
    /// else should need it.
    /// </summary>
    public string DeriveFingerprintServiceName()
    {
        Span<byte> raw = stackalloc byte[16];
        DeriveGroup("hv", _hvSalt, "fp_service_name", raw);
        var cs = "abcdefghijklmnopqrstuvwxyz";
        var cs2 = "abcdefghijklmnopqrstuvwxyz0123456789";
        var sb = new StringBuilder(12);
        sb.Append(cs[raw[0] % cs.Length]);
        for (int i = 1; i < 8; i++)
        {
            sb.Append(cs2[raw[i] % cs2.Length]);
        }
        return sb.ToString();
    }

    private string DeriveDeviceSuffix()
    {
        Span<byte> raw = stackalloc byte[16];
        DeriveGroup("hv", _hvSalt, "device_suffix", raw);
        var cs = "abcdefghijklmnopqrstuvwxyz";
        var cs2 = "abcdefghijklmnopqrstuvwxyz0123456789";
        var sb = new StringBuilder(10);
        sb.Append(cs[raw[0] % cs.Length]);
        for (int i = 1; i < 10; i++)
        {
            sb.Append(cs2[raw[i] % cs2.Length]);
        }
        return sb.ToString();
    }

    private uint[] DerivePoolTags()
    {
        var names = new[] { "svm", "npt", "vmexit", "dump", "integrity", "dispatch" };
        var tags = new uint[6];
        for (int i = 0; i < 6; i++)
        {
            Span<byte> raw = stackalloc byte[8];
            DeriveGroup("hv", _hvSalt, $"pool_tag_{names[i]}", raw);
            // 4 ASCII [A-Za-z] bytes packed little-endian.
            var letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
            uint v = 0;
            for (int j = 0; j < 4; j++)
            {
                v |= (uint)letters[raw[j] % letters.Length] << (8 * j);
            }
            tags[i] = v;
        }
        return tags;
    }

    private string DeriveComputerName()
    {
        Span<byte> raw = stackalloc byte[16];
        DeriveGroup("identity", _identitySalt, "computer_name", raw);
        const string cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var sb = new StringBuilder(15);
        for (int i = 0; i < 15; i++)
        {
            sb.Append(cs[raw[i] % cs.Length]);
        }
        return sb.ToString();
    }

    private Guid DeriveGuidV4(string group, uint salt, string field)
    {
        Span<byte> raw = stackalloc byte[16];
        DeriveGroup(group, salt, field, raw);
        raw[6] = (byte)(0x40 | (raw[6] & 0x0F));
        raw[8] = (byte)(0x80 | (raw[8] & 0x3F));
        return new Guid(raw);
    }

    private long DeriveInstallDateFiletime()
    {
        Span<byte> raw = stackalloc byte[8];
        DeriveGroup("identity", _identitySalt, "install_date", raw);
        var r = BinaryPrimitives.ReadUInt64LittleEndian(raw);
        // FILETIME for [2019-01-01, 2024-01-01].
        var lo = new DateTime(2019, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
        var hi = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc).ToFileTimeUtc();
        var span = (ulong)(hi - lo);
        return lo + (long)(r % span);
    }

    private string DeriveProductId()
    {
        Span<byte> raw = stackalloc byte[32];
        DeriveGroup("identity", _identitySalt, "product_id", raw);
        const string cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var sb = new StringBuilder(23);
        for (int i = 0; i < 20; i++)
        {
            if (i == 5 || i == 10 || i == 15)
            {
                sb.Append('-');
            }
            sb.Append(cs[raw[i] % cs.Length]);
        }
        return sb.ToString();
    }

    private byte[] DeriveDigitalProductId()
    {
        var buf = new byte[164];
        DeriveGroup("identity", _identitySalt, "digital_product_id", buf);
        // Last 4 bytes = CRC32 over the preceding 160 for a plausible DPID.
        var crc = Crc32(buf.AsSpan(0, 160));
        BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(160, 4), crc);
        return buf;
    }

    private string DeriveCpuBrand()
    {
        Span<byte> raw = stackalloc byte[4];
        DeriveGroup("identity", _identitySalt, "cpu_brand", raw);
        // Pool is AMD-only by default because the HV sees an AMD host; the
        // Intel brands become selectable when the full feature-flag spoof
        // ships in a future wave.
        var pool = CpuBrandPoolAmd;
        return pool[raw[0] % pool.Length];
    }

    private string DeriveSerial(string field)
    {
        Span<byte> raw = stackalloc byte[16];
        DeriveGroup("identity", _identitySalt, field, raw);
        const string cs = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        var sb = new StringBuilder(12);
        for (int i = 0; i < 12; i++)
        {
            sb.Append(cs[raw[i] % cs.Length]);
        }
        return sb.ToString();
    }

    private string DeriveBiosVersion()
    {
        Span<byte> raw = stackalloc byte[4];
        DeriveGroup("identity", _identitySalt, "bios_version", raw);
        var head = BiosVersions[raw[0] % BiosVersions.Length];
        const string cs = "0123456789ABCDEF";
        return $"{head}{cs[raw[1] % cs.Length]}{cs[raw[2] % cs.Length]}";
    }

    private MacAddress[] DeriveMacs()
    {
        // One derive() per MAC with field "mac_addr_<i>", matching the
        // FID_MAC_ADDR_BASE enum comment in identity.h so Agent C's
        // interceptor arrives at the exact same bytes from the seed.
        var macs = new MacAddress[6];
        for (int i = 0; i < 6; i++)
        {
            Span<byte> raw = stackalloc byte[4];
            DeriveGroup("identity", _identitySalt, $"mac_addr_{i}", raw);
            var o = OuiPool[raw[0] % OuiPool.Length];
            var nic = new byte[3] { raw[1], raw[2], raw[3] };
            macs[i] = new MacAddress(o, nic);
        }
        return macs;
    }

    private string[] DeriveDiskSerials()
    {
        var s = new string[20];
        for (int i = 0; i < 20; i++)
        {
            Span<byte> raw = stackalloc byte[20];
            DeriveGroup("identity", _identitySalt, $"disk_serial_{i}", raw);
            const string cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var sb = new StringBuilder(20);
            for (int j = 0; j < 20; j++)
            {
                sb.Append(cs[raw[j] % cs.Length]);
            }
            s[i] = sb.ToString();
        }
        return s;
    }

    private uint[] DeriveVolumeSerials()
    {
        var v = new uint[4];
        for (int i = 0; i < 4; i++)
        {
            Span<byte> raw = stackalloc byte[4];
            DeriveGroup("identity", _identitySalt, $"volume_serial_{i}", raw);
            v[i] = BinaryPrimitives.ReadUInt32LittleEndian(raw);
        }
        return v;
    }

    private uint DeriveU32(string group, uint salt, string field)
    {
        Span<byte> raw = stackalloc byte[4];
        DeriveGroup(group, salt, field, raw);
        return BinaryPrimitives.ReadUInt32LittleEndian(raw);
    }

    private ulong DeriveU64(string group, uint salt, string field)
    {
        Span<byte> raw = stackalloc byte[8];
        DeriveGroup(group, salt, field, raw);
        return BinaryPrimitives.ReadUInt64LittleEndian(raw);
    }

    private byte[] DeriveBytes(string group, uint salt, string field, int n)
    {
        var raw = new byte[n];
        DeriveGroup(group, salt, field, raw);
        return raw;
    }

    private string DerivePick(string field, string[] pool)
    {
        Span<byte> raw = stackalloc byte[4];
        DeriveGroup("identity", _identitySalt, field, raw);
        return pool[raw[0] % pool.Length];
    }

    private uint DerivePickU32(string field, uint[] pool)
    {
        Span<byte> raw = stackalloc byte[4];
        DeriveGroup("identity", _identitySalt, field, raw);
        return pool[raw[0] % pool.Length];
    }

    // --- Pools. DonorPool MUST be byte-identical to driver/stealth.c
    //     DONOR_POOL[] because RenameDonorIndex is a single uint8 and the
    //     driver indexes its own pool by the same number. The prior
    //     user-mode-exe names (winlogon.sys, lsass.sys, ...) resolved to
    //     the wrong donor on the driver side, so the UI showed the
    //     operator a name the sample would never see. These are the real
    //     boot-critical kernel-mode modules. ---
    public static readonly string[] DonorPool =
    {
        "pci.sys", "acpi.sys", "msrpc.sys", "storport.sys",
        "tcpip.sys", "ndis.sys", "disk.sys", "partmgr.sys",
    };

    public static readonly string[] CpuBrandPoolAmd =
    {
        "AMD Ryzen 7 7700X 8-Core Processor",
        "AMD Ryzen 9 7900X 12-Core Processor",
        "AMD Ryzen 9 7950X 16-Core Processor",
        "AMD Ryzen 7 5800X 8-Core Processor",
        "AMD Ryzen 5 5600X 6-Core Processor",
    };

    public static readonly string[] BiosVendors =
    {
        "American Megatrends Inc.",
        "Phoenix Technologies Ltd.",
        "Insyde Corp.",
        "AMI",
        "Award Software International",
    };

    public static readonly string[] BiosVersions =
    {
        "F.27", "2.A1", "1801", "P3.80", "5.17", "F.14",
    };

    public static readonly OuiEntry[] OuiPool =
    {
        new(new byte[] { 0x24, 0x4b, 0xfe }, "ASUSTeK"),
        new(new byte[] { 0xb0, 0x25, 0xaa }, "Dell"),
        new(new byte[] { 0x00, 0x25, 0xb3 }, "HPE"),
        new(new byte[] { 0x18, 0xc0, 0x4d }, "Intel"),
        new(new byte[] { 0x50, 0xeb, 0x71 }, "Realtek"),
        new(new byte[] { 0x74, 0xd4, 0x35 }, "Gigabyte"),
        new(new byte[] { 0x28, 0x80, 0x88 }, "Lenovo"),
        new(new byte[] { 0xa4, 0x1f, 0x72 }, "MSI"),
    };

    public static readonly uint[] GpuVenDevPool =
    {
        0x10DE2684, 0x10DE2782, 0x10DE1E07,
        0x10022208, 0x1002731F, 0x86415690,
    };

    // --- DPAPI + (de)serialization ---

    private byte[] Serialize()
    {
        var plain = new byte[PlaintextLen];
        var s = plain.AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(s, MagicBytes);
        BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(4), FormatVersion);
        _seed.CopyTo(s.Slice(8));
        BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(40), _identitySalt);
        BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(44), _hvSalt);
        BinaryPrimitives.WriteUInt32LittleEndian(s.Slice(48), Toggles);
        return plain;
    }

    private bool TryDeserialize(byte[] plain)
    {
        if (plain.Length < PlaintextLen) return false;
        var s = plain.AsSpan();
        if (BinaryPrimitives.ReadUInt32LittleEndian(s) != MagicBytes) return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(4)) != FormatVersion) return false;
        s.Slice(8, SeedLen).CopyTo(_seed);
        _identitySalt = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(40));
        _hvSalt = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(44));
        Toggles = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(48));
        return true;
    }

    private static byte[] DpapiProtect(byte[] plain) =>
        System.Security.Cryptography.ProtectedData.Protect(
            plain,
            optionalEntropy: Encoding.ASCII.GetBytes("TheChamber.Seed.v1"),
            scope: System.Security.Cryptography.DataProtectionScope.CurrentUser);

    private static byte[] DpapiUnprotect(byte[] wrapped) =>
        System.Security.Cryptography.ProtectedData.Unprotect(
            wrapped,
            optionalEntropy: Encoding.ASCII.GetBytes("TheChamber.Seed.v1"),
            scope: System.Security.Cryptography.DataProtectionScope.CurrentUser);

    // --- Tiny CRC32 (IEEE 802.3) for the DPID tail. Not security-sensitive. ---
    private static readonly uint[] Crc32Table = BuildCrc32Table();

    private static uint[] BuildCrc32Table()
    {
        var t = new uint[256];
        for (uint i = 0; i < 256; i++)
        {
            var c = i;
            for (int k = 0; k < 8; k++)
            {
                c = ((c & 1) != 0) ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
            }
            t[i] = c;
        }
        return t;
    }

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint c = 0xFFFFFFFF;
        foreach (var b in data)
        {
            c = Crc32Table[(c ^ b) & 0xFF] ^ (c >> 8);
        }
        return c ^ 0xFFFFFFFF;
    }
}

public readonly record struct OuiEntry(byte[] Bytes, string Vendor);

public readonly record struct MacAddress(OuiEntry Oui, byte[] Nic)
{
    public string Pretty() =>
        $"{Oui.Bytes[0]:X2}-{Oui.Bytes[1]:X2}-{Oui.Bytes[2]:X2}-" +
        $"{Nic[0]:X2}-{Nic[1]:X2}-{Nic[2]:X2}";
}
