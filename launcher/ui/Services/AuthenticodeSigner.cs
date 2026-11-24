using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace TheChamber.Services;

/// <summary>
/// Minimal Authenticode re-signer for the launcher. The embedded driver
/// images come out of resources Authenticode-signed with the Chamber dev
/// cert; the moment <see cref="CfgPatcher"/> patches the 632-byte CFG
/// blob or re-checksums the PE header, that signature is invalidated and
/// Windows CI rejects the driver at <c>NtLoadDriver</c> time. This class
/// re-signs the patched file in place with the same cert.
///
/// The signing cert is a self-signed ECDSA / RSA code-signing cert whose
/// Subject is literally <b>The Chamber</b>. It is never any real vendor's
/// name. The cert is cached at
/// <c>%ProgramData%\TheChamber\cert\the_chamber.pfx</c> and generated via
/// <see cref="CertificateRequest"/> (which wraps
/// <c>CertCreateSelfSignCertificate</c>) on first run; subsequent runs
/// reuse the cached cert so a given operator machine stays on the same
/// chain across re-seeds.
///
/// The PFX password is a fixed per-install string. The private key is
/// only usable with admin on this machine (the launcher runs elevated)
/// so a more elaborate secret store buys little here; the cert is a
/// local test-signing cert, not a production code-signing identity.
/// </summary>
public sealed class AuthenticodeSigner
{
    /// <summary>
    /// Subject common name for every cert this class generates. Must stay
    /// literally "The Chamber" — the cert never impersonates Microsoft,
    /// Intel, AMD, Realtek, or any real vendor.
    /// </summary>
    public const string CertSubjectCommonName = "The Chamber";

    private const string PfxPassword = "the-chamber";

    public string CertDirectory { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "TheChamber",
        "cert");

    public string PfxPath => Path.Combine(CertDirectory, "the_chamber.pfx");

    /// <summary>
    /// Load the cached cert, or materialize one from a build-time
    /// embedded resource, or generate a fresh one, in that order. Also
    /// recovers if a cached PFX is present but corrupted by falling
    /// through. Returns the live cert.
    /// </summary>
    public X509Certificate2 LoadOrCreateCert()
    {
        Directory.CreateDirectory(CertDirectory);

        // 1. Cached cert from an earlier run on this box.
        if (File.Exists(PfxPath))
        {
            try
            {
                // X509KeyStorageFlags.MachineKeySet keeps the private key
                // under the local machine profile so a different admin can
                // still re-sign on the same install. Exportable so the
                // user can inspect / extract the cert if they want to.
                return new X509Certificate2(
                    PfxPath,
                    PfxPassword,
                    X509KeyStorageFlags.MachineKeySet |
                    X509KeyStorageFlags.PersistKeySet |
                    X509KeyStorageFlags.Exportable);
            }
            catch (CryptographicException)
            {
                // Fall through to resource / regenerate.
            }
        }

        // 2. Embedded PFX resource: the release pipeline signs the
        //    embedded .sys / .dll blobs with recovery\the_chamber_sign.pfx
        //    and embeds the matching cer public portion in the launcher
        //    so a run-time re-sign uses the same chain. If the private
        //    PFX itself was ever embedded (the project currently embeds
        //    only the .cer), it lives at logical name
        //    TheChamber.Certs.the_chamber.pfx -- cache it and return.
        var asm = Assembly.GetExecutingAssembly();
        using (var s = asm.GetManifestResourceStream("TheChamber.Certs.the_chamber.pfx"))
        {
            if (s is not null)
            {
                using var ms = new MemoryStream();
                s.CopyTo(ms);
                var embeddedPfxBytes = ms.ToArray();
                try
                {
                    var embeddedCert = new X509Certificate2(
                        embeddedPfxBytes,
                        PfxPassword,
                        X509KeyStorageFlags.MachineKeySet |
                        X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable);
                    // Cache so later runs skip the resource path.
                    File.WriteAllBytes(PfxPath, embeddedPfxBytes);
                    return embeddedCert;
                }
                catch (CryptographicException)
                {
                    // Embedded resource malformed; fall through.
                }
            }
        }

        // 3. Fresh self-signed cert. 2048-bit RSA / SHA-256 / 5-year
        //    validity. CertificateRequest ultimately calls the same
        //    Crypto Next Gen API that CertCreateSelfSignCertificate
        //    sits on top of.
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            $"CN={CertSubjectCommonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        // Mark as code-signing + non-CA. Enhanced Key Usage
        // 1.3.6.1.5.5.7.3.3 is the standard "Code Signing" OID.
        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.3") },
                true));
        req.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(req.PublicKey, false));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = DateTimeOffset.UtcNow.AddYears(5);
        using var cert = req.CreateSelfSigned(notBefore, notAfter);

        var pfxBytes = cert.Export(X509ContentType.Pfx, PfxPassword);
        File.WriteAllBytes(PfxPath, pfxBytes);
        // The returned cert must have its private key accessible for
        // signing; re-import from the PFX bytes so the key handle lives
        // inside the standard machine key set.
        return new X509Certificate2(
            pfxBytes,
            PfxPassword,
            X509KeyStorageFlags.MachineKeySet |
            X509KeyStorageFlags.PersistKeySet |
            X509KeyStorageFlags.Exportable);
    }

    /// <summary>
    /// Sign <paramref name="filePath"/> in place with the cached cert via
    /// Mssign32!SignerSignEx2. The file must be a valid PE (driver or
    /// shim DLL); other formats are rejected by the signer. On a signed
    /// file, this call replaces the existing Authenticode signature
    /// rather than appending.
    /// </summary>
    public async Task SignAsync(string filePath, CancellationToken ct = default)
    {
        if (!File.Exists(filePath))
        {
            throw new FileNotFoundException("Nothing to sign.", filePath);
        }

        using var cert = LoadOrCreateCert();
        await Task.Run(() => SignCore(filePath, cert), ct).ConfigureAwait(false);
    }

    private static void SignCore(string filePath, X509Certificate2 cert)
    {
        // SignerSignEx2 is the only documented API that signs without
        // needing signtool.exe on the operator's PATH. The structures are
        // in Mssign32.dll; the signatures are documented in the Windows
        // SDK header <mssign.h>. We only wire the SHA-256 code-signing
        // path because that is the only shape the Chamber drivers use.
        var subjectFile = new SIGNER_FILE_INFO
        {
            cbSize = (uint)Marshal.SizeOf<SIGNER_FILE_INFO>(),
            pwszFileName = filePath,
            hFile = IntPtr.Zero,
        };
        var pSubjectFile = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(subjectFile, pSubjectFile, false);

            var subjectInfo = new SIGNER_SUBJECT_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_SUBJECT_INFO>(),
                pdwIndex = Marshal.AllocHGlobal(sizeof(uint)),
                dwSubjectChoice = SIGNER_SUBJECT_FILE,
                union = pSubjectFile,
            };
            Marshal.WriteInt32(subjectInfo.pdwIndex, 0);

            // Build the certificate store wrapper. SignerSignEx2 wants a
            // SIGNER_CERT with the cert handle inside a SIGNER_CERT_STORE_INFO.
            var certStoreInfo = new SIGNER_CERT_STORE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_CERT_STORE_INFO>(),
                pSigningCert = cert.Handle,
                dwCertPolicy = SIGNER_CERT_POLICY_CHAIN,
                hCertStore = IntPtr.Zero,
            };
            var pCertStoreInfo = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_CERT_STORE_INFO>());
            Marshal.StructureToPtr(certStoreInfo, pCertStoreInfo, false);

            var signerCert = new SIGNER_CERT
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_CERT>(),
                dwCertChoice = SIGNER_CERT_STORE,
                union = pCertStoreInfo,
                hwnd = IntPtr.Zero,
            };
            var pSignerCert = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_CERT>());
            Marshal.StructureToPtr(signerCert, pSignerCert, false);

            // SIGNER_ATTR_AUTHCODE gets us an Authenticode (PE)
            // signature; SignerSignEx2 refuses PE files with any other
            // attribute shape.
            var authcode = new SIGNER_ATTR_AUTHCODE
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_ATTR_AUTHCODE>(),
                fCommercial = 0,
                fIndividual = 1,
                pwszName = IntPtr.Zero,
                pwszInfo = IntPtr.Zero,
            };
            var pAuthcode = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_ATTR_AUTHCODE>());
            Marshal.StructureToPtr(authcode, pAuthcode, false);

            var signatureInfo = new SIGNER_SIGNATURE_INFO
            {
                cbSize = (uint)Marshal.SizeOf<SIGNER_SIGNATURE_INFO>(),
                algidHash = 0, // unused with pszObjId
                dwAttrChoice = SIGNER_AUTHCODE_ATTR,
                union = pAuthcode,
                psAuthenticated = IntPtr.Zero,
                psUnauthenticated = IntPtr.Zero,
                pszObjId = Marshal.StringToHGlobalAnsi("2.16.840.1.101.3.4.2.1"), // SHA-256
            };
            var pSignatureInfo = Marshal.AllocHGlobal(Marshal.SizeOf<SIGNER_SIGNATURE_INFO>());
            Marshal.StructureToPtr(signatureInfo, pSignatureInfo, false);

            try
            {
                var hr = SignerSignEx2(
                    dwFlags: 0,
                    pSubjectInfo: ref subjectInfo,
                    pSignerCert: pSignerCert,
                    pSignatureInfo: pSignatureInfo,
                    pProviderInfo: IntPtr.Zero,
                    dwTimestampFlags: 0,
                    pszTimestampAlgorithmOid: IntPtr.Zero,
                    pwszHttpTimeStamp: IntPtr.Zero,
                    psRequest: IntPtr.Zero,
                    pSipData: IntPtr.Zero,
                    ppSignerContext: out _,
                    pCryptoPolicy: IntPtr.Zero,
                    pReserved: IntPtr.Zero);

                if (hr != 0)
                {
                    // 0x800B0100 = NTE_BAD_SIGNATURE and friends;
                    // Marshal.GetExceptionForHR surfaces a readable
                    // message. Error cases are mostly: missing cert
                    // private key, unsupported file layout, invalid
                    // flags. None of these should fire in steady state.
                    throw Marshal.GetExceptionForHR(hr)
                        ?? new CryptographicException($"SignerSignEx2 failed 0x{hr:X8}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(pAuthcode);
                Marshal.FreeHGlobal(pSignatureInfo);
                Marshal.FreeHGlobal(pCertStoreInfo);
                Marshal.FreeHGlobal(pSignerCert);
                Marshal.FreeHGlobal(subjectInfo.pdwIndex);
                Marshal.FreeHGlobal(signatureInfo.pszObjId);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pSubjectFile);
        }
    }

    // ------- mssign32 interop -------

    private const uint SIGNER_SUBJECT_FILE = 1;
    private const uint SIGNER_CERT_STORE = 2;
    private const uint SIGNER_CERT_POLICY_CHAIN = 2;
    private const uint SIGNER_AUTHCODE_ATTR = 1;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SIGNER_FILE_INFO
    {
        public uint cbSize;
        public string pwszFileName;
        public IntPtr hFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SIGNER_SUBJECT_INFO
    {
        public uint cbSize;
        public IntPtr pdwIndex;
        public uint dwSubjectChoice;
        public IntPtr union;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SIGNER_CERT_STORE_INFO
    {
        public uint cbSize;
        public IntPtr pSigningCert;
        public uint dwCertPolicy;
        public IntPtr hCertStore;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SIGNER_CERT
    {
        public uint cbSize;
        public uint dwCertChoice;
        public IntPtr union;
        public IntPtr hwnd;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SIGNER_ATTR_AUTHCODE
    {
        public uint cbSize;
        public int fCommercial;
        public int fIndividual;
        public IntPtr pwszName;
        public IntPtr pwszInfo;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SIGNER_SIGNATURE_INFO
    {
        public uint cbSize;
        public uint algidHash;
        public uint dwAttrChoice;
        public IntPtr union;
        public IntPtr psAuthenticated;
        public IntPtr psUnauthenticated;
        public IntPtr pszObjId;
    }

    [DllImport("mssign32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern int SignerSignEx2(
        uint dwFlags,
        ref SIGNER_SUBJECT_INFO pSubjectInfo,
        IntPtr pSignerCert,
        IntPtr pSignatureInfo,
        IntPtr pProviderInfo,
        uint dwTimestampFlags,
        IntPtr pszTimestampAlgorithmOid,
        IntPtr pwszHttpTimeStamp,
        IntPtr psRequest,
        IntPtr pSipData,
        out IntPtr ppSignerContext,
        IntPtr pCryptoPolicy,
        IntPtr pReserved);
}
