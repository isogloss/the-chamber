# Phase 9 -- Operational Discipline

Operating THE_CHAMBER as a malware-analysis sandbox demands that the physical
environment, the storage layout, the network, the debugger topology, the
source tree and the synthetic-value documentation all stay disciplined.  A
hypervisor that spoofs CPUID / MSR fields is only as credible as the
operational hygiene around it.  This document is the running checklist a
one-person lab follows before, during and after every analysis session.

Scope: Ryzen 7 7700X (Zen 4, family 19h) on AM5.  Windows 11 host.  Analysis
targets: Themida, VMProtect, Enigma, custom crypters.  No network-capable
anti-cheat (Vanguard, EAC-online, BattlEye-online) -- see `ceilings.md`
section 10.3.

## 9.1 Hardware isolation

A dedicated analysis box is not optional.  Shared machines leak side-channels
through browser cache, pagefile residue, prefetch, and every cloud-sync
agent that logs file hashes.

### 9.1.1 Minimum recommended specs

| Component | Minimum | Reason |
|-----------|---------|--------|
| CPU | Ryzen 7 7700X (Zen 4, 8C/16T, family 19h model 61h) | Matches HV target silicon; TSC invariant across cores. |
| Motherboard | AM5 with discrete AMI or Insyde UEFI | Needs an exposed "SVM Mode" or "AMD Virtualization" toggle in the CBS menu. Low-end B650 boards hide it. |
| RAM | 32 GB DDR5 non-ECC minimum, 64 GB preferred | Guest + VM memory dumps + WinDbg symbols concurrently. |
| OS SSD | Dedicated 500 GB+ NVMe for the Windows install, separate from any data drive | Allows `dd`-level baseline clone without touching unrelated partitions. |
| Discrete GPU | Any PCIe card with at least one display output | Lets SMT and iGPU be disabled in BIOS without losing display. 7700X integrated graphics are RDNA2; keep a dGPU so BIOS experiments don't blind the console. |
| Chassis | Case with front USB disabled or physically covered | Prevents accidental USB insertion mid-session. |

### 9.1.2 AMD BIOS settings that matter

Enter BIOS, navigate `Advanced -> AMD CBS -> CPU Common Options`.  Document
each setting value in a per-box config file (`audit/box_<serial>_bios.txt`)
before any snapshotting:

- `SVM Mode` = `Enabled`.  Required for VMRUN to succeed; without it the
  first VMRUN raises #UD and the driver bails.
- `IOMMU` = `Enabled`.  Required if nested paging ever uses device
  isolation; harmless if left on even when the HV does not use the IOMMU.
- `Core Performance Boost` (CPB) = experiment-dependent.  Boost on produces
  variable RDTSC rates that make bare-metal expectations noisier; some
  probes cite "TSC is invariant but APERF/MPERF drift" as a VM tell.  For
  a first baseline run with CPB off (pinned base clock); for later
  correctness checks run with CPB on.  Record which was used.
- `Simultaneous Multi-Threading` (SMT) = experiment-dependent.  SMT off
  halves logical CPUs and therefore halves the per-CPU VMCB count.  Some
  loaders probe `GetLogicalProcessorInformation` for sibling-pair layout;
  running with SMT in both positions during probe-battery testing proves
  the HV handles both.
- `Global C-state Control` = `Enabled`.  Disabling it changes idle MSR
  behavior and creates a bare-metal tell.
- `Secure Boot` = `Disabled`.  Required for the self-signed driver cert at
  `recovery\the_chamber_test.pfx` to load.  Record this in the box config;
  if any future experiment demands Secure Boot on, the driver cert must be
  swapped first.
- `TPM Device Selection` = whatever the box physically has (fTPM for a
  bare 7700X).  Do not disable -- a missing TPM is itself a VM tell.
- `AMD Memory Guard` / `Transparent SME` = `Disabled` for the first
  baseline, `Enabled` for later encrypted-memory experiments.  Flag in box
  config.

### 9.1.3 No personal use

The analysis box must not host:

- any email client (Outlook, Thunderbird),
- any browser used for personal accounts (keep Firefox portable for
  research only -- see 9.3.5),
- any cloud-sync client (OneDrive, iCloud, Dropbox, Google Drive, pCloud,
  Mega) -- they hash every new file and phone the hash home,
- any gaming or chat clients (Steam, Discord, Battle.net),
- any "optimization" or "driver updater" software, which polls hardware
  IDs and uploads them.

### 9.1.4 Minimal toolchain

Install only these, in this order, on the baseline image:

1. Windows 11 24H2 clean install from an offline USB (download the ISO on a
   different machine, verify the Microsoft SHA-256, make the USB with
   `Rufus` or `dd` from a Linux curator box -- see 9.2.4).
2. Latest WDK that matches the SDK version used to build the driver
   (current: WDK 10.0.26100.x; see `tools\install_wdk.ps1`).
3. Visual Studio 2022 Build Tools with only the C++ workload + Windows
   Driver Kit integration.
4. WinDbg Preview (store app) + the matching `windbg` classic from WDK --
   Preview for triage, classic for remote kd.
5. One reversing suite.  Pick one, not several: IDA Pro (preferred for Zen
   4 disassembly accuracy), Binary Ninja, or Ghidra.  Multiple reversing
   suites increase attack surface and complicate the baseline.

No other software.  Not `7-Zip` with shell integration (use the command-line
`7za.exe` only), not `Notepad++` (use `notepad.exe`), not `Process Hacker`
(use kernel debugger and `livekd` instead -- a userland tool that reads
every process is itself a detection vector some loaders flag on).

### 9.1.5 Reproducible clean baseline

After the Windows install + the tools in 9.1.4, before any analysis work:

```powershell
# Record a baseline manifest. Run as elevated PowerShell.
$manifestDir = "C:\baseline"
New-Item -ItemType Directory -Force $manifestDir | Out-Null

# Installed drivers
driverquery /V /FO CSV > "$manifestDir\drivers.csv"

# Installed services
Get-Service | Select-Object Name, DisplayName, Status, StartType |
    Export-Csv -NoTypeInformation "$manifestDir\services.csv"

# Running processes at idle
Get-Process | Select-Object Name, Id, Path |
    Export-Csv -NoTypeInformation "$manifestDir\processes.csv"

# Scheduled tasks
Get-ScheduledTask | Select-Object TaskName, TaskPath, State |
    Export-Csv -NoTypeInformation "$manifestDir\scheduled_tasks.csv"

# Patch level
Get-HotFix | Export-Csv -NoTypeInformation "$manifestDir\hotfixes.csv"

# Firmware version
(Get-CimInstance Win32_BIOS) | Format-List * > "$manifestDir\bios.txt"

# SMBIOS
Get-CimInstance Win32_ComputerSystem | Format-List * > "$manifestDir\system.txt"

# Patch Guard / Secure Boot / Test Mode state
bcdedit /enum > "$manifestDir\bcdedit.txt"

# Pentest baseline (uses the existing suite)
C:\THE_CHAMBER\pentest\run_all.ps1 -Label baseline_clean
Copy-Item -Recurse C:\THE_CHAMBER\pentest\reports\*baseline_clean* $manifestDir\
```

Commit the contents of `C:\baseline` to a private git repo on the curator
box (see 9.2.4).  Every subsequent baseline rebuild gets diffed against
this manifest; a new `.sys` in `drivers.csv` that you did not install is a
red flag before any sample work starts.

### 9.1.6 Known-good snapshot of the base install

Two viable paths.  Pick one and stick to it per box.

**Path A -- Hyper-V differencing disk.**  The analysis workload runs inside
a Generation 2 Hyper-V VM on the 7700X host, with the host serving only as
hypervisor + storage.  THE_CHAMBER driver loads inside the guest; the VMCB
chain becomes nested (Microsoft Hyper-V on L0, THE_CHAMBER on L1, target
on L2).  Nested SVM on Windows Server 2022 / Windows 11 Pro 24H2 host is
documented but has rough edges (see `ceilings.md` 10.3 for why L0 Hyper-V
affects L1 CPUID observations).

Snapshot flow:

```powershell
# One-time: create base.vhdx manually, install Windows + tools into it.
# Make it the parent of a differencing disk.
New-VHD -Path "D:\snapshots\session.avhdx" `
        -ParentPath "D:\snapshots\base.vhdx" `
        -Differencing

# Create the VM against the differencing child.
New-VM -Name "analysis" -MemoryStartupBytes 16GB -Generation 2 `
       -VHDPath "D:\snapshots\session.avhdx"

# Before any session: full-state checkpoint (memory + disk).
Checkpoint-VM -Name "analysis" -SnapshotName "pre_session_$(Get-Date -Format yyyyMMdd_HHmm)"

# After the session: revert, discard the child, recreate a fresh child.
Restore-VMCheckpoint -VMName "analysis" `
                     -Name "pre_session_<timestamp>" `
                     -Confirm:$false
```

**Path B -- `dd`-level clone to a holding drive.**  THE_CHAMBER runs
bare-metal on the 7700X.  A second SSD holds a byte-identical image of the
clean baseline.  After a session, you re-image.

```bash
# Run from a Linux curator USB (see 9.2.4) with both drives attached.
# Identify drives with lsblk; confirm which is baseline-source and which
# is analysis-target before running dd.
lsblk -o NAME,SIZE,MODEL,SERIAL

# Clone baseline -> analysis drive. pv for progress; conv=sync,noerror
# would MASK bad sectors -- do NOT use. If dd aborts, the source has bad
# sectors and must be re-created.
sudo dd if=/dev/disk/by-id/ata-baseline_<serial> \
        of=/dev/disk/by-id/ata-analysis_<serial> \
        bs=4M status=progress

# Verify.
sudo sha256sum /dev/disk/by-id/ata-baseline_<serial> \
               /dev/disk/by-id/ata-analysis_<serial>
# Both hashes must match. If they do not, do not boot the analysis drive.
```

Path B is slower per cycle (30-60 minutes for a 500 GB SSD on SATA, ~10
minutes on NVMe-to-NVMe) but produces a byte-identical replica with no
differencing layer for a target to probe.  Path A is faster but adds a
nested-virtualization layer.

For malware-packer analysis the recommendation is Path B.  The L1
hypervisor should see bare metal below itself; otherwise CPUID /
HV-leaf observations will carry the L0 Hyper-V fingerprint into every
experiment and never match a naive user's box.

## 9.2 Snapshot hygiene

### 9.2.1 Snapshot before every session

Always snapshot before loading a sample.  The snapshot must capture
runtime state (memory) and disk state, because every modern protector
drops residue outside the loader binary:

- Themida writes a machine-specific blob under
  `HKLM\SOFTWARE\<random-GUID-looking-key>` and sometimes under
  `HKCU\Software\<same-key>`.  Older versions used
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\<random>`
  as a cover location.  Keys stay after the loader is deleted.
- VMProtect 3.x drops a scratch file in `%TEMP%\.vmp_<8hex>` and a smaller
  marker in `%LOCALAPPDATA%\Temp\.vmpstate_<8hex>`; 2.x only used
  `%TEMP%`.  These files are deleted on clean exit but persist on crash.
- Enigma Protector 7.x leaves a `HKCU\Software\Enigma Protector` key with
  a last-run timestamp and a 64-byte opaque blob.
- Custom crypters routinely pin to the machine via `GetVolumeInformation`
  VolumeSerialNumber or SMBIOS UUID and refuse to run elsewhere; the
  first run writes a serial-keyed value into a random location (search
  behavior per sample).
- EAC (offline-mode hobby reversing only -- not the live service, which
  is out of scope per `ceilings.md` 10.3) reads but does not primarily
  write; HWIDs are pinned server-side.

Disk-only snapshots will NOT catch these if the write happened then was
deleted but the registry transaction log still contains the ghost.
Memory-and-disk is required.

### 9.2.2 Snapshot commands

**Hyper-V (Path A):**

```powershell
# Pre-session. Note -SnapshotName includes a timestamp AND a sample
# fingerprint (SHA-256 first 8 hex) so the revert target is unambiguous.
$sampleHash = (Get-FileHash -Algorithm SHA256 <sample>.exe).Hash.Substring(0,8)
Checkpoint-VM -Name "analysis" `
              -SnapshotName "pre_$(Get-Date -Format yyMMdd_HHmm)_$sampleHash"

# After session.
Restore-VMCheckpoint -VMName "analysis" `
                     -Name "pre_<timestamp>_<hash>" `
                     -Confirm:$false
```

Hyper-V checkpoints are production-style, i.e. they quiesce the guest via
VSS.  For a malware session you want a standard checkpoint (full memory
state, no VSS cooperation).  Verify:

```powershell
Set-VM -Name "analysis" -CheckpointType Standard
```

**VMware Workstation 17 (alternative, if the shop runs VMware instead of
Hyper-V):**

```powershell
# vmrun.exe is at C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe
& "vmrun.exe" snapshot "D:\vms\analysis\analysis.vmx" "pre_<tag>"
& "vmrun.exe" revertToSnapshot "D:\vms\analysis\analysis.vmx" "pre_<tag>"
& "vmrun.exe" deleteSnapshot  "D:\vms\analysis\analysis.vmx" "post_<tag>"
```

VMware captures memory by default on `snapshot`; no extra switch required.

**Bare metal (Path B):**

Re-image the drive from the clean baseline per 9.1.6 Path B.  There is no
"memory snapshot" for bare metal in this flow; power-cycle resets memory.
If you need memory forensics of the post-run state, capture before reboot
with `winpmem.exe` (a signed userland driver that reads physical memory
via `\\.\pmem`) to the drop-only share described in 9.2.4.

### 9.2.3 Loader-persistence notes to keep near the operator

The analyst has to know what each protector leaves behind in order to
decide if a snapshot is sufficient.  Keep this near the console:

| Protector | On-disk residue | Registry residue | HWID pin |
|-----------|----------------|------------------|---------|
| Themida 3.x | None by default | `HKLM\SOFTWARE\<random-GUID>` | VolumeSerial + SMBIOS UUID |
| VMProtect 3.x | `%TEMP%\.vmp_<8hex>`, `%LOCALAPPDATA%\Temp\.vmpstate_<8hex>` | None | None by default (SDK-caller choice) |
| Enigma 7.x | None by default | `HKCU\Software\Enigma Protector` | VolumeSerial |
| Custom crypters | Sample-specific | Sample-specific | Usually VolumeSerial + ProcessorId + MAC |
| EAC (offline hobby reversing only) | `%ProgramData%\EasyAntiCheat\*` | `HKLM\SOFTWARE\EasyAntiCheat` | Server-side (out of scope) |

A "custom crypter" row is intentionally vague -- every sample is different;
monitor with Procmon filtered to the loader PID on first run, and record
the new paths into the row.

### 9.2.4 Dump exfiltration BEFORE revert

Session artifacts (memory dumps, unpacked PE snapshots, disassembly
listings, Procmon CSVs) must leave the analysis VM before the revert, or
they are lost.

The curator pattern:

- A separate Linux box (Debian 12 minimum) on the same subnet, call it
  `curator`.  Hostname `curator.lab`, IP `10.42.0.2` (see 9.3).  Nothing
  installed on it but `samba` and `ssh`.
- A SMB share on `curator` named `drops`, mounted with `writable = yes`,
  `read only = no`, `create mask = 0640`, exported only to the analysis
  subnet.
- Analysis VM mounts `\\10.42.0.2\drops` with `net use` right before the
  session.  Writes dumps there.  Does not mount it read-write to anything
  it will not need to drop.

Curator-side samba config (`/etc/samba/smb.conf`):

```ini
[global]
   workgroup = LAB
   server string = curator
   security = user
   map to guest = never
   bind interfaces only = yes
   interfaces = 10.42.0.2/24
   hosts allow = 10.42.0.0/24
   hosts deny = 0.0.0.0/0

[drops]
   path = /var/lab/drops
   valid users = drop
   writable = yes
   browseable = yes
   create mask = 0640
   directory mask = 0750
   force user = drop
   force group = drop
```

A dedicated user `drop` with a per-session password is created on
`curator`.  The password is rotated every session (shell script writes it
to `/etc/samba/passwd.<date>` and `smbpasswd -a drop`).

Alternative one-way-write channel: run `samba` on the analysis VM instead
and have the curator pull via `smbclient`.  The curator never mounts the
analysis share; it executes per-session:

```bash
smbclient //10.42.0.100/outbox -U analyst%<password> \
  -c 'prompt OFF; recurse ON; mget *; exit'
# Then rm -rf the outbox from curator side by first switching to a
# dedicated share definition that permits the curator to delete.
```

Either direction works.  The constraint: the analysis VM must not be able
to READ anything on the curator that it has not just written.  Preventing
back-door execution of a curator-side payload is the point.

### 9.2.5 Revert checklist

Sequence, every time:

1. Stop the analysis launcher (`launcher\stop.ps1`).  Driver unloads.
2. Verify `sc query the_chamber` returns `STOPPED`.
3. Copy outputs to `\\curator\drops\<sample-hash>\` or push via the
   alternate smbclient route.
4. Confirm on the curator that the expected files are there and sized > 0.
5. Only then: revert the snapshot (`Restore-VMCheckpoint`) or re-image
   (Path B).
6. Boot, confirm baseline manifest matches 9.1.5, before loading the next
   sample.

Skipping step 4 and reverting on faith has lost dumps to a silent SMB auth
failure more than once.  The pattern is non-negotiable.

## 9.3 Network segmentation

### 9.3.1 Subnet

Analysis traffic rides a dedicated VLAN or physical port.  Example:

- Analysis subnet: `10.42.0.0/24`.
- Analysis VM: `10.42.0.100` static.
- Curator: `10.42.0.2`.
- Gateway (pfSense VM or dedicated appliance): `10.42.0.1`.
- No route from analysis subnet to the operator's personal LAN.

Do not NAT the analysis subnet to the open internet.  All egress goes
through a sinkhole / proxy host that rewrites DNS to known-sinkhole IPs
and blocks everything else.

### 9.3.2 Firewall ruleset (pfSense, sample)

Interface: `ANALYSIS` (bound to the analysis NIC).

```
# Pass: analysis VM -> curator SMB
pass in on ANALYSIS from 10.42.0.100 to 10.42.0.2 \
    proto tcp port { 139 445 } keep state

# Pass: analysis VM -> sinkhole DNS
pass in on ANALYSIS from 10.42.0.100 to 10.42.0.1 \
    proto udp port 53 keep state

# Pass: analysis VM -> sinkhole HTTP/HTTPS (a Python server on
# 10.42.0.1:80/443 that serves a fixed 200 OK)
pass in on ANALYSIS from 10.42.0.100 to 10.42.0.1 \
    proto tcp port { 80 443 } keep state

# Block everything else on this interface
block in log on ANALYSIS from any to any
block out log on ANALYSIS from any to any
```

Equivalent on a Linux gateway with `iptables`:

```bash
# Default drop on the FORWARD chain.
iptables -P FORWARD DROP

# Analysis VM -> curator SMB.
iptables -A FORWARD -s 10.42.0.100 -d 10.42.0.2 \
    -p tcp -m multiport --dports 139,445 -j ACCEPT

# Analysis VM -> sinkhole services on gateway itself (INPUT chain).
iptables -A INPUT -s 10.42.0.100 -d 10.42.0.1 \
    -p udp --dport 53 -j ACCEPT
iptables -A INPUT -s 10.42.0.100 -d 10.42.0.1 \
    -p tcp -m multiport --dports 80,443 -j ACCEPT

# Log everything else from the analysis subnet.
iptables -A INPUT -s 10.42.0.0/24 -j LOG --log-prefix "ANALYSIS_DROP "
iptables -A INPUT -s 10.42.0.0/24 -j DROP
iptables -A FORWARD -s 10.42.0.0/24 -j LOG --log-prefix "ANALYSIS_FWD_DROP "
iptables -A FORWARD -s 10.42.0.0/24 -j DROP
```

### 9.3.3 DNS and HTTP sinkhole

On the gateway, run a minimal DNS server (`dnsmasq`) with a catch-all
entry pointing every name to the sinkhole IP:

```
# /etc/dnsmasq.d/sinkhole.conf
no-resolv
no-hosts
address=/#/10.42.0.1
```

And a minimal HTTP sinkhole (Python stdlib):

```python
# /opt/sinkhole/sinkhole.py -- run as a systemd unit on 10.42.0.1
from http.server import BaseHTTPRequestHandler, HTTPServer
import ssl, logging

logging.basicConfig(filename="/var/log/sinkhole.log",
                    level=logging.INFO,
                    format="%(asctime)s %(message)s")

class H(BaseHTTPRequestHandler):
    def do_GET(self):
        logging.info("GET %s from %s hdrs=%s",
                     self.path, self.client_address, dict(self.headers))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()
    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        logging.info("POST %s from %s body=%r",
                     self.path, self.client_address, body)
        self.send_response(200); self.send_header("Content-Length","0"); self.end_headers()
    def log_message(self, *a): pass  # we log ourselves

srv = HTTPServer(("10.42.0.1", 80), H)
srv.serve_forever()
```

A second instance wrapped in `ssl.wrap_socket` on port 443 with a
self-signed cert.  The point is not to fool the sample's TLS check but to
log the CN and SNI the sample tries to reach.

### 9.3.4 No direct internet from analysis box

The analysis box has physically no route to the WAN.  This is checked
twice: once in the pfSense WAN rules (block source `10.42.0.0/24`), and
once on the box itself by removing the default gateway from the analysis
NIC.

```powershell
# On the analysis VM
Get-NetAdapter | Where-Object { $_.Name -eq "Ethernet" } |
    Set-NetIPInterface -AddressFamily IPv4 -Dhcp Disabled
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.42.0.100 `
                 -PrefixLength 24  # no -DefaultGateway argument
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" `
                           -ServerAddresses 10.42.0.1
```

### 9.3.5 Research browser

If any web access is required (reading a vendor's documentation of a
packer, for example), do it from the CURATOR, not the analysis box, and
keep the research browser profile isolated.

- Download Firefox Portable (not standard Firefox) on a different machine.
- Copy to `curator:/opt/firefox-research/`.
- Launch with a dedicated profile directory and `--no-remote`.
- `about:config`: set `services.sync.enabled=false`, remove any Pocket /
  telemetry endpoints, disable `datareporting.healthreport.uploadEnabled`,
  disable `app.normandy.enabled`.
- Do not sign in to any account.  No password manager.  No history sync.
- Delete the profile directory between research sessions if the pages
  visited are sensitive to the target.

The analysis VM itself has no browser installed.  Browsers are a
large and well-known attack surface and a reliable VM/bare-metal
distinguisher (their font-cache + WebGL fingerprint differs).

## 9.4 Kernel debugger ready

THE_CHAMBER will bugcheck during bringup.  The audit in
`audit/detection_surface.md` lists concrete bugs that, until fixed,
produce reliable crashes (uninitialized `vmrun_entry_tsc`, r15 as the ctx
pointer across VMRUN, Patch Guard tripping on `PsLoadedModuleList`
unlink).  You need the dump, every time, even on the first boot.

### 9.4.1 Second machine with WinDbg

- Separate Windows 11 machine, call it `kd-host`.  Any modern CPU is
  fine; this box does not run the HV.
- WDK 10.0.26100.x installed (same version as the build machine).
- WinDbg Preview + `windbg` classic.
- Static symbol cache: `_NT_SYMBOL_PATH =
  srv*C:\symbols*https://msdl.microsoft.com/download/symbols`.
- 100 GB free for symbol cache growth.
- Wired network to the analysis subnet gateway, with a firewall rule
  permitting UDP port 50000 inbound from the analysis VM only:

```
pass in on ANALYSIS from 10.42.0.100 to 10.42.0.3 \
    proto udp port 50000 keep state
```

`kd-host` at `10.42.0.3`.

### 9.4.2 Serial-over-LAN kd setup

AMD boxes without a physical serial header use KDNET.  The `kdnet.exe`
utility in the WDK generates a connection key.

On the analysis box, in an elevated prompt:

```powershell
# Find the NIC kdnet is willing to use.
C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kdnet.exe

# Output example:
# Network debugging is supported on the following NICs:
# busparams=0.25.0, Intel I225-V, KDNET is running on this NIC.

# Configure. HOSTIP is kd-host; PORT 50000; the key output goes to stdout.
bcdedit /dbgsettings NET HOSTIP:10.42.0.3 PORT:50000

# Capture the key printed. You will need it on the kd side.
bcdedit /debug on
bcdedit /bootdebug {current} on   # also debug the boot loader
```

The exact key is printed once; record it in the box config file
immediately (`audit/box_<serial>_kd_key.txt`).  Reboot.

On `kd-host`:

```powershell
# WinDbg Preview GUI: File -> Attach to kernel -> Net
# Port: 50000
# Key: <the key from bcdedit above>

# Or classic:
windbg -k net:port=50000,key=<the key>
```

The two boxes handshake in the first second of the analysis box boot.

### 9.4.3 Generating the KEY manually

`bcdedit /dbgsettings NET ... KEY:` will accept a provided key if you
want deterministic per-box keys.  Generate with `kdnet.exe`:

```powershell
# Generates a fresh random KDNET key of the standard shape
# xxxxxxxxxxxxxx.yyyyyyyyyyyyyy.zzzzzzzzzzzzzz.wwwwwwwwwwwwww
kdnet.exe 10.42.0.3 50000

# Output includes a line like:
# key=1a2b3c4d5e6f7g.8h9i0j1k2l3m4n.5o6p7q8r9s0t1u.2v3w4x5y6z7a8b
```

Use that string verbatim in `bcdedit /dbgsettings NET KEY:<...>`.

### 9.4.4 Crashdump kernel-mode capture

When the HV bugchecks mid-session the kd channel catches live state, but
also configure Windows to capture a full memory dump to disk as a
fallback (useful when kd was not attached or desynced).

```powershell
# Full kernel dump (not minidump; minidumps lack pool and loaded-module
# details needed to post-mortem SVM state).
# HKLM\SYSTEM\CurrentControlSet\Control\CrashControl
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" `
                 -Name "CrashDumpEnabled" -Value 1   # 1 = Complete memory dump

# Dump file location.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" `
                 -Name "DumpFile" -Value "C:\dumps\MEMORY.DMP"

# Keep older dumps (do not overwrite silently).
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl" `
                 -Name "Overwrite" -Value 0

# Ensure WER captures user-mode faults from the launcher too.
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" `
                 -Name "DumpFolder" -Value "C:\dumps\wer"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" `
                 -Name "DumpCount" -Value 10
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps" `
                 -Name "DumpType" -Value 2   # 2 = Full dump

# Pagefile must be at least RAM + 257 MB and on the system drive for the
# complete-memory-dump writer to succeed.
wmic computersystem set AutomaticManagedPagefile=False
wmic pagefileset where "name='C:\\pagefile.sys'" set \
    InitialSize=36864,MaximumSize=36864    # for a 32 GB RAM box
```

`wer.exe` itself is a WER-side tool for user-mode faults; the
`LocalDumps` registry key is what controls per-process dumps for the
launcher (`launcher\*.exe`) if it ever faults.  Kernel dumps go via
`CrashControl` only.

After a crash, confirm:

```powershell
Get-ChildItem C:\dumps -Recurse | Sort-Object LastWriteTime -Descending |
    Select-Object -First 5
```

The dump is in `C:\dumps\MEMORY.DMP`.  Copy to `\\curator\drops\` BEFORE
reverting, per 9.2.4.

## 9.5 Change management

### 9.5.1 Git repository

This repository is the single source of truth for the driver, launcher,
pentest scripts, recovery, and this documentation.  No code lives on the
analysis box that is not committed and pushed to the curator-side remote.

```bash
# On the analysis box, one-time.
git remote add curator ssh://git@10.42.0.2/srv/git/the-chamber.git
git push -u curator main
```

All feature work on topic branches.  `main` is baseline-validated code
only.

### 9.5.2 Atomic, tested, documented

Every commit must:

1. Build cleanly with `driver\build.ps1`.
2. Pass the pentest probe battery (see 9.5.4) in `after_load` mode
   against the probes that commit claims to fix.
3. Have a commit message that cites one or both of:
   - the specific detection vector it closes, by audit section
     (e.g. `vmexit: close EFER.SVME read -- audit §9 row EFER`);
   - the specific capability it adds (e.g. `npt: add 2 MiB-page split
     helper for sample-under-test unmap`).

### 9.5.3 Changelog format

Keep a `CHANGELOG.md` at the repo root (not in this doc set).  Each
release block documents:

```
## v0.X.Y -- YYYY-MM-DD

Detection vectors closed:
- EFER.SVME visible to guest RDMSR (audit §EFER row). Fixed by populating
  MSRPM at init for 0xC0000080.
- TSC monotonicity regression after VMEXIT (audit §RDTSC row). Fixed by
  calling timing_before_vmrun() from vmrun.asm before vmrun rax.

Capabilities added:
- (none this release)

Regressions introduced:
- (declared empty if git bisect run passed; else list)
```

### 9.5.4 git bisect with the probe battery

When a regression shows up ("probe X passed on commit A, fails on commit
B"), find the culprit with `git bisect run`:

```bash
# Example: EFER.SVME visibility regressed.
# The probe lives in pentest\detectors\ and exits 0 on pass, 1 on fail.
git bisect start
git bisect bad   HEAD
git bisect good  <last-known-good-sha>

git bisect run ./pentest/bisect_probe.sh efer_svme
```

`pentest/bisect_probe.sh` (not written by this phase; template):

```bash
#!/usr/bin/env bash
# Usage: bisect_probe.sh <probe-name>
# Exits 0 if the probe passes against the currently-checked-out driver.
set -euo pipefail

probe="$1"

# Build the driver at the current HEAD.
powershell.exe -NoProfile -File .\driver\build.ps1 || exit 125  # skip

# Install, load, run probe, unload.
powershell.exe -NoProfile -File .\INSTALL.ps1 || exit 125
powershell.exe -NoProfile -File .\launcher\start.ps1 || exit 125

# Run the specific detector in after_load mode.
powershell.exe -NoProfile -File .\pentest\detectors\${probe}.ps1
rc=$?

powershell.exe -NoProfile -File .\launcher\stop.ps1 || true
powershell.exe -NoProfile -File .\UNINSTALL.ps1 || true

exit $rc
```

Exit code 125 tells `git bisect` to skip the commit (build broken or
install failed -- not a probe-level conclusion).  Exit codes 0 and 1
mean pass / fail respectively.

### 9.5.5 Tag every tested baseline

Tag the commit used for each baseline manifest.  When a regression is
reported months later, `git bisect` has a known-good anchor to start
from.

```bash
git tag -a baseline-2026-11-23 -m "Baseline manifest C:\baseline captured"
git push curator baseline-2026-11-23
```

## 9.6 Secret documentation

For every synthetic value the HV presents to the guest -- CPUID bit
flipped, MSR read mocked, MSR write absorbed -- there must be a single
canonical record of WHAT value is substituted, WHY that value is the
correct bare-metal baseline, and the SOURCE (AMD APM citation,
Hyper-V TLFS citation, or concrete probe-battery measurement).

### 9.6.1 Why

Three failure modes a spoofing hypervisor hits sooner or later:

1. A later Zen 4 microcode update subtly changes an MSR value, and the
   HV keeps returning the old one.  The guest sees a mismatch between its
   CPUID stepping and the MSR; detection.
2. A junior engineer sees a suspicious value in a commit and does not
   know whether it is "the real bare-metal value" or an earlier
   spoofing experiment that leaked through.
3. A packer vendor publishes new probes keyed on a specific MSR the HV
   never knew about.  Audit finds the field was pass-through but no one
   remembered why it was pass-through and not spoofed.

A synthetic-values table makes all three answerable at a glance.

### 9.6.2 Format

The canonical table lives at `audit/synthetic_values_table.md`.  Columns:

- `MSR/Field` -- human name (e.g. `EFER.SVME`, `CPUID.1:ECX[31]`).
- `Address` -- numeric address (MSR number) or leaf.sub[bit] notation.
- `Spoofed Value` -- exactly what the handler returns.  For a passthrough
  field, write `PASSTHROUGH` with a short reason.
- `Bare-metal Expected` -- what a non-virtualized 7700X returns.  Must
  be measured, not assumed.  Measurement method cited in Notes.
- `Source` -- AMD APM Vol/Section, Hyper-V TLFS section, or
  measurement-provenance string.
- `Notes` -- any caveat, including `(unverified)` flags from the audit,
  microcode-dependency warnings, and known detection paths.

### 9.6.3 Update discipline

The table is updated in lock-step with any VMCB handler change.  A
commit that adds an MSR intercept whose handler returns a value MUST
also add or update the corresponding table row in the same commit.  The
pre-commit hook (optional; recommended) checks this:

```bash
# .githooks/pre-commit  (installed via core.hooksPath)
#!/usr/bin/env bash
# If driver/vmexit.c or driver/svm_vmcb.c changed, require that
# audit/synthetic_values_table.md also changed in the same commit.
set -e
staged=$(git diff --cached --name-only)
if echo "$staged" | grep -qE '^driver/(vmexit\.c|svm_vmcb\.c)$'; then
  if ! echo "$staged" | grep -qE '^audit/synthetic_values_table\.md$'; then
    echo "pre-commit: driver MSR/CPUID handler changed; update audit/synthetic_values_table.md"
    exit 1
  fi
fi
```

### 9.6.4 Where the table lives relative to this doc

`audit/synthetic_values_table.md`.  See that file for the live table.
This document only sets the policy that the table must exist, must be
current, and must be the single source of truth for synthetic values.
