namespace TheChamber.Model;

/// <summary>
/// Enumeration of the five operator-facing trigger kinds on the Dump
/// tab. Kept separate from <c>Services.DumpIoctls.TriggerKindCode</c> —
/// that enum carries the on-the-wire ABI the driver reads, this one
/// is only ever persisted locally in <c>dump_prefs.json</c>, so the two
/// may diverge if the on-disk format is versioned later.
/// </summary>
public enum TriggerKind
{
    /// <summary>Operator presses "Dump now".</summary>
    Manual = 0,

    /// <summary>Driver fires a dump when a page in the target CR3
    /// transitions from write-watched to executable.</summary>
    WriteToExecute = 1,

    /// <summary>Driver fires a dump when execution lands on a caller-
    /// supplied suspected OEP in the target.</summary>
    Oep = 2,

    /// <summary>Driver fires a dump once a running byte count of
    /// write traffic to a watched page range crosses the threshold.</summary>
    WriteThreshold = 3,

    /// <summary>Driver fires a dump when the WFP shim observes a
    /// payload delivered to the target. Stub until the shim ships.</summary>
    PayloadReceived = 4,
}

/// <summary>
/// Operator preferences persisted to
/// <c>%AppData%\TheChamber\dump_prefs.json</c> so the Dump tab reopens
/// with the last kind of arm the operator configured, the directory
/// they chose and the last tuning values they typed in. None of this is
/// sensitive and none of it is binding on the driver — it only seeds
/// the UI on the next launch.
/// </summary>
public sealed class TriggerConfig
{
    /// <summary>Which trigger radio was last selected.</summary>
    public TriggerKind Kind { get; set; } = TriggerKind.Manual;

    /// <summary>Last directory the operator picked in the Browse... dialog.</summary>
    public string LastOutputDir { get; set; } = string.Empty;

    /// <summary>Last suspected-OEP hex value the operator typed, if any.</summary>
    public ulong? LastOep { get; set; }

    /// <summary>Last write-threshold value the operator typed, if any.</summary>
    public uint? LastThresholdBytes { get; set; }
}
