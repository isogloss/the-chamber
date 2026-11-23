using System;

namespace TheChamber.Model;

/// <summary>
/// One row in the Dump tab's history ListView. Corresponds 1:1 with a
/// <see cref="TheChamber.Services.DumpIoctls.DumpHistoryEntry"/> returned
/// from the driver — the service layer maps between them so the UI
/// never sees the native layout.
///
/// Immutable record so bound ListView cells never go stale while the
/// background refresh timer swaps the backing collection.
/// </summary>
public sealed class DumpRecord
{
    /// <summary>Local-time timestamp of when the dump landed on disk.</summary>
    public DateTime Timestamp { get; init; }

    /// <summary>Short display name of the target process ("notepad.exe (7124)").</summary>
    public string Target { get; init; } = string.Empty;

    /// <summary>Which trigger fired this dump: "manual", "wx", "oep", "threshold", "payload".</summary>
    public string Trigger { get; init; } = string.Empty;

    /// <summary>Size of the dump payload in bytes.</summary>
    public long Bytes { get; init; }

    /// <summary>Full on-disk path to the dump file; used by the "Open" column.</summary>
    public string Path { get; init; } = string.Empty;
}
