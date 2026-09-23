# Game frame evidence: offline import only

`benchmarks/game_frame_oracle.py` reads a user-supplied PresentMon v2 CSV. It does
not run PresentMon, start an ETW trace, open a game, inspect live processes,
change settings, or request elevation. The resulting `untrusted_import_only`
record is useful for testing report math and deciding which evidence is still
missing. It is not an authenticated physical-rig benchmark or a supported
diagnosis of a 12-FPS cause.

The importer requires an absolute CSV path and the SHA-256 digest of its bytes.
It reads at most 8 MiB and parses at most 100,000 frame rows. The caller also
reports the game PID, executable name and creation time, PresentMon version,
phase, exact scene, settings, and the time settings were attested. The importer
checks PID and application-name values present in the CSV, but CSV rows cannot
prove that process creation time, game settings, scene, capture version, or
machine identity. A matching digest proves only that the imported bytes match
the supplied digest; it does not authenticate their origin.
The path is selected by the operator running this benchmark module; no
investigator, model, MCP tool, or application endpoint can supply it. The
module produces a typed in-memory result and performs no export. Any later
CSV or spreadsheet export must escape untrusted text to prevent formula
interpretation. The imported-at timestamp is distinct from the unverified
capture time and the user-attested settings time.
The result stores a generic source label and byte digest, not the absolute
operator path; the path remains only in the import request.

PresentMon's [console documentation](https://github.com/GameTechDev/PresentMon/blob/main/README-ConsoleApplication.md)
defines `MsBetweenPresents` as the interval between Present calls and
`MsBetweenDisplayChange` as the prior frame's displayed duration before the
current displayed Present. `DisplayedTime` can be `NA` for frames that were not
displayed. The importer reports p50/p95/p99 milliseconds and sample counts for
presented and displayed intervals separately, per `SwapChainAddress`. It never
combines multiple swapchains into one FPS figure. Missing, malformed, mixed,
truncated, or target-absent rows produce `partial` or `unavailable` coverage.
No FPS cap, render adapter, bottleneck, setting, or recovery is inferred.
Malformed UTF-8 is rejected, and swapchain identifiers must be bounded
hexadecimal values. Other imported strings remain untrusted.

Live capture is deliberately deferred. PresentMon's
[shutdown handler](https://github.com/GameTechDev/PresentMon/blob/main/PresentMon/MainThread.cpp#L1368-L1397)
notes that process termination before its threads finish may leave the trace
session open; a safe live
runner needs verified ownership and cleanup across timeout and cancellation,
plus capture-overhead qualification on the physical game rig. The current
importer provides neither. The documented [console options](https://github.com/GameTechDev/PresentMon/blob/main/README-ConsoleApplication.md)
would permit PID-targeted timed capture, but they are not invoked here.
