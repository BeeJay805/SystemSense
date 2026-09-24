# Windows IT reference graph v6 source review

Reviewed 2026-09-23. This is a review of **possible mechanisms**, not a report about
any machine. The v6 pack adds four nodes and nine conditional relations to v5
(95 nodes, 136 relations, 35 sources). Source links in schema v1 are not pinned
or hash-verified. An upstream document can change after this review.

| Relation | Primary-source location and supported claim | Inference and evidence still required |
| --- | --- | --- |
| `kr_wifi_007` | [Microsoft Wi-Fi layout, “Check your signal strength”](https://support.microsoft.com/en-us/windows/experience/connectivity-networking/wi-fi-and-your-home-layout) says weak signal can make a connection unreliable; [Microsoft advanced wireless troubleshooting, “Connection drops or roaming is unreliable”](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/wireless-network-connectivity-issues-troubleshooting) calls for time, AP, and signal conditions. | A present signal snapshot cannot reconstruct the failed interval. Require a bound WLAN interface and time-aligned disconnect evidence; AP/interference attribution remains open. |
| `kr_wifi_008` | [Microsoft advanced wireless troubleshooting, “Scenarios” and “Troubleshooting”](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/wireless-network-connectivity-issues-troubleshooting) lists unreliable roaming and the connected-to-roaming-to-disconnected state path. | Bind the transition to the affected interface and symptom time. Client events alone cannot identify an AP or controller fault. |
| `kr_wifi_009` | [Microsoft advanced wireless troubleshooting, “Start with the reported symptom”](https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/wireless-network-connectivity-issues-troubleshooting) includes missing adapters and post-driver-change failures; [Microsoft device/driver installation troubleshooting, “Check if the device is marked with a problem”](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/troubleshooting-device-and-driver-installations) describes explicit device problem codes. | Infer loss of the wireless path only for the same adapter and absent a working alternate path. Driver age alone is not failure evidence. |
| `kr_pdf_007`, `kr_app_007` | [Microsoft “List of WPA Graphs,” Storage graphs](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs) documents per-process/path disk service time and per-thread file-I/O duration. | A PDF read or synchronous application wait is a conditional critical-path inference, not a product-specific finding from that page. Current probes cannot bind file, thread, action, and latency. |
| `kr_pdf_008` | [Microsoft “Memory Footprint Optimization,” introduction](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/memory-footprint-optimization) relates low available memory, paging, and responsiveness; [WPA Memory graphs](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs) include hard-fault I/O time by process/file. | Viewer-specific hard-fault wait must overlap a timed page action. Available-memory snapshots screen only. |
| `kr_game_cpu_submit_001` | [Microsoft “Top Issues for Windows Titles,” “CPU-Limited Performance” and “Poor Batch Management”](https://learn.microsoft.com/en-us/windows/win32/dxtecharts/top-issues-for-windows-titles) describes CPU-side game and draw-submission limits. The article is historical and its numerical tuning advice is **not** imported. [WPA Video graphs](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs) show process frame durations. | A current game, GPU, and frame-time trace must be bound before attributing low FPS to CPU submission. Aggregate CPU/GPU load is insufficient. |
| `kr_game_memory_001` | [Microsoft memory-footprint introduction](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/memory-footprint-optimization) documents paging under limited memory; [WPA Memory/Video graphs](https://learn.microsoft.com/en-us/windows-hardware/test/wpt/list-of-wpa-graphs) show per-process hard faults and frame durations. | The game-specific frame impact is an inference requiring aligned hard-fault wait and bad frames, not a claim that system memory pressure explains this game. |
| `kr_game_tdr_001` | [Microsoft WDDM timeout detection and recovery, “Desktop recovery”](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/timeout-detection-and-recovery) describes graphics-stack reset, visible interruption, and Event Viewer logging. | A time-aligned recovery event can explain an episode of poor smoothness, **not** sustained low FPS or which process initiated the timeout. |

All `probes` on these schema-v1 relations are registered, read-only **screening
hints**. They do not promise to discriminate causes. The next gate is a reviewed
schema-v3 pack with explicit screening, discriminating, and unavailable probe
roles, source-specific citation artifacts, and contract tests against the real
collector outputs. In particular, Wi-Fi needs time-bound BSSID/AP and roam
evidence; PDF/app needs bound file, thread, hard-fault, and action latency;
gaming needs game-produced frame times and per-process CPU/GPU attribution.
Those capabilities must be separately registered and privacy-reviewed before
the graph may reference them. No arbitrary commands or collection are added by
this pack.

A scalable expansion path is to index official Microsoft, Adobe, NVIDIA, and
hardware-vendor documents by version and section; preserve reviewed source
artifacts and digests; generate candidate relations with a human-reviewed
mechanism, applicability, counterevidence, and probe-role contract; then admit
only relations that pass schema, registration, and provenance checks. Retrieved
documentation remains reference knowledge. Only case-bound observations from
authorized read-only collectors can enter the machine evidence graph, and
neither graph connectivity nor source agreement proves a machine cause.
