# Active delivery record

Objective: a production-grade Windows self-diagnosis and repair platform with
adaptive two-brain investigation, targeted evidence, user-authorized exact fixes,
independent recovery verification, laptop/cloud and fully local editions, and
measured superiority to conventional scanners. This objective is **not met**.

Target environment: disposable local development fixtures first; Windows VM and
physical laptop/gaming rigs are later qualification environments. No production
deployment or host repair is authorized by this record.

Acceptance evidence required:

1. Real held-out Windows faults, healthy and external controls, and independent
   before/after symptom oracles. Record cause accuracy, false fixes, observability,
   end-to-end p50/p95 latency, and host overhead against equal-access baselines.
2. Focused, timestamped probes and an adaptive two-brain loop outperform a
   deterministic/keyword baseline on the same episodes without inventing facts.
3. Exact, separately consented repairs have live precondition checks, durable
   single-use authorization, crash reconciliation, rollback limits, and independent
   verification. Unauthorized or unverified mutation fails closed.
4. An ordinary-laptop profile has measured latency/memory/power and a safe
   cloud-reasoning privacy boundary; a fully local profile remains functional.
5. A usable symptom-to-measured-outcome application, documented and tested on
   supported Windows hardware. Unsupported hardware/external cases report precise
   observations and limitations instead of a false local fix.

Prior published baseline: `40e70a6` on `codex/windows-investigator`; it established
the read-only case coordinator, 15 probes, local Laya/Qwen providers, and a
conditional reference graph. Its 626-pass non-GPU suite verifies contracts, not
field accuracy. A desktop CPU
Laya batch took 65.820 seconds; no laptop qualification or held-out diagnostic
comparison exists. Existing benchmark fixtures are not independently injected
Windows faults. Do not claim product completion from these checks.

Current work: build the controlled episode harness, a narrowly scoped repair
boundary, and staged connectivity evidence; then integrate and verify a complete
connectivity journey. Reassess this record after every milestone, keeping failed
and unverified gates explicit.

Current branch progress: 16 registered read-only probes now include a
passive staged connectivity snapshot; the investigator seeds only the relevant
symptom family before the fast decision provider. The reference pack now has 69
nodes and 105 conditional relations. A fail-closed WinINet repair runner and
native API adapter are unit-tested through fakes, but no application route,
authoritative managed-policy guard, or scope-matched independent oracle is
connected. The native writer has not been invoked on this host. These changes do
not establish a repaired machine or general diagnostic accuracy.
Before enabling WinINet writes, verify an actual interactive desktop execution
boundary (session number alone is insufficient) and qualify supported WinINet
flag combinations on controlled Windows fixtures. The current conservative
DIRECT-bit requirement intentionally rejects some otherwise valid states.

Measured local rehearsal (ignored `tmp/lab-loopback-rehearsal-a1.json` and `.db`):
the owned listener accepted all three clean TCP checks, failed all three injected
checks, remained failed after a real 1.523-second keyword/deterministic case with
four successful probes, and accepted all three after the harness re-bound its own
listener. The investigator ended budget-exhausted; `repair_verified=false` and
`reference_recovery_verified=true`. This validates the harness and exposes a
current product gap. It is not a measured root-cause or repair success.
No Hyper-V, VirtualBox, or QEMU command is currently available on this host's
PATH, so the disposable Windows fault lane has not been run here. This is not a
reason to credit the loopback rehearsal as a proxy or Wi-Fi qualification.

Design finding: [WinINet normally bypasses loopback addresses](https://learn.microsoft.com/en-us/windows/win32/wininet/enabling-internet-functionality),
and its user Internet Options are not the same as
[WinHTTP or every application's proxy scope](https://learn.microsoft.com/en-us/windows/win32/wininet/wininet-vs-winhttp).
The owned-loopback episode can validate harness mechanics, not a WinINet proxy
repair. [Microsoft recommends changing default WinINet options through the
WinINet API](https://learn.microsoft.com/en-us/windows/win32/wininet/setting-and-retrieving-internet-options)
rather than direct registry writes. A real proxy fix therefore needs
an affected-stack, non-loopback owned endpoint oracle and a qualified native
adapter before it can be offered to users.
