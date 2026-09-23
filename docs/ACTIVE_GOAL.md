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

Last published revision before this work: `c00e929` on
`codex/windows-investigator`. It established the read-only coordinator, 16
registered probes including passive connectivity, optional local Laya/Qwen
providers, conditional reference graph, loopback rehearsal, and fake-tested
WinINet repair foundation. These tests verify contracts, not field accuracy.
A desktop CPU Laya batch took 65.820 seconds; there is no ordinary-laptop
qualification or held-out diagnostic comparison. Existing benchmark fixtures
are not independently injected Windows faults.

Current work: connect the controlled episode harness, narrow
repair boundary, and staged connectivity evidence into a complete, independently
verified connectivity journey. Reassess this record after every milestone,
keeping failed and unverified gates explicit.

Current branch progress: the investigator seeds the relevant symptom family and,
when the fast provider offers no probe, follows only a relevant registered
reference-relation distinguishing probe within budget; no unrelated cheapest
probe is chosen for activity's sake. The passive connectivity collector retains
a full redacted snapshot plus a bounded inference preview with stage-specific
times and omission counts. Deterministic reasoning derives only unresolved,
cited WLAN/IP/route/DNS/WinINet stage hypotheses from fresh, sufficiently
covered evidence, never a reachability or root-cause verdict. The reference pack
has 69 nodes and 105 conditional relations.

The WinINet repair runner and native API adapter are fake-tested. The native
identity gate now checks the active interactive session, primary process token,
and absence of thread impersonation. A fixed-descriptor, current-user WinINet
oracle contract records redacted evidence and can distinguish a direct-path
control, but neither its owned external HTTPS endpoint nor an isolated native
transport exists. There is no application repair route or authoritative
managed-policy guard. The native writer has not been invoked on this host; no
Windows repair or independent symptom recovery has been shown. Before enabling
writes, qualify WinINet flag combinations, the exact affected-app scope, the
active-session boundary and the independent oracle on controlled Windows VMs.
The conservative DIRECT-bit requirement intentionally rejects some otherwise
valid states.

`benchmarks/vm_lab_contract.py` validates proposed allowlisted VM recipe,
checkpoint/reset, injection, arm identity, independent-controller and oracle
records. An admitted record is classified `vm_protocol_only`: it is not a
hypervisor adapter, cryptographic attestation, measured fault, repair proof, or
diagnostic-accuracy result. No VM rig or actual Windows fault episode has run.

Next: implement an independently controlled disposable Windows VM lane and
owned external HTTPS symptom endpoint; qualify an isolated, hard-deadline
WinINet transport plus direct-path control; prove exact user/application scope
and managed-policy detection; then wire one separately consented action through
durable journal, rollback limits, and independent before/after verification.
Only after this safety gate, compare blinded equal-access deterministic,
deep-only and two-brain arms on healthy, faulted, and external controls. Measure
time-to-supported-answer, false fixes, model/probe overhead and recurrence.
Broaden to Wi-Fi hardware, PDF workloads and gaming rigs without substituting
VM/network fixtures for physical qualification. Laptop Laya and any cloud
advisory provider remain separate, unqualified decisions.

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
