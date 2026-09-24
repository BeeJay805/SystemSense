# Deterministic simulated pilot episodes

`systemsense.evaluation.simulated_pilot` provides toy, read-only investigation
episodes to exercise candidate labeling and leakage checks. It does **not**
collect Windows evidence, emulate Windows faithfully, authenticate a real
outcome, qualify a model, or contribute diagnostic-performance numbers. Every
episode explicitly has `training_admissible=false` and
`diagnostic_performance_admissible=false`.

The public `model_input` contains only a symptom report, predecision baseline
facts, and registered toy probe descriptions. The separate evaluator-only
`oracle` contains the controlled root causes and hypothetical repair outcome.
`adjudications` contain postdecision probe results. Pass only `model_input` to
a worker; sending the whole episode would leak future results. Wi-Fi cases
share identical public input even when the hidden cause, incidental battery
abnormality, or measurement availability differs.

`generate_simulated_episode(scenario_id, executed_probe_ids=...)` evaluates
each selected toy probe independently against the same immutable hidden world.
An observed result is `useful` only if it eliminates at least one possible
root-cause set from the **frozen predecision baseline** under the toy catalog;
an observed result that eliminates none is `negative`. The recorded
`utility_scope=independent_single_probe_from_frozen_baseline` is not a
sequential marginal-utility label. Do not add the gains or assume that a probe
remains useful after another probe runs. In the dual-cause Wi-Fi case, radio
and DNS are each useful from baseline, but DNS adds no discrimination after a
disabled-radio result.
Unavailable and unrun alternatives are `unknown`, never negatives. Battery
wear and measurement availability are crossed with every causal world, so
those nuisance signals cannot become a shortcut to the hidden fault. The
simulator includes healthy controls, unrelated abnormalities, missing
measurements, competing simultaneous causes, and Wi-Fi/PDF/game examples.
`simulated_symptom_after_hypothetical_repair` is a pure toy outcome oracle;
it never performs or authorizes a machine repair.

The evaluator-only `oracle.compatible_root_cause_sets` enumerates distinct
causal worlds that produce the same **complete** toy probe signature, crossing
irrelevant battery and missing-measurement states. If more than one root-cause
set remains, `exact_diagnosis_abstain_required=true`. In particular,
`wifi_radio` and `wifi_competing_causes` have indistinguishable registered
measurements, so neither supports an exact diagnosis even if every toy probe
runs. A missing DNS measurement similarly leaves the healthy and DNS-fault
worlds ambiguous. These flags are not in `model_input` and must not be treated
as features or as evidence that a live Windows system has those faults.

`verify_simulated_episode` regenerates a record and rejects altered labels or
predecision content. `validate_simulated_splits` prevents case, machine,
application, application-version, and fault-family groups from crossing splits
within a supplied batch. These keys are deterministic simulation identifiers,
not authenticated host identities. The catalog is small and deliberately
scripted, so even a held-out toy score would measure simulator fit, not real
diagnostic utility or laptop inference performance.

To inspect one episode without invoking a model or touching Windows:

```powershell
uv run python -c "from systemsense.evaluation.simulated_pilot import generate_simulated_episode; e = generate_simulated_episode('wifi_irrelevant_abnormality', executed_probe_ids=('wifi.gateway', 'system.battery_wear')); print(e.model_dump_json(indent=2))"
```

To check the contracts:

```powershell
uv run python -m pytest -q tests/unit/evaluation/test_simulated_pilot.py
```

Promotion to trainable data still requires a qualified source with independent
real-world outcome review, consent and custody, exact live worker-input parity,
global grouped splits, and an evaluation protocol that does not reuse the
simulator's scripted causal table as its answer key.
