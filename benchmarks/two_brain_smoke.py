"""Opt-in live local investigator journeys, not a diagnostic accuracy benchmark."""

import argparse
import json
import time
from pathlib import Path

from systemsense.application.bootstrap import default_capabilities, default_case_runtime
from systemsense.application.investigator import Investigator
from systemsense.application.service import ApplicationService
from systemsense.inference.factory import load_advisory_providers
from systemsense.inference.profile import load_inference_profile
from systemsense.storage.sqlite_store import SQLiteStore


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--objective", action="append", required=True)
    parser.add_argument("--budget-ms", type=int, default=180000)
    parser.add_argument("--max-rounds", type=int, default=6)
    parser.add_argument("--baseline-decision", action="store_true")
    args = parser.parse_args()
    profile = load_inference_profile(args.profile)
    providers = load_advisory_providers(
        profile.inference,
        laya_config=None if args.baseline_decision else profile.laya.runtime_config(),
        laya_timeout_seconds=profile.laya.timeout_seconds,
    )

    def factory(store: SQLiteStore) -> Investigator:
        return Investigator(
            store=store,
            runtime=default_case_runtime(store),
            capabilities=default_capabilities(),
            decision=providers.decision,
            reasoning=providers.reasoning,
            knowledge=providers.knowledge,
        )

    results: list[dict[str, object]] = []
    try:
        service = ApplicationService(
            args.database, factory=factory, inference_status=profile.inference_status()
        )
        try:
            for objective in args.objective:
                started = time.monotonic()
                case = service.start_case(objective, args.budget_ms, args.max_rounds)
                case_id = str(case["case_id"])
                print(json.dumps({"case_id": case_id, "event": "started"}), flush=True)
                service.wait()
                report = service.get_case(case_id)
                result: dict[str, object] = {
                    "elapsed_seconds": time.monotonic() - started,
                    "report": report,
                }
                results.append(result)
                print(
                    json.dumps(
                        {
                            "case_id": case_id,
                            "elapsed_seconds": result["elapsed_seconds"],
                            "outcome": report["outcome"],
                            "calls": report["provider_calls"],
                        }
                    ),
                    flush=True,
                )
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(
                    json.dumps(
                        {
                            "classification": "live-local-runtime-integration",
                            "diagnostic_accuracy_claim": False,
                            "profile": profile.model_dump(mode="json"),
                            "results": results,
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
        finally:
            service.close()
    finally:
        providers.close()


if __name__ == "__main__":
    main()
