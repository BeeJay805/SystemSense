from systemsense.application.bootstrap import default_capabilities
from systemsense.packs.runtime import default_probe_runner
from systemsense.worker import REGISTERED_PROBE_IDS


def test_display_mode_is_registered_as_bounded_read_only_probe() -> None:
    probe_id = "display.mode"
    runner = default_probe_runner()
    manifest = runner.manifest(probe_id)

    assert probe_id in REGISTERED_PROBE_IDS
    assert manifest is not None
    assert manifest.limits.max_records == 1
    assert manifest.safety.target_state_effect == "none"
    assert probe_id in {item.probe_id for item in default_capabilities()}
