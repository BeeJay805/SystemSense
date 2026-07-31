from pathlib import Path

from systemsense.packs.devices.audio import AudioObservation, collect_audio
from systemsense.packs.devices.drivers import DriverObservation, collect_drivers
from systemsense.packs.devices.pnp import DeviceObservation, collect_devices
from systemsense.packs.devices.setupapi import parse_setupapi_increment


def test_device_and_driver_observations_preserve_problem_and_version_facts() -> None:
    device = DeviceObservation(
        instance_id=r"USB\VID_1234&PID_5678",
        name="Fixture device",
        pnp_class="USB",
        status="Error",
        problem_code=10,
        present=True,
    )
    driver = DriverObservation(
        device_id=device.instance_id,
        name="Fixture driver",
        version="1.2.3.4",
        provider="Fixture Corp",
        driver_date="20260730",
        inf_name="oem42.inf",
    )

    assert collect_devices((device,), max_records=1)[0].problem_code == 10
    assert collect_drivers((driver,), max_records=1)[0].version == "1.2.3.4"


def test_setupapi_increment_extracts_failure_and_advances_byte_offset() -> None:
    fixture = Path(__file__).parents[3] / "fixtures" / "devices" / "setupapi.dev.log"
    raw = fixture.read_bytes()

    increment = parse_setupapi_increment(raw, start_offset=0, max_bytes=4096)

    assert increment.next_offset == len(raw)
    assert not increment.truncated
    assert len(increment.entries) == 1
    assert increment.entries[0].device_instance == r"USB\VID_1234&PID_5678"
    assert "0x0000001f" in increment.entries[0].errors[0]


def test_setupapi_increment_is_byte_bounded() -> None:
    increment = parse_setupapi_increment(b"x" * 100, start_offset=20, max_bytes=10)

    assert increment.next_offset == 30
    assert increment.truncated


def test_audio_observation_includes_related_service_state() -> None:
    audio = AudioObservation(
        endpoint_name="Speakers",
        device_instance_id=r"HDAUDIO\FUNC_01",
        state="active",
        audio_service_state="running",
    )

    assert collect_audio((audio,), max_records=8)[0].audio_service_state == "running"
