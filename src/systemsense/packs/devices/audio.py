"""Audio endpoint and related service observations."""

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class AudioObservation(FrozenModel):
    endpoint_name: str = Field(min_length=1, max_length=1024)
    device_instance_id: str = Field(min_length=1, max_length=4096)
    state: str = Field(min_length=1, max_length=255)
    audio_service_state: str = Field(min_length=1, max_length=255)


def collect_audio(
    observations: tuple[AudioObservation, ...],
    *,
    max_records: int = 64,
) -> tuple[AudioObservation, ...]:
    if not 1 <= max_records <= 256:
        raise ValueError("max_records must be between 1 and 256")
    return observations[:max_records]
