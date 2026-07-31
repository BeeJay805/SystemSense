"""Agent tool manifests and parity checks for the two experimental arms."""

from __future__ import annotations

from pydantic import Field, model_validator

from benchmarks.ab.contracts import ExperimentArm, ExperimentModel, canonical_sha256

SYSTEMSENSE_TOOL_NAMES = frozenset(
    {
        "open_case",
        "get_case_brief",
        "query_case_evidence",
        "get_evidence",
        "inspect_more",
        "get_coverage_map",
    }
)


class ToolDefinition(ExperimentModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    description: str = Field(min_length=1, max_length=1000)
    parameters: dict[str, object]
    strict: bool = False

    def responses_api_schema(self) -> dict[str, object]:
        return {
            "type": "function",
            "name": self.name,
            "description": self.description,
            "parameters": self.parameters,
            "strict": self.strict,
        }


class ToolManifest(ExperimentModel):
    schema_version: int = 1
    arm: ExperimentArm
    tools: tuple[ToolDefinition, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_names(self) -> ToolManifest:
        names = [tool.name for tool in self.tools]
        if len(names) != len(set(names)):
            raise ValueError("tool names must be unique")
        return self

    def by_name(self) -> dict[str, ToolDefinition]:
        return {tool.name: tool for tool in self.tools}

    def manifest_hash(self) -> str:
        payload = [
            tool.model_dump(mode="json") for tool in sorted(self.tools, key=lambda item: item.name)
        ]
        return canonical_sha256(payload)


def shared_repair_tools() -> tuple[ToolDefinition, ...]:
    return (
        ToolDefinition(
            name="run_powershell",
            description=(
                "Run one PowerShell command inside the study VM and return bounded "
                "stdout, stderr, exit code, and elapsed time."
            ),
            parameters={
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 8000,
                    },
                    "timeout_seconds": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 120,
                    },
                },
                "required": ["command"],
                "additionalProperties": False,
            },
        ),
    )
