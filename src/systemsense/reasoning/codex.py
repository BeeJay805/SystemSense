"""Opt-in GPT-6 Sol advisory inference through the user's Codex subscription."""

from systemsense.decision.contracts import ProviderIdentity
from systemsense.inference.codex import CodexInferenceConfig, CodexJsonClient
from systemsense.reasoning.structured import StructuredReasoningProvider


class CodexReasoningProvider(StructuredReasoningProvider):
    def __init__(
        self, config: CodexInferenceConfig, *, client: CodexJsonClient | None = None
    ) -> None:
        if not config.enabled:
            raise ValueError("subscription inference requires explicit enablement")
        if client is not None and client.config != config:
            raise ValueError("injected Codex client differs from reasoning config")
        super().__init__(
            client=client or CodexJsonClient(config),
            model="gpt-6-sol",
            timeout_seconds=config.timeout_seconds,
            identity=ProviderIdentity(
                provider_id="codex-subscription-reasoning", provider_version="1", role="reasoning"
            ),
            proposal_label="Unverified subscription model proposal",
        )
