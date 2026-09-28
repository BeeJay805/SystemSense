"""Optional local Ollama provider using the shared advisory contract."""

from systemsense.decision.contracts import ProviderIdentity
from systemsense.inference.ollama import JsonTransport, OllamaChatClient, OllamaPreloadResult
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.structured import StructuredReasoningProvider


class OllamaReasoningProvider(StructuredReasoningProvider):
    def __init__(
        self,
        config: LocalInferenceConfig,
        *,
        transport: JsonTransport | None = None,
        client: OllamaChatClient | None = None,
        fallback: DeterministicReasoningProvider | None = None,
    ) -> None:
        if not config.enabled or config.reasoning_model is None:
            raise ValueError("Ollama reasoning provider requires explicit enablement and a model")
        if transport is not None and client is not None:
            raise ValueError("provide either an Ollama client or a transport")
        if client is not None and client.config != config:
            raise ValueError("injected Ollama client differs from reasoning config")
        self._ollama_client = client or OllamaChatClient(config=config, transport=transport)
        super().__init__(
            client=self._ollama_client,
            model=config.reasoning_model,
            timeout_seconds=config.timeout_seconds,
            identity=ProviderIdentity(
                provider_id="ollama-local-reasoning", provider_version="1", role="reasoning"
            ),
            proposal_label="Unverified local model proposal",
            fallback=fallback,
        )

    def prewarm(self, *, timeout_seconds: float) -> OllamaPreloadResult:
        return self._ollama_client.preload(model=self._model, timeout_seconds=timeout_seconds)
