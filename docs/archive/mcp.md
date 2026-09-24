# Optional MCP adapter

MCP is an optional transport for an external assistant. It is not the SystemSense
runtime, policy boundary, scheduler, evidence source of truth, or required local
workflow. The same neutral application API must remain usable from the local CLI,
tests, and future UI without an MCP client.

## Adapter contract

An adapter may expose bounded case creation, cited evidence summaries, individual
case-owned evidence, coverage, and progressive case state. It must:

- accept only typed, bounded arguments;
- preserve case ownership, opaque pagination, provenance, redaction, and coverage;
- expose observations and limitations, not authority to repair;
- treat symptoms and captured text as untrusted data;
- call the application coordinator rather than owning planning, storage, policy, or
  model selection;
- be removable without changing local collection or deterministic fallback behavior.

The old fixed tool surface is a legacy compatibility shape, not a product
requirement. Tool count, names, and client-specific instructions must not constrain
the core architecture.

## Security and deployment notes

If an MCP adapter is installed, use a local stdio process with an absolute
executable/data path and protect the local store using the Windows account. Do not
add an HTTP listener or arbitrary command, path, URL, registry, SQL, or event-query
surface. Adapter readiness is an adapter test, not a release gate for the local
investigator.

Any repair or experiment requires separate local policy and explicit consent. An
assistant connected through MCP cannot mint permission, expand the probe catalog,
or turn a read-only evidence request into a change.

## Future cloud providers

Cloud reasoning is a separate advisory provider behind the same typed reasoning
interface. It requires a local minimization/redaction/export gate and authenticated
transport. The response is validated locally and cannot grant authority. There is
no automatic cloud or paid fallback.
