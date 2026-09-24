# Curated reference knowledge

SystemSense ships a small, versioned Windows diagnostic reference graph for local retrieval.
It is deliberately separate from the evidence graph: `kr_*` reference relations are possible
mechanisms to test, while `ev_*` records and machine relations describe observations from a case.
A reference relation never proves cause, grants permission, or instructs the system to change
anything.

## API and bounds

```python
from systemsense.knowledge import KnowledgeQuery, ReferenceKnowledgeGraph

graph = ReferenceKnowledgeGraph.load_default(
    registered_probe_ids=runner.probe_ids,
)
packet = graph.query(
    KnowledgeQuery(
        keywords=("dns", "timeout"),
        categories=("dns", "network"),
        max_relations=12,
        max_chars=24_000,
    )
)
related = graph.expand(
    start_node_ids=("kn_dns_resolution",),
    max_depth=2,
    max_nodes=24,
    max_edges=32,
)
```

`load_json` reads at most 4 MB and validates the complete file before returning a graph. Packs are
limited to 128 sources, 512 nodes, and 2,048 relations. It rejects duplicate IDs, dangling node or
source references, and referenced probe IDs absent from the caller's real registered catalog.
Query returns at most 64 relations; expansion is limited to depth 4, 64 nodes, and 128 edges. Both
paths report omitted relationships and serialize an explicit non-causality limitation.

During an investigation, `focused_packet` selects at most six conditional relations within a
6,000-character packet. Exact, locally recognized error or Wi-Fi node anchors are considered first;
when the objective names a separate symptom branch, a small anchor quota reserves room for it.
Remaining relations rotate across source-node categories with stable ID tie-breaking. The selector
uses bounded objective and hypothesis wording, not proof from machine evidence; its vocabulary and
packet limits can still miss a relevant mechanism. It preserves the loaded pack's IDs, version,
sources, and limitations and does not promote reference relations into observed or causal edges.
This retrieval change adds no sources, nodes, or diagnostic-performance claim.

The bundled `windows-it-reference` v6 pack contains 136 curated conditional mechanism relations across
applications, services, processes, devices, drivers, storage, file systems, networking, DNS,
proxying, TLS, power, hardware, security, Windows Update, native runtimes, CUDA, gaming, and PDF performance. Every edge has
conditions, symptoms, legacy registered probe hints, counterevidence, limitations, OS
applicability, and one or more source landing-page links. Those links are not
revision-pinned or hash-verified in the bundled schema-v1 pack, so the pack is
not yet an independently authenticated, broad IT dependency corpus. The compact
authoring format is specified
by `src/systemsense/knowledge/data/reference_pack.schema.json`; runtime Pydantic validation is the
enforced schema.

Schema v3 adds explicit probe roles: *screening* probes can show that a branch is
worth exploring, while *discriminating* probes have a reviewed claim about which
competing mechanisms their outcomes separate; unavailable probes remain a
declared gap. The legacy v1/v2 `distinguishing_probe_ids` field is mapped only
to screening, because its historical wording is not evidence that a collector
actually distinguishes causes. The coordinator can auto-request a reference
probe as a discriminator only from an explicit v3 discriminating role. The
bundled pack is still v1 and is not silently promoted. The v3 contract and
runtime validation are in `src/systemsense/knowledge/data/reference_pack.v3.schema.json`;
no source artifact has been re-reviewed merely because the schema exists.

Schema v2 is available at `src/systemsense/knowledge/data/reference_pack.v2.schema.json` for new,
independently reviewable packs. The bundled v1 pack remains readable without changing its retrieval
or output format. In a v2 pack, every relation has its own `reviewed_at` date and one `citations`
entry for each `sources` ID. Each citation records the source ID, a full commit hash or declared
published version, the section reviewed, a license identifier, the license terms URL, a direct HTTPS
`pinned_url` for the exact source artifact, and `content_sha256` of that artifact's bytes. The
`KnowledgeSource.url` remains a human-friendly landing page and may move. The loader requires the
declared revision in the pinned URL's path or query and a lowercase 64-digit SHA-256 digest; URL
fragments cannot carry the revision because servers do not receive them. It rejects missing or
unmatched citations, duplicate citation sources, moving branch names, invalid review dates, and
unregistered probes. Validation does not fetch the artifact or verify its hash. The separate source
admission review must retrieve the pinned URL, hash the exact returned bytes, check the cited section
and license, and retain the reviewed artifact or a durable archive reference. A declared release
version or URL can still move; the digest exposes changed bytes during that review. Neither this
metadata nor a successful source check proves that an upstream claim applies to a particular Windows
build or incident.

For each proposed v2 relation, a reviewer must check the cited section and license, write an
original conditional mechanism, identify applicable versions and counterevidence, and name a
registered read-only probe that can distinguish it. Keep source licenses and any required notices
with the source review record. A schema-valid relation is a candidate for diagnosis, not an
observation or proof of cause. Do not convert CIM/WMI associations or telemetry names directly into
causal relations.

The gaming branch distinguishes actual low game-produced FPS from low perceived display smoothness.
It links frame caps, render-adapter selection, graphics workload and render scale, driver regression,
clock/power/thermal limits, CPU/GPU contention, and graphics-memory pressure to tests and counterevidence. The existing collectors can
sample aggregate NVIDIA telemetry and CPU pressure and observe the calling desktop's current display
mode. They cannot yet measure game frame times, the game's actual display or dynamic refresh changes,
in-game caps or render scale, or per-game GPU-engine use. These are explicit coverage gaps, so no
reference edge may be presented as an observed cause or a verified game-performance repair.

The PDF branch records a local page-action dependency on viewer execution and
conditional routes through CPU interference, image-intensive content, Acrobat
next-page caching, 2D graphics acceleration, and accessibility reading-order
processing. These are screening routes, not measurements of this machine or
explanations of slowness. The registered probes can sample process pressure
and adapter inventory, but cannot inspect Acrobat preferences or PDF content,
measure page-action latency, or identify the viewer thread's critical path.
Accessibility features must not be disabled as a generic speed fix. A storage-wait branch is deferred
until a probe can measure per-volume latency and relate the document's reads to
that volume. The selected-process probe is deliberately absent from
model-routable references because it requires an explicit user-bound identity.

## Source policy

The pack contains independently written, short factual summaries and source URLs. It does not copy
documentation text or redistribute upstream databases. Primary sources reviewed for the
current pack include:

- Microsoft Learn product documentation for WER, SCM, processes, Device Manager/SetupAPI, Disk
  Management, NTFS/ReFS, DNS Client, Windows Filtering Platform, WinHTTP, Schannel, Modern Standby,
  WHEA, Defender, Windows Update, WLAN connectivity, and DLL loading. Microsoft Learn's general terms restrict copying
  and redistribution, so the pack stores citations and original summaries only:
  <https://learn.microsoft.com/en-us/legal/termsofuse>.
- NVIDIA's CUDA Compatibility documentation for driver/runtime compatibility:
  <https://docs.nvidia.com/deploy/cuda-compatibility/latest/>. The pack links to the documentation
  and does not redistribute NVIDIA documentation or software.
- Microsoft DirectX and display documentation, NVIDIA control-panel and telemetry documentation,
  and Intel gaming guidance for conditional low-FPS mechanisms. Source URLs accompany individual
  relations; current telemetry gaps remain limitations rather than inferred measurements.
- Microsoft Windows Performance Toolkit CPU analysis for conditional PDF viewer
  scheduling investigation. No PDF-specific causal claim is imported from that
  general performance source.
- Adobe Acrobat viewing and accessibility documentation for conditional PDF
  performance routes. These apply only to the affected Acrobat configuration,
  not every PDF viewer. The source landing pages are
  <https://helpx.adobe.com/acrobat/using/viewing-pdfs-viewing-preferences.html> and
  <https://helpx.adobe.com/acrobat/using/reading-pdfs-reflow-accessibility-features.html>.
- Microsoft Windows client wireless and network troubleshooting documentation for
  WLAN AutoConfig, radio state, DHCP assignment, and DNS-server distinctions.
  Client inventory alone cannot localize a DHCP server, relay, or resolver fault.

The following existing graphs/catalogs were evaluated and intentionally not bulk-imported:

- **MITRE ATT&CK** is authoritative for adversary behaviors and permits research, development, and
  commercial use with its required notice: <https://attack.mitre.org/resources/terms-of-use/>. It is
  valuable for a future security-specific reference pack, but is not a general Windows reliability
  or diagnostic-causality graph.
- **CWE** is a licensed weakness taxonomy, not a machine troubleshooting graph. Its terms permit
  research, development, and commercial use: <https://cwe.mitre.org/about/termsofuse.html>. Mapping
  weaknesses directly to observed Windows symptoms would manufacture unsupported causal claims.
- **DBpedia** extracts broad encyclopedic relations under CC BY-SA 3.0 and GFDL:
  <https://www.dbpedia.org/about/>. Its breadth, weak diagnostic specificity, and share-alike
  obligations make it a poor bundled source for this focused pack.

Future pack changes should update `version` and `reviewed_at`, retain stable IDs for unchanged
semantics, add a new ID when semantics change, and include a focused test that demonstrates the new
retrieval or validation behavior. Machine-specific dependencies such as the actual service
`DEPENDS_ON` relation still belong to collectors and the evidence graph, never this reference pack.
Before expanding the bundled pack, compare a candidate v2 pack against the existing pack on held-out
Windows incidents under the same probe budget and source snapshot. Admit it only if reviewers can
trace the citations, counterevidence, and probe choice and it improves diagnostic quality without
concealing unsupported or unavailable evidence.

## Installed Windows error catalog

`systemsense.knowledge.windows_errors` provides a separate runtime-backed lookup for exact Windows
error identifiers. It does not bundle or copy `winerror.h`. On Windows it filters the installed
`pywin32.winerror` constants to the Win32, Winsock, DNS, RPC, and endpoint-mapper error families,
then asks the local system message table through `win32api.FormatMessage`. On other platforms or
without pywin32 it returns an empty, explicitly unavailable catalog rather than fabricated text.

```python
from systemsense.knowledge.windows_errors import WindowsErrorCatalog, reference_for_text

catalog = WindowsErrorCatalog.from_runtime()
access = catalog.lookup_win32(5)
port = catalog.lookup_symbol("WSAEADDRINUSE")
hresult = catalog.lookup_hresult("0x80070005")
references = reference_for_text("The API returned Win32 error 5", max_items=4)
```

Text retrieval recognizes only `Win32 error N`, `HRESULT 0xXXXXXXXX`, and exact uppercase symbols
present in the filtered runtime catalog. It deliberately ignores bare integers, bare hex values,
event IDs, PnP problem codes, and hardware IDs. `HRESULT` conversion is accepted only for the exact
failure form produced by `HRESULT_FROM_WIN32` with `FACILITY_WIN32` (facility 7); unrelated HRESULT
facilities are not reinterpreted as Win32 codes. Results include the local OS and pywin32 versions,
constant aliases, the local message or an explicit absence, source URLs, bounded reviewed `kn_*`
mappings, and a limitation that an error code is not causal proof.

Microsoft documents that system error descriptions should be retrieved with `FormatMessage`, and
warns that unknown messages must be handled with inserts ignored. The implementation formats only
codes admitted from the installed error families and never executes text returned by the message
table. The exact `HRESULT_FROM_WIN32` bit mapping and `FACILITY_WIN32` meaning come from Microsoft:

- <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-formatmessage>
- <https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499->
- <https://learn.microsoft.com/en-us/windows/win32/api/winerror/nf-winerror-hresult_from_win32>
- <https://learn.microsoft.com/en-us/windows/win32/com/structure-of-com-error-codes>

Catalog size is runtime metadata, not a bundled product claim. On the verified Windows host,
pywin32 312 exposed 7,229 uppercase integer constants; the reviewed filters admitted 3,126 exact
symbols representing 3,116 distinct Win32 codes. Counts may change with the installed SDK-derived
pywin32 catalog.

The investigator resolves error references only from the user objective, with at most four results.
Reviewed `kn_*` mappings become seeds for the same bounded reference graph supplied to the fast and
reasoning providers. The reasoning request and case report also carry the typed error records under
`error_references`. They are labeled reference semantics, never evidence or measurements; they have
no evidence ID and cannot satisfy a hypothesis citation. If the local model context is too small,
error references are reduced and then omitted before observed evidence, with an explicit context
limitation. No catalog dump, live lookup network request, event-message scan, or inference-generated
code interpretation occurs.
