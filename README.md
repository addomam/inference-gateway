# infer

Rust HTTP inference gateway. Separate inference and control listeners; native provider passthrough, cross-provider translation, and persistent request/response traces. Inbound TLS belongs at your reverse proxy; upstream HTTPS uses rustls.

All original material in this repository is dedicated to the public domain under [CC0-1.0](LICENSE). Third-party material and dependencies retain their applicable terms and attribution. See [third-party notices](THIRD_PARTY_NOTICES.md) for the Apache-2.0 schema test fixtures and dependency-distribution requirements.

## Contents

- [Run](#run) and [routing](#routing)
- [API and media compatibility](#current-api-and-media-compatibility)
- [OpenAI Decisions](#openai-decisions), [System One / Jev](#system-one--jev), and [Cloudflare Clairic](#cloudflare-clairic)
- [Authentication and subscriptions](#authentication-and-subscriptions)
- [Claude Code → ChatGPT subscription](#claude-code--chatgpt-subscription)
- [Inspect and export](#inspect-and-export), including [OMP traces](#omp-execution-traces)
- [Local-history imports](#native-local-history-imports) and [provider account exports](#provider-account-export-imports)
- [Reverse proxy and operations](#reverse-proxy-and-operations)
- [Integration validation](#integration-validation)
- [Architecture](docs/architecture.md), [data flow](docs/data-flow.md), and [database schema](docs/database-schema.md)
- [Development conventions](CONVENTIONS.md)

## Run

```sh
cargo build --release --locked
# Choose different, randomly generated values (at least 16 visible ASCII characters, no whitespace).
export INFER_PROXY_TOKEN="$(openssl rand -hex 32)"
export INFER_CONTROL_TOKEN="$(openssl rand -hex 32)"
./target/release/infer --config infer.toml check
./target/release/infer --config infer.toml serve
```

Create `infer.toml` from `infer.example.toml`, **removing providers you do not use** and setting the remaining provider credential environment variables. Environment variables are read by the process, not interpolated in TOML. Paths do not expand `~`. Both listeners default to loopback. Configuration changes require restart. `check` validates configuration and environment credential availability. For Codex, it reads the same bounded regular-file snapshot used at request time and verifies either usable current access/account headers or a valid refresh token; it never refreshes, contacts the network, or writes credentials. It does not prove upstream entitlement or perform an inference request.

Minimal local llama.cpp configuration (`llama-server --port 8082`):

```toml
proxy_token_env = "INFER_PROXY_TOKEN"
control_token_env = "INFER_CONTROL_TOKEN"
default_provider = "local"

[providers.local]
kind = "llama"
base_url = "http://127.0.0.1:8082"
```

### Routing

* `/providers/NAME/PATH`: native passthrough. For example `/providers/anthropic/v1/messages`, `/providers/openai/v1/responses`, `/providers/openai_decisions/v1/decisions`, `/providers/typesafe/v1/systemone`, `/providers/cloudflare/client/v4/accounts/ACCOUNT/ai/run/@cf/cloudflare/clairic`, `/providers/grok/v1/chat/completions`, `/providers/llama/v1/chat/completions`. Arbitrary HTTP methods, paths, query strings, binary bodies, provider errors, and SSE are forwarded. No schema translation or model aliasing. A Codex provider uses `/providers/chatgpt/responses` because its configured base includes `/backend-api/codex`.
* `POST /v1/messages`, `/v1/chat/completions`, `/v1/responses`: resolve `model` by an exact `[models]` alias, then by a configured provider `namespace` (`xai/grok-4.7` selects namespace `xai` and sends upstream model `grok-4.7`), then by the compiled model catalog, otherwise use `default_provider` and the original model. A catalog hit selects a configured provider of that model's family that speaks a reachable dialect. A known model on an unsupported route is rejected. An unknown id falls through and logs a warning so the catalog can be updated. A slash whose prefix is not a configured namespace stays part of the model id. Translate to the destination dialect when necessary. No automatic fallback, hidden model substitution, or inference retries.
* `POST /v1/decisions`: the same model resolution for OpenAI Decisions requests. A provider that speaks Decisions forwards the body. A provider that speaks System One, including local Jev on llama.cpp, translates predicate/choice/score questions and text input, then maps named answers back. A System One client can target a Decisions provider the same way for string state and those three question types. Images, files, Box questions, object state, and unknown question types are rejected. Only a changed `model` is rewritten on a native Decisions provider.
* `POST /v1/systemone`: the same model resolution for JSON System One requests (`model`, `state`, `questions`). The selected provider must speak System One (`system_one` or `llama`), or speak Decisions, in which case string state and noul/choice/score questions are translated. Only a changed model is rewritten on a native System One provider; typed answers, probabilities, confidence, usage, and the upstream's resolved model name pass through unchanged. Cataloged Jev ids `jev-latest`, `jev-preview`, and `jev-1.14` accept images and Box questions; `jev-1.13` accepts images but not Box. Those requests must send `TypeSafe-Danger-Zone-Images: true`, unless the provider sets `danger_zone_images = true`, in which case infer adds the header. Other cataloged models reject both. Uncataloged models are not schema-filtered.
* `POST /v1/embeddings`: the same model resolution for OpenAI Embeddings requests. `openai` and `llama` forward the body to `/v1/embeddings`; an alias changes only `model`. String, string-array, and token-array `input`, `encoding_format`, and `user` pass through. llama.cpp ignores `dimensions` and would return the model width, so that field is rejected before dispatch. `text-embedding-ada-002` is rejected the same way. OpenAI embedding models accept text and token arrays only. `ggml-org/embeddinggemma-2-GGUF:Q8_0` also accepts llama.cpp `image_url`, `input_audio`, and `input_video` content parts. Remove `dimensions` or use a model that applies it.
* Daybreak is not a separate upstream model. `gpt-6-sol#daybreak-blue`, `gpt-6.1-sol#daybreak-blue`, `gpt-6-astra#daybreak-blue`, and `gpt-5.6-cyber#daybreak-red` resolve to the base model and set Responses `access_programs.cyber`. An OpenAI provider `daybreak` ceiling defaults to `standard`, which rejects those programs and omits the matching models from `GET /v1/capabilities`. Set `daybreak = "blue"` or `"red"` to allow them. infer does not query upstream entitlement for this flag; the ceiling is local configuration.
* `POST /client/v4/accounts/ACCOUNT/ai/run/@cf/cloudflare/clairic`: the canonical Cloudflare Workers AI route. The body `model` uses the same resolution, and the selected provider must have `kind = "clairic"`. Current SDK percent-encoding of the model path is accepted and normalized to Cloudflare's slash-separated upstream route. The account remains the caller-supplied path component.
* `GET /v1/capabilities`: the machine-readable route, provider, and model document for this process. It lists catalog models a configured provider can serve, including Daybreak ids only when that provider's ceiling allows them. `/v1/models` remains the selected backend's own list, not this document.
* `POST /v1/audio/transcriptions` and `POST /v1/audio/speech`: OpenAI audio routes. The selected model must declare `transcribe`, `diarize`, or `speak`, and the provider must already speak that OpenAI path. `response_format=diarized_json` requires `diarize`. A transcriber does not call a second diarization model. A local model not in the catalog can declare operations on its `[models]` alias. Unknown models may transcribe or speak only when the provider speaks the route; they cannot diarize. Routed audio is buffered to `max_request_bytes`.
* `POST /v1/audio/diarization`: speaker turns only (`file`, `model`, optional `response_format` of `json` or `rttm`). A model must declare `diarize` and not `transcribe`. `include_text` is rejected. No configured provider speaks this route, so a valid request fails closed instead of falling through. A transcription model that also declares `diarize` stays on `/v1/audio/transcriptions`.
* Audio and video generation input require a provider that already speaks the client protocol. Catalog records and explicit `[models]` alias `modalities` declarations constrain accepted input. Unknown models without declarations defer media support to the provider. infer does not transcribe, sample, or translate audio/video input. Image URL and data-URL translation is unchanged.
* `GET /v1/realtime`: WebSocket proxy. The `model` query must resolve to a model that declares `realtime` and a provider that speaks that websocket. infer rewrites the provider credential and copies frames. It does not run a voice pipeline. Any other upgrade remains HTTP 501.
* `POST /v1/files`: stores the bytes in the same content-addressed blob tree as trace artifacts and returns an infer id (`file-` plus 32 hex digits). `purpose` must be `user_data` or `vision`. A later routed JSON request that contains that id uses a cached file id for the selected provider, if available. Otherwise infer uploads the bytes, remembers the provider's file id, and sends that id instead. Concurrent first uses can upload the same bytes more than once. `openai`, `grok`, and `anthropic` accept the upload. Other providers reject the request. `GET /v1/files/{id}` and `GET /v1/files/{id}/content` read the stored bytes. `DELETE` removes the index row and leaves the blob. `/v1/uploads` is refused. `/providers/NAME/v1/files` remains the raw provider pipe and does not create an infer id.
* Root account-product paths return HTTP 501: `/v1/assistants`, `/v1/threads`, `/v1/batches`, `/v1/fine_tuning`, `/v1/fine-tunes`, `/v1/vector_stores`, `/v1/evals`, and their child paths. Explicit provider paths retain native passthrough for these APIs.
* Other paths use native passthrough to `default_provider`. `/v1/models` queries that backend rather than a synthesized union. `/v1/messages/count_tokens` is native-only, not an approximate tokenizer for translated models.

Provider kinds: `anthropic`, `openai`, `openai_decisions`, `grok`, `llama`, `codex`, `system_one`, `clairic`. `openai` and `llama` also speak OpenAI embeddings. `openai_decisions`, `system_one`, and `clairic` are native typed APIs rather than generation dialects; `openai` remains a generation provider. Optional `namespace` is the client model prefix for that provider. Two providers may share a namespace only when they implement different APIs; the same namespace and API is a configuration error. A configured namespace sent to an API that provider does not implement returns HTTP 400. `base_url` normally contains the origin **without `/v1` or `/client/v4`**. A deployment path prefix is allowed. Redirects are returned, never followed with provider credentials. Outbound connections intentionally ignore `HTTP_PROXY`/`HTTPS_PROXY` environment settings.

Native GET bodies stream upstream, including chunked uploads. infer normalizes URLs before dispatch and rejects normalized paths that escape the configured deployment prefix before credential resolution. infer also rejects Cloudflare account components with dot segments or encoded slashes or backslashes. Traces record the actual resolved URL.

### Current API and media compatibility

“Native” below means ordinary HTTP forwarding through `/providers/NAME/PATH`; it is not a claim that the configured account or model is entitled to the upstream feature. Native requests are not schema-filtered or model-aliased. “Routed” means model selection on a named API route through aliases, provider namespaces, the model catalog, or the default provider. All media capability remains model- and provider-specific.

Byte-preservation statements below assume no infer-owned file references. Routed JSON containing infer-owned `file`/`file_id` values can upload files and replace those IDs, even when the model is unchanged. Explicit provider paths bypass that resolution.

| API family | Native and routed compatibility | Cross-protocol boundary |
|---|---|---|
| OpenAI Chat Completions (`/v1/chat/completions`) | Native is arbitrary HTTP. Routed JSON preserves same-Chat fields; an unchanged model leaves request bytes unchanged, while model resolution can rewrite only `model`. Images by URL/data URL, Chat PDF/file parts, `input_audio`, audio configuration/history/output and native SSE therefore stay native on a Chat backend. | Translation supports ordered text, URL/data-URL images and function calls/results. File and audio parts, audio output and other unmatched media reject explicitly. There is no legacy `/v1/completions` route. |
| OpenAI Responses (`/v1/responses`) | `openai`, `grok`, `llama` and `codex` already retain the Responses protocol. Native/same-protocol requests preserve `input_image` file IDs, `input_file`, built-in image-tool fields, media output and SSE rather than converting them to Chat. Codex routed requests have the separately documented rewrites. | Only ordered text, URL/data-URL images and function calls/results are translated. File-ID images, files/documents and provider-native output items require native/same-Responses routing. |
| Anthropic Messages (`/v1/messages`) | Native/same-Anthropic requests retain URL/base64/file-ID images, documents, citations, provider tools, cache controls, beta headers and native SSE. | URL/base64 images are representable. Files/documents, citations, opaque thinking and provider tools require native Anthropic. Image tool results map to Responses, not Chat. Cache and tool-error approximations are declared below. |
| OpenAI Decisions (`/v1/decisions`) | Native or same-protocol routed JSON. Model resolution changes only `model` when needed; ordered typed questions/answers, image evidence, refusals, confidence/probabilities, cache/safety fields, usage, status, headers and body remain native. | Text input and predicate/choice/score questions can translate to System One and back. Images, files, Box questions, object state, and unmatched fields require native routing. No generation/extraction conversion or synthetic Decisions SSE. |
| OpenAI Embeddings (`/v1/embeddings`) | Native is arbitrary HTTP. Routed JSON on `openai` and `llama` preserves the body; model resolution changes only `model` when needed. `encoding_format`, string and token-array `input`, and `user` pass through. Responses stay the provider's embedding list. | No generation, Decisions, or extraction conversion. llama.cpp does not apply `dimensions` and would return the model width, so that field is rejected before dispatch. Multimodal llama.cpp input objects are not rewritten into the OpenAI text contract. |
| TypeSafe System One (`/v1/systemone`) | Native is arbitrary HTTP. Same-protocol routed JSON and SDK-shaped multipart support model resolution plus one `gzip`, `x-gzip` or `zstd` layer. Multipart retains binary assets; responses and provider errors stay typed/native. | JSON string state and noul/choice/score questions can translate to Decisions and back. Other state, assets, Box questions, and unmatched fields require native System One. No generation conversion. Routed limits are 32 MiB for encoded, decoded and rewritten bodies, with an 8 MiB zstd window; native bypass is not decoded or rewritten. |
| Cloudflare Clairic (`/client/v4/accounts/ACCOUNT/ai/run/@cf/cloudflare/clairic`) | Canonical routed JSON preserves embedded PNG/JPEG/WebP inputs and the complete Cloudflare REST envelope, including typed/null answers, spans, confidence, distributions, `truncated`, state text, usage and errors. The explicit provider path is fully native. | No Chat/Decisions approximation, remote-image fetching or schema validation. The account and resources remain in the caller-supplied Cloudflare path. |

Routed generation JSON is buffered and must fit `max_request_bytes` (32 MiB by default); it does not decode compressed JSON or parse multipart. Translated buffered responses must fit `max_buffered_response_bytes` (also 32 MiB by default). Translated SSE bounds an event and aggregate pending semantic state to 8 MiB and tracks at most 4096 open/completed blocks. Native HTTP uploads and responses stream with backpressure instead of using those routed buffers, but trace storage, client/reverse-proxy limits and upstream limits still apply.

Native payload fidelity is not identical HTTP framing. infer replaces provider credentials and `Host`, removes hop-by-hop and `Connection`-nominated headers, requests `Accept-Encoding: identity`, and may regenerate lengths/chunk framing. It preserves body bytes, query strings, ordinary content headers, upstream status/errors, redirects, provider-supplied encodings/digests and native SSE without interpreting media events. Body rewrites remove stale encoding, length and digest claims. The dedicated `GET /v1/realtime` route supports WebSockets for a declared realtime model and compatible provider. Other upgrades and CONNECT return HTTP 501. Ordinary Realtime signaling/control HTTP can pass natively; WebRTC media/data channels are outside infer.

#### Dedicated native HTTP media workflows

Use one explicit provider for the whole resource lifecycle. For example, the official OpenAI client base is `http://127.0.0.1:8080/providers/openai/v1`, the Anthropic base is `http://127.0.0.1:8080/providers/anthropic`, and an OpenAI-compatible xAI client base is `http://127.0.0.1:8080/providers/grok/v1`. Supply the infer gateway token to the client; configure the provider credential on infer. Provider/project/account-scoped file and job IDs are opaque: upload, consume, poll, download and delete through the same explicit provider and credential scope. A `[models]` alias neither routes these dedicated endpoints nor transfers a resource to another provider.

| Workflow | Native method/path and boundary |
|---|---|
| OpenAI Images | `POST /providers/openai/v1/images/generations` with native JSON. Edits support the current REST JSON reference form (`images` containing URL/data-URL or `file_id` references) and the official SDK multipart form at `/images/edits` (`image` or repeated `image[]`, optional `mask`, scalar `model`). Native JSON/base64 and supported image-event SSE remain unchanged; infer does not decode, convert or fetch images. |
| OpenAI speech/transcription | `POST /providers/openai/v1/audio/speech` takes native JSON and returns raw audio, or native SSE when the selected model supports `stream_format:"sse"`. `POST /audio/transcriptions` is multipart `file` plus scalar `model` and returns the model-selected JSON/text/SRT/VTT/SSE shape. `POST /audio/translations` uses multipart and currently translates to English with `whisper-1`; it is not arbitrary target-language translation. infer imposes no copied media-format allowlist. |
| OpenAI Files/Uploads | Direct files: multipart `POST /v1/files`, then native metadata/list/content/delete operations under `/v1/files/{id}`. Segmented uploads: JSON `POST /v1/uploads`, multipart `POST /v1/uploads/{id}/parts`, ordered JSON `POST /v1/uploads/{id}/complete`, or cancel. Current published limits are 512 MB per direct file, 8 GB per segmented upload, 64 MB per part and one hour before an incomplete upload expires; consuming APIs have separate lower/type limits. |
| Anthropic files/documents | Use native `/providers/anthropic/v1/files` operations and native Messages image/document sources, retaining provider version headers and applicable feature headers. The Files API is generally available and does not require a Files beta header. The legacy `files-api-2025-04-14` header remains supported with its older response shape. infer does not download, extract or re-upload a document, and does not treat an Anthropic file ID as an OpenAI file ID. |
| xAI images/video/audio | Images use native JSON `/providers/grok/v1/images/generations` and `/images/edits`; xAI-specific deferred image jobs poll `/v1/images/{request_id}`. Active video uses JSON `POST /v1/videos/generations` and consumer-driven `GET /v1/videos/{request_id}` polling. The completed `video.url` is returned, not fetched. xAI TTS is JSON `POST /v1/tts`; STT is native multipart `POST /v1/stt` with the file part last when required by the upstream contract. These are not inferred OpenAI Audio/Video aliases. |
| llama.cpp speech | A supporting deployment exposes native `POST /providers/llama/tts`, returning WAV or PCM from JSON or its optional multipart speaker-reference form. General Chat/Responses compatibility does not imply OpenAI Images, Files or Audio endpoints. |

Representative native calls:

```sh
OPENAI_BASE=http://127.0.0.1:8080/providers/openai/v1
GROK_BASE=http://127.0.0.1:8080/providers/grok/v1

# JSON generation; the response remains the provider's image envelope.
curl "$OPENAI_BASE/images/generations" \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-image-2.5-sunburst","prompt":"A blue square","output_format":"png"}'

# Official-SDK-shaped multipart edit. Let curl generate the multipart boundary.
curl "$OPENAI_BASE/images/edits" \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -F model=gpt-image-2.5-sunburst \
  -F 'image[]=@fixture.png;type=image/png' \
  -F prompt='Make the background blue'

# The current REST JSON edit form can reference an existing same-provider file.
curl "$OPENAI_BASE/images/edits" \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-image-2.5-sunburst","prompt":"Add a border","images":[{"file_id":"file_same_provider"}]}'

# Binary speech is not JSON; use an output file. Set stream_format to sse only
# for a model that publishes speech SSE support.
curl "$OPENAI_BASE/audio/speech" \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini-tts","input":"Fixture sentence.","voice":"coral","response_format":"wav"}' \
  --output speech.wav

# Recorded transcription consumes the file directly, not an invented file_id.
curl "$OPENAI_BASE/audio/transcriptions" \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -F model=gpt-transcribe \
  -F 'file=@fixture.wav;type=audio/wav'

# xAI video is an asynchronous native job. Poll explicitly; infer does not poll
# or access the returned media URL.
curl "$GROK_BASE/videos/generations" \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"grok-imagine-video-1.5","prompt":"A paper boat"}'
curl "$GROK_BASE/videos/job_id_from_previous_response" \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN"
```

OpenAI's retained Videos SDK/reference symbols are historical, not an active compatibility claim: the provider states that Sora 2 and the Videos API shut down on **September 24, 2026**, with no one-to-one replacement. Native forwarding may still expose the upstream error but infer does not advertise successful OpenAI video creation/content retrieval. OpenAI also currently states that the HTTP Speech models shut down on **January 6, 2027** and recommends a Realtime model that is not supported by `/v1/audio/speech`; changing an alias is not a transport migration. Audio translations and older transcription models are scheduled to shut down on **February 26, 2027**; recorded transcription has a same-endpoint replacement, while translation's documented replacement changes workflow.

Primary contracts checked **2026-10-25**: [OpenAI Images](https://developers.openai.com/api/reference/resources/images/methods/edit), [image guide](https://developers.openai.com/api/docs/guides/image-generation), [Audio](https://developers.openai.com/api/reference/resources/audio), [speech](https://developers.openai.com/api/docs/guides/text-to-speech), [recorded transcription](https://developers.openai.com/api/docs/guides/speech-to-text), [Files](https://developers.openai.com/api/reference/resources/files/methods/create), [Uploads](https://developers.openai.com/api/reference/resources/uploads/methods/create), [Videos shutdown](https://developers.openai.com/api/reference/resources/videos/methods/create), [deprecations](https://developers.openai.com/api/docs/deprecations), [Anthropic Files](https://platform.claude.com/docs/en/build-with-claude/files), [Anthropic PDFs](https://platform.claude.com/docs/en/build-with-claude/pdf-support), [xAI Images](https://docs.x.ai/developers/rest-api-reference/inference/images), [xAI video](https://docs.x.ai/developers/model-capabilities/video/generation), [xAI TTS](https://docs.x.ai/developers/model-capabilities/audio/text-to-speech), [xAI STT](https://docs.x.ai/developers/model-capabilities/audio/speech-to-text), and [llama.cpp `/tts`](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md#post-tts-generate-speech-audio-from-text). These contracts do not prove current account entitlement or a particular deployed model's media support.

#### Exact translation media boundary

Cross-protocol conversion is deliberately smaller than native/same-protocol forwarding. It preserves ordered text, function calls and IDs, URL images, and base64 images via data URLs. Chat/Responses image detail `auto` maps to Anthropic; explicit `low`, `high` or `original` cannot be represented and fails before upstream contact. Images inside Anthropic tool results can map, in order, to Responses function output; Chat cannot represent that screenshot result and rejects it. File/document/audio/video parts, file-ID resolution, citations and unmatched output media never become a successful text-only substitute. Unsupported buffered output returns HTTP 502; unsupported translated SSE ends without a successful terminal marker and records the trace error. The native counterpart remains unparsed.

Two intentional compatibility approximations qualify the general reject-not-drop rule:

* Anthropic `cache_control` on tools and content blocks is discarded only during cross-protocol translation. No breakpoint, TTL, eligibility, cache-price or latency policy is promised on the target. Top-level unsupported policy still errors. Native and same-Anthropic requests preserve the controls; cache-policy-sensitive requests must use those paths. A fixture can prove field handling, not a provider cache hit.
* Anthropic `tool_result.is_error: true` is textualized for targets without that typed flag. All-text Chat/Responses output becomes the exact string prefix `[Tool error]\n` followed by the normalized concatenation of text blocks. Multimodal Responses output receives a leading `{"type":"input_text","text":"[Tool error]"}` before the original ordered text/image parts. Content and an error signal survive, but the typed flag and all-text segmentation are not losslessly reversible. infer never parses arbitrary user tool text to reconstruct `is_error`; use native Anthropic when the typed distinction matters.

Native and same-protocol paths do not apply either approximation.

```sh
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"model":"local-model","messages":[{"role":"user","content":"Hello"}],"stream":true}'
```

### OpenAI Decisions

The [OpenAI Decisions contract](https://developers.openai.com/api/docs/guides/decisions) uses `POST /v1/decisions`; OpenAI SDKs expose it as `client.decisions.create(...)`. Configure a separate decision-only provider and an optional exact alias:

```toml
[providers.openai_decisions]
kind = "openai_decisions"
base_url = "https://api.openai.com"
[providers.openai_decisions.auth]
mode = "api_key"
token_env = "OPENAI_API_KEY"

[models.luna]
provider = "openai_decisions"
model = "gpt-6-luna"
```

```sh
curl http://127.0.0.1:8080/v1/decisions \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "luna",
    "input": [{"role":"user","content":[
      {"type":"input_text","text":"Inspect this item"},
      {"type":"input_image","image_url":"https://example.test/item.png","detail":"original"}
    ]}],
    "questions": [
      {"type":"predicate","instructions":"Is it damaged?"},
      {"type":"choice","name":"route","instructions":"Choose","choices":[{"value":true},{"value":"true"}]},
      {"type":"score","name":"priority","instructions":"Rate","levels":[{"label":"low"},{"label":"high","description":"Act now"}]}
    ]
  }'
```

On a Decisions provider, requests remain provider-native and schema-free at the gateway. This preserves optional names, typed string/boolean choices, question and answer order, per-question refusals, prompt-cache and safety fields, current provider extensions, JSON/conversation evidence, and image references without duplicating OpenAI validation. With an unchanged model, infer forwards the original bytes and content/digest headers. Model resolution changes only `model` using the precision-safe JSON path and records distinct original/upstream bodies. `/providers/openai_decisions/v1/decisions` is the fully undecoded, unaliased native path.

The provider response is never wrapped as Chat/Responses output or synthesized as SSE. Routed Decisions can target System One, and routed System One can target Decisions, through the limited [typed conversion](#routing). This conversion requires text/string state and predicate/noul, choice, or score questions. Images, files, Box questions, and object state are rejected before dispatch. Unsupported top-level and question fields also reject before dispatch.

Conversion discards extra input-message and text-part metadata. Use native routing to preserve those fields.

Messages, Chat, Responses, and extraction do not convert to Decisions. OpenAI API-key entitlement is separate from a ChatGPT/Codex subscription: infer never sends Decisions to the Codex subscription `/responses` endpoint. No legacy `/v1/decision` or `/v1/completions` compatibility endpoint is provided.

### System One / Jev

Jev uses the [TypeSafe System One API](https://docs.typesafe.ai/api/system-one), not a text-generation API. Add this provider and optional alias to your configuration, and set `TYPESAFE_API_KEY` in infer's environment:

```toml
[providers.typesafe]
kind = "system_one"
base_url = "https://api.typesafe.ai"
[providers.typesafe.auth]
mode = "api_key"
token_env = "TYPESAFE_API_KEY"

[models.jev]
provider = "typesafe"
model = "jev-latest"
```

```sh
curl http://127.0.0.1:8080/v1/systemone \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "jev",
    "state": {"message": "I was charged twice. Please refund the extra charge."},
    "questions": {
      "billing": {"type": "noul", "instructions": "Is this message about billing?"}
    }
  }'
```

The alias works even when your default provider is a chat backend. Cataloged Jev names select a compatible configured provider without a System One default. Unknown model names use `default_provider` unless an alias or configured namespace selects another provider. Explicit `/providers/typesafe/v1/systemone` passthrough skips model resolution and supports multipart/image uploads and compressed bodies without JSON rewriting. Use `/providers/typesafe/v1/models` to discover that backend's available models.

Official TypeSafe SDKs can use `http://127.0.0.1:8080` as their base URL with the gateway token as their API key. Routed `/v1/systemone` accepts JSON and multipart requests, including one `gzip`, `x-gzip`, or `zstd` encoding layer. Encoded, decoded, and rewritten bodies must fit both `max_request_bytes` and TypeSafe's 32 MiB limit; zstd windows are capped at 8 MiB. Unsupported or multiple encoding layers return HTTP 415; malformed compressed bodies or multipart request envelopes return HTTP 400; size violations return HTTP 413.

For multipart, the first part must be named `request` with content type `application/json`; model aliases are resolved from that JSON. If the model is unchanged, the original wire encoding, bytes, and valid digests are forwarded. An alias rewrite emits an uncompressed body, updates outer framing, and removes stale outer and JSON-part lengths/digests while preserving image parts byte-for-byte. Original client bytes and rewritten upstream bytes have separate trace artifacts. Explicit `/providers/typesafe/v1/systemone` remains an undecoded, unrewritten native bypass.

Provider headers such as `TypeSafe-Danger-Zone-Images: true` and `TypeSafe-Danger-Zone-Long-Context: true` pass through. Cataloged models must support the request's assets and Box questions, with the image opt-in described under [Routing](#routing). infer leaves asset references, image content validation, and other question schemas to the provider. Native responses retain upstream fields, including null confidence in Box answers. Image support and entitlement also depend on the selected backend.

For a System One provider, requests that pass these catalog gates retain their question types, state, assets, and extension fields. infer does not duplicate the provider's other schema validation or fabricate answers. System One responses stay native rather than being converted into chat messages or synthetic SSE. Other System One-compatible services use the same provider kind with their own `base_url` and credential environment variable.

### Cloudflare Clairic

Clairic uses Cloudflare's canonical Workers AI run route and native extraction body. Configure the Cloudflare API origin and bearer token. The compiled catalog resolves `@cf/cloudflare/clairic` to a compatible configured provider. An exact alias supports the short `clairic` spelling. The canonical alias below is optional and can select a provider when multiple compatible providers exist:

```toml
[providers.cloudflare]
kind = "clairic"
base_url = "https://api.cloudflare.com"
[providers.cloudflare.auth]
mode = "bearer"
token_env = "CLOUDFLARE_API_TOKEN"

[models.clairic]
provider = "cloudflare"
model = "@cf/cloudflare/clairic"

[models."@cf/cloudflare/clairic"]
provider = "cloudflare"
model = "@cf/cloudflare/clairic"
```

```sh
curl http://127.0.0.1:8080/client/v4/accounts/$CLOUDFLARE_ACCOUNT_ID/ai/run/@cf/cloudflare/clairic \
  -H "Authorization: Bearer $INFER_PROXY_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{
    "model": "clairic",
    "state": "Invoice INV-2291, issued 2026-09-02, net 30.",
    "fields": {
      "invoice_number": {"type": "text"},
      "due_date": {"type": "date"},
      "payment_days": {"type": "estimate", "min": 0, "max": 120, "step": 1}
    },
    "reference_date": "2026-10-22",
    "options": {"include_quantiles": true, "return_state_text": true}
  }'
```

The route is compatible with clients that construct `POST /accounts/{account_id}/ai/run/{model_name}` relative to a `/client/v4` base URL. Set an official Cloudflare SDK's base URL to `http://127.0.0.1:8080/client/v4` and use the infer gateway token as its API token. SDKs may expose only the inner `result`; raw REST clients receive Cloudflare's unchanged `{result, success, errors, messages}` envelope. infer also accepts the SDK-encoded model path `@cf%2Fcloudflare%2Fclairic` and sends Cloudflare the canonical slash-separated model path.

The body remains Cloudflare-native: `model` is `clairic` or `@cf/cloudflare/clairic`; `state` is not normalized; named text/number/date/time/datetime/duration/list/estimate/forecast fields, `reference_date`, options, embedded PNG/JPEG/WebP images, and extension fields pass through. Responses are not parsed into chat or decision output. Null scalar values keep guesses, spans, `p_null`, and confidence; empty lists, list spans, estimate distributions/quantiles/tails, forecast steps, `truncated`, `state_text`, and all usage counters remain in the REST envelope. HTTP success does not imply `truncated: false` or application-level `success: true`.

infer does not fetch image URLs, resize assets, validate Cloudflare's field schema, retry model calls, or claim hosted model entitlement. Use `/providers/cloudflare/client/v4/accounts/ACCOUNT/ai/run/@cf/cloudflare/clairic` for fully schema-free, unaliased byte-native forwarding. The provider `base_url` is the API origin or an intentional deployment prefix; do not include `/client/v4/accounts/ACCOUNT`, because the account is supplied by each canonical request.

### Authentication and subscriptions

Gateway authentication accepts `x-infer-key`, `Authorization: Bearer`, or `x-api-key`, in that precedence. Inference and control tokens must differ. These credentials are never forwarded as upstream credentials.

Provider `auth.mode`:

| Mode | Source | Upstream behavior |
|---|---|---|
| `none` | None | Unauthenticated backend, e.g. local llama.cpp |
| `api_key` | `token_env` | Anthropic `x-api-key`; otherwise bearer |
| `bearer` | `token_env` | Externally managed authorized bearer token |
| `passthrough` | Client | Forward the client's native authorization / API key |
| `codex` | `auth_file` | Load Codex subscription credentials; refresh expiring tokens |

For `passthrough`, authenticate to infer with **`x-infer-key`**, leaving `Authorization`/`x-api-key` for the real provider credential. For native Claude Code subscription traffic, use Anthropic's own login and supply the gateway key as an additional header; do not replace the subscription credential with the gateway key. Native provider beta headers are preserved.

For a configured Anthropic provider with `auth.mode = "passthrough"`, an existing native Claude Code login can route without replacing its credential:

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080/providers/anthropic
export ANTHROPIC_CUSTOM_HEADERS="x-infer-key: $INFER_PROXY_TOKEN"
unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN
claude
```

A consumer subscription is **not** a general API key:

* **ChatGPT**: use `codex login` with `cli_auth_credentials_store = "file"` and configure the resulting `auth.json` (usually `~/.codex/auth.json`). The configured path may be a symlink, but its resolved target must be a bounded regular file; directories, FIFOs, devices and sockets are rejected without reading them. Subscription requests go to `https://chatgpt.com/backend-api/codex/responses`, not `api.openai.com`. infer reads the file for credential changes and refreshes expiring JWTs using Codex's public OAuth refresh protocol, persisting rotated credentials atomically. Access tokens may also be opaque visible-ASCII bearer values, including values containing periods, when an account ID is configured, stored in the token file or available from a valid ID JWT. JWT candidates are recognized by a decodable JOSE header containing `alg`; once recognized, their envelope, claims and expiration remain strictly validated. Upstream authorization ultimately determines whether any bearer has subscription entitlement. File-based credentials are required; infer does not extract OS keychain secrets or implement its own login screen. Avoid simultaneous refresh by multiple independent processes sharing the same token file; provider refresh-token rotation cannot be made transactional across processes.
* **Anthropic**: native Claude Code traffic can retain its own subscription authentication. Anthropic's [credential-use rules](https://code.claude.com/docs/en/legal-and-compliance) restrict third-party subscription credential use. API keys are the supported application-integration option. infer does not offer Claude.ai login or promise that a subscription token is accepted for third-party inference.
* **Grok**: native xAI API-key and externally managed bearer-token passthrough are supported. A Grok/X subscription is not assumed to grant API entitlement. There is no Grok browser-session scraping, cookie replay, or bundled OAuth login/refresh. If your authorized subscription token is accepted at your configured API endpoint, use `bearer` or native `passthrough`; upstream authorization and tier restrictions are returned unchanged.

Provider aliases using the same Codex credential file share refresh synchronization within one infer process. This does not make refresh-token rotation transactional across independent processes.

Never expose a personal subscription gateway as a public or shared service. Verify your provider's current terms and entitlement. Official [Codex authentication documentation](https://learn.chatgpt.com/docs/auth) distinguishes subscription access from API billing. Protocol prior art: [codex-openai-proxy](https://github.com/0oAstro/codex-openai-proxy). Transport/storage compose Axum, Tokio, reqwest, and SQLite rather than introducing provider SDKs on the passthrough path.

### Claude Code → ChatGPT subscription

Use this focused `infer.toml` after `codex login`:

```toml
proxy_token_env = "INFER_PROXY_TOKEN"
control_token_env = "INFER_CONTROL_TOKEN"
default_provider = "chatgpt"

[providers.chatgpt]
kind = "codex"
base_url = "https://chatgpt.com/backend-api/codex"
[providers.chatgpt.auth]
mode = "codex"
auth_file = "/absolute/path/to/.codex/auth.json"

[models.code]
provider = "chatgpt"
model = "gpt-5.4"
```

Use a model actually available to your Codex account; the example is not an availability guarantee.

```sh
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_AUTH_TOKEN="$INFER_PROXY_TOKEN"
export ANTHROPIC_MODEL=code
export ANTHROPIC_DEFAULT_OPUS_MODEL=code
export ANTHROPIC_DEFAULT_SONNET_MODEL=code
export ANTHROPIC_DEFAULT_HAIKU_MODEL=code
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
# Disable extended/adaptive thinking in Claude Code for this translation route.
# If adaptive thinking remains enabled, set output_config.effort to low, medium, or high; infer does not choose an effort.
export MAX_THINKING_TOKENS=0
export ENABLE_TOOL_SEARCH=false
claude --model code
```

Translation supports text, representable images, system instructions, function tools, tool argument streaming, tool results, stop reasons and usage. Anthropic Messages ↔ OpenAI Chat works with OpenAI, xAI and llama.cpp. Anthropic/Chat → Responses supports Codex; Responses outputs can be translated back into Messages/Chat. Translation into Anthropic requires an explicit output-token cap (`max_tokens`, `max_completion_tokens`, or `max_output_tokens`, depending on the source API). Streaming Responses clients require a Responses backend; non-streaming Responses clients can use translated backends. Unsupported semantic features fail explicitly, rather than silently dropping content; provider-native server tools, opaque signed thinking, citations, audio and other unmatched modalities are not universal cross-provider features. Use native passthrough when fidelity requires a provider-specific feature. Cross-protocol translation rejects top-level `metadata` and `user` instead of dropping them; same-protocol and native requests preserve them. Anthropic adaptive thinking is translated to Responses only when `output_config.effort` is `low`, `medium`, or `high`; infer does not choose an effort.

Cross-protocol Responses requests to Chat or Anthropic require `store:false` explicitly. Responses defaults `store` to true, and those targets cannot preserve Responses object retrieval; omitted, null, or true values are rejected. Translated Chat or Anthropic requests sent to a Responses backend set `store:false` so the target does not persist data by default. Same-Responses and native requests preserve the caller's storage setting.

Function-tool strictness is preserved: non-strict Anthropic/Chat tools use explicit `strict: false` when sent to Responses. Translating Responses function tools requires an explicit `strict` boolean, because automatic Responses schema normalization is not reproduced. Adjacent parallel Responses calls become one Chat assistant tool-call turn. Text canonically placed after a call cannot be represented in Chat and is rejected. Usage is mapped when returned by the backend; missing usage becomes zero/unknown, not an estimate of actual charges. Present nested cached/reasoning counters must be nonnegative integers; malformed detail containers or counters are rejected. For translated streaming Chat responses, `stream_options.include_usage: true` requests the final usage-only chunk; false or omitted suppresses it. Native and same-protocol routes preserve the provider's behavior.

Translated requests to OpenAI Chat use `max_completion_tokens`, including reasoning-model routes. Grok and llama.cpp retain `max_tokens`; native and same-protocol Chat requests keep the caller's cap fields unchanged.

Empty Anthropic `stop_sequences` and Chat `stop` arrays are treated as absent when translating to Responses/Codex. Nonempty stop constraints still require a native Chat/Anthropic route. Responses function-tool `description: null` is likewise absent during translation; malformed descriptions, unknown tool fields and implicit Responses tool strictness remain errors.

JSON numeric values retain their full precision through tool-argument conversion and body rewrites, including integers beyond 64 bits and high-precision decimals. JSON decoding also preserves literal objects and strings, including keys resembling parser-internal markers. JSON formatting and numeric spelling may normalize; original wire bytes remain available in traces.

Anthropic assistant-prefills cannot be represented by Chat or Responses translation and are rejected. Conversely, Chat/Responses histories ending in an assistant turn are rejected when translating into Anthropic, where that turn would become a prefill rather than completed history. End translated Anthropic requests with a user/tool-result turn; native passthrough remains available.

Responses assistant-message `phase` values cannot round-trip through Anthropic/Chat history. Translated request history accepts null or omitted phases; non-null phases return HTTP 400. Any non-null phase on translated output, including `commentary` and `final_answer`, is rejected, whether first supplied at message start or in a later completion snapshot. Buffered clients receive HTTP 502; streaming translation terminates without a success marker and records the error in the trace. Native Responses routes preserve phase. This limitation also applies to the Claude Code → Codex example above: if the backend emits phases, use native Responses instead of the translated bridge.

Responses `output_text` history and streamed text deltas accept omitted, null or empty-array `logprobs`. Nonempty logprobs cannot be preserved across protocols and are rejected; malformed values and unknown history fields remain errors.

Anthropic text history accepts omitted, null or empty-array `citations`, including system text and text inside tool results. Nonempty citations require native Anthropic; malformed citations and unknown content fields remain errors.

Streaming translation preserves source ordering: Responses text parts/tools use canonical `(output_index, content_index)` for Anthropic and Chat clients, and Chat tools use numeric tool indices for Anthropic clients even when higher indices arrive first. Active canonical deltas stream incrementally; later blocks use bounded buffering until their predecessors can open. Pending arguments, buffered text and retained tool IDs/names share an 8 MiB aggregate budget; completed tool headers remain charged for terminal snapshot validation. Chat tool indices must be contiguous from zero at terminal completion. A completed Responses stream containing canonical function calls terminates as Anthropic `tool_use` or Chat `tool_calls`. Partial usage updates preserve omitted or null cache counts. Terminal `response.completed` and `response.incomplete` events must agree with their nested status and cannot contain a non-null error.

Optional Chat `tool_calls: null` is treated as absent in history, complete responses and streamed deltas. Anthropic custom tools may omit `type`, use `"type": "custom"`, or set it to `null`; provider-native tool types remain unsupported on translated routes. SSE detection matches `text/event-stream` case-insensitively and allows media-type parameters, but rejects similarly prefixed types.

Known nullable Chat request options are treated as absent before translation: a null token cap does not conflict with an explicit cap, and null sampling/streaming options are not forwarded as invalid target values. Anthropic still requires an explicit positive output cap. Unknown options and unsupported non-null features remain errors. Empty Chat refusal strings are absent in history, complete responses and streamed deltas, not evidence of a refusal. Nonempty refusals retain their semantics in output and require native Chat in request history; malformed refusal types fail explicitly. Translation to Anthropic promotes a normal end-turn containing refusal content to `stop_reason: refusal`, preserves an existing compatible refusal reason, and rejects refusal combined with `max_tokens` or `tool_use` rather than erasing either condition. Chat streaming can preserve ordered text/refusal transitions, but buffered Responses output that resumes an earlier text or refusal kind is rejected instead of regrouping content across the intervening block. Anthropic-to-Chat streaming preserves immediate ordinary text deltas; if a late Anthropic `stop_reason: refusal` arrives after text has escaped as Chat `content`, translation terminates without a success marker. Use a buffered translated request or native Anthropic when late refusal classification must remain lossless.

A null Chat `stream` is treated as absent (non-streaming); explicit `true` and `false` remain unchanged by translation. Model-routed Codex requests still use upstream `stream=true` and reconstruct JSON for non-streaming clients.

Translated SSE accepts one leading UTF-8 BOM, including when split across network chunks. BOM characters inside content are preserved. Buffered Responses reconstruction and streaming translation both use the SSE event name when the payload omits its type, and reject disagreement between event names and payload types.

**Codex differences:** model-routed requests use `stream=true`, `store=false`; non-streaming clients receive a reconstructed JSON response after upstream completion. Explicit `/providers/chatgpt/responses` passthrough does not rewrite the body: supply these Codex-required fields yourself. The subscription backend does not support an enforceable `max_output_tokens`: infer removes that field on model-routed requests, preserves the original request in the trace and sends `x-infer-warning`. Do not rely on the client token cap for budgeting on this backend. Unsupported sampling/options are not silently removed. Claude Code features and provider protocols change independently; the translated route is not an Anthropic-supported configuration. Live account/CLI compatibility must be verified with your own credentials.

Non-streaming model-routed Codex calls are collected even when the upstream media type is missing or wrong.

Recognized SSE reconstructs JSON; otherwise the body must parse as JSON or return HTTP 502 with an error trace. Native and streaming passthrough remain unchanged.


## Inspect and export

The control API requires **`INFER_CONTROL_TOKEN`**, not the inference token:

```sh
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" http://127.0.0.1:8081/health
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" http://127.0.0.1:8081/providers
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" 'http://127.0.0.1:8081/traces?limit=50'
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" http://127.0.0.1:8081/traces/TRACE_ID
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" http://127.0.0.1:8081/traces/TRACE_ID/body/response
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" 'http://127.0.0.1:8081/export?limit=50'
```

Ordinary proxied HTTP inference responses include `x-infer-trace-id`. Capabilities, owned-file operations, session-event ingestion, and Realtime use separate handlers without these inference traces. Realtime does not record WebSocket frames.

Body kinds: `request`, `response`, `upstream_request`, `upstream_response`. Native requests avoid duplicate body storage; rewritten calls retain the original and rewritten forms. Metadata includes method, path, selected provider, upstream URL, redacted headers, byte counts and completion/error state. List results include `next_before`; pass it as `before=TRACE_ID` for the next page. Export uses the same cursor order. `/export` returns JSONL rows with `metadata` and `bodies`; each body is parsed JSON or exact base64 bytes (including SSE/binary). It is a raw dataset, **not** automatically validated or filtered fine-tuning data. Keep only completed, suitable records and apply consent/redaction/quality policies before training.

Traces are written under `trace_dir` with a SQLite WAL index and per-trace body files. Directory/file permissions are restricted on Unix. Ordinary proxied HTTP inference requests enter trace recording before upstream dispatch, including requests that later fail local model routing or validation. Authentication failures, nonexistent providers, root account-product paths, and unsupported root file/upload routes reject before trace creation. Request limits reject oversized routed requests; only received bytes are available for rejected/interrupted uploads. An interrupted inbound upload preserves its exact recorded prefix and leaves the trace incomplete without recording a synthetic response. Raw provider routes stream uploads without a configured size cap. Storage errors fail closed rather than forwarding unrecorded bytes. Client cancellation/crash leaves an incomplete trace. Completion flushes and syncs body files before finalizing the metadata row; a live/incomplete file is not a durability guarantee.

`complete` describes a finished recorded exchange, **not necessarily a successful generation**: a translated HTTP-200 SSE failure is complete with a non-null `error`. Native passthrough deliberately does not parse provider-specific event semantics, so inspect native response events as well as metadata before selecting training records.

HEAD, 204 and 304 traces finish even without a response body, retaining legal representation headers. Cancellation leaves traces incomplete; disk failures fail closed rather than marking an unrecorded exchange complete.

Export is limited to 100 rows and 16 MiB of aggregate raw body data per request; exceeding the cap errors without truncation. Download individual bodies for larger records. Listing is bounded to 100 rows. Non-streaming translated responses and routed JSON requests have configurable 32 MiB defaults. SSE translation bounds individual pending events. Native HTTP response bodies stream without accumulation.

**The dataset is sensitive.** Authorization/API-key/cookie headers, including Cloudflare's legacy `X-Auth-Key` and `X-Auth-Email`, are redacted from recorded request/upstream/response metadata and exports; native forwarding still retains the provider's required credentials. Prompts, tool arguments/results, URLs/query strings and generated text may contain secrets, personal data or source code. infer does not redact model content, encrypt local traces, or impose automatic retention. Keep the data directory private, provision disk space, restrict control access, use encrypted storage/backups, and define retention before production. Do not put credentials in URL query strings. No trace deletion endpoint is provided.

### OMP execution traces

Inference bodies alone do not show tools that fail, are denied, or finish without
another model request. Load the OMP extension to record the harness events too:

```sh
export INFER_EVENTS_URL=http://127.0.0.1:8080/session-events
# Same inference credential used by the model connection; never the control token.
export INFER_PROXY_TOKEN
# Optional; default: ~/.omp/agent/infer-spool
export INFER_TRACE_SPOOL_DIR=/absolute/private/path/infer-spool
omp --extension /absolute/path/to/infer/integrations/omp/infer-traces.ts
```

The extension does **not** configure the model connection. Route OMP's provider
through infer separately using its `models.yml` provider configuration, for
example (merge this entry into your existing file):

```yaml
providers:
  infer-local:
    baseUrl: http://127.0.0.1:8080/providers/llama/v1
    api: openai-completions
    apiKey: INFER_PROXY_TOKEN
    models:
      - id: local-model
        name: Local model through infer
        reasoning: false
        input: [text]
        contextWindow: 32768
        maxTokens: 4096
        cost: {input: 0, output: 0, cacheRead: 0, cacheWrite: 0}
```

Select `omp --model infer-local/local-model --extension /absolute/path/to/infer/integrations/omp/infer-traces.ts`.
Use a configured native provider route and an OMP API matching that provider;
the `llama` route above assumes the example local provider is enabled.
Provider response events associate the OMP session with infer's
`x-infer-trace-id`. Calls bypassing infer still produce execution events, but
have no infer body trace to link.

Events include session/agent/turn/message lifecycle, provider request payloads,
tool execution progress/results, approvals, retries, compaction, and supported
subagent lifecycle notifications. Native event payloads are retained rather than
normalized into a lossy training schema. Event timestamps are observation times,
not a promise of exact tool CPU time. A stopped loop or closed process is not
proof that the task succeeded.
These are registered hook surfaces, not evidence that every lifecycle path has
been exercised. Validate the hooks your workflow uses, including subagent execution,
approval UI, compaction, and session switching, against your installed OMP version.

Payload fidelity is JSON-level, not original JSON formatting or arbitrary
JavaScript object identity. The OMP emitter serializes big integers as decimal
strings, errors as their exposed fields/name/message/stack, and cancellation
signals as their state/reason. Cycles or serialization failures warn rather than
silently dropping fields.

Each event is appended and synced to a private local JSONL spool before upload.
The gateway acknowledges only after the SQLite event commit. If upload fails,
the extension warns, stops uploads for that extension instance, and keeps
spooling. After restoring the gateway, replay each affected spool file:

```sh
infer --config infer.toml import-events /absolute/path/to/spool.jsonl
```

Import does not require provider credentials or a running server. It uses
`trace_dir` from the configuration and commits one event at a time; a bad line
stops import after earlier valid lines. Replaying identical event IDs is safe.
Reusing an ID with different event content fails. Spools retain uploaded events
too; no automatic spool cleanup or retention is performed.
Local spools have no event-size or total-storage cap; the gateway/import limit
below still applies. Upload rejection leaves the full local event for inspection.
Synchronous per-hook append/fsync and queued uploads add latency and can consume
substantial disk/memory during long streams; no production throughput claim is made.

The inference listener accepts `POST /session-events` with the inference token.
The body is one JSON object:

```json
{
  "id": "c2e92009-f2e0-4c22-b9e1-cb649f2066e0",
  "session_id": "omp-session-id",
  "source": "omp",
  "kind": "tool_execution_end",
  "occurred_at": "2026-10-22T12:00:00Z",
  "trace_id": null,
  "payload": {"type": "tool_execution_end", "toolCallId": "call_1"}
}
```

`id` is a canonical UUID v4; optional `trace_id` is a canonical UUID. Session IDs and kinds are
1–128 ASCII letters/digits/`_`/`.`/`-`; `source` has the same alphabet with a
64-character limit. `occurred_at` is RFC 3339. The serialized event limit is
16 MiB, also subject to `max_request_bytes`; oversized events are rejected,
never truncated. Payloads are arbitrary JSON. Duplicate identical IDs return
the original receipt; conflicting content returns HTTP 409. Other agents can
emit this same envelope without an OMP dependency.
Event IDs are globally unique across all sources. Reusing an ID for another
session or source is a content conflict, not a new event. Session IDs also share
one global namespace: `source` does not partition them, and a session summary
retains its first event's source. Adapters must namespace unrelated native session
IDs before ingestion to avoid combining histories.

`occurred_at` is caller-supplied; `received_at` is the server's ingestion time.
Session-summary `started_at`/`updated_at` are first/last receipt times, not inferred
historical session times. Neither these fields nor an event kind establishes
completeness, success, a human preference, or a reward.

Session inspection remains on the separately authenticated control listener:

```sh
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" \
  'http://127.0.0.1:8081/sessions?limit=50'
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" \
  'http://127.0.0.1:8081/sessions/SESSION_ID/events?limit=50&after=0'
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" \
  'http://127.0.0.1:8081/sessions/SESSION_ID/traces?limit=50'
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" \
  'http://127.0.0.1:8081/sessions/SESSION_ID/export?limit=50&after=0'
```

Session lists use numeric `next_before`; linked trace lists use UUID
`next_before`. Event pages are in ingestion order and return `next_after`;
pass that numeric sequence as `after`. Session export is JSONL of the same
`{sequence, received_at, event}` records, with optional `acquisitions` and
`acquisitions_truncated` provenance fields for imported observations. Its `x-infer-next-after` header supplies
the next cursor when more rows exist. All page limits are 1–100. Event pages
also stop at a 16 MiB aggregate event-data budget without splitting an event.
Download linked inference bodies through the existing trace endpoints.
Native SDKs may stop consuming immediately after a terminal event; a body can
contain `[DONE]` while its trace remains `complete=false` because infer never
observed EOF. Session events do not promote such traces to complete or successful.

**Capture boundary:** this records events exposed by OMP, not arbitrary hidden
subprocess activity or unexposed model reasoning. OMP catches errors from dispatched extension handlers:
spool/disk failures must not be mistaken for a complete execution trace.
Provider response headers are allowlisted, but event content, tool output,
context, and provider payloads are sensitive and are **not content-redacted**.
Protect both `trace_dir` and the local spool, including backups.

**Prior art:** [ACP tool reports](https://agentclientprotocol.com/protocol/v1/tool-calls)
are recommended rather than mandatory, with optional raw inputs/outputs.
An ACP recorder can retain all reported messages but cannot ensure full tool
fidelity across adapters. This integration instead uses the
[OMP extension event API](https://github.com/can1357/oh-my-pi/blob/v18.12.6/docs/extensions.md)
(target: OMP 18.12.6), with a harness-neutral storage envelope. Exports remain
raw evidence: human preferences/rewards, consent, quality filtering, and
trainer-specific SFT/LoRA/RLHF conversion are separate dataset preparation.

### Native local-history imports

`local-traces` discovers and imports existing native history without launching or
resuming a harness:

```sh
infer --config infer.toml local-traces discover
infer --config infer.toml local-traces discover \
  --harness codex --root codex=/absolute/CODEX_HOME
infer --config infer.toml local-traces import --dry-run \
  --source omp=/absolute/session.jsonl
infer --config infer.toml local-traces import \
  --harness omp --harness claude_code --scope all
```

Harness names are `omp`, `claude_code`, `codex`, and `grok_build`. With no
selection, all four are included. `--root HARNESS=PATH` replaces that harness's
default roots; `--source HARNESS=PATH` adds one exact file or Grok session
directory **without disabling default-root discovery**. Both options are
repeatable. To constrain discovery, select `--harness` and override its
`--root` explicitly; `--source` alone is not an exact-only selection mode.
Naming an already discovered source explicitly retains its selected root's
namespace, so adding `--source` does not duplicate that source's imported history.
`--scope managed` excludes arbitrary
OMP files named by `custom-session-files`; `--scope registered` selects only
those OMP registry entries plus explicit `--source` inputs; `all` is the
default. `discover` reports paths, kinds, byte sizes, missing roots, skipped
symlinks, and warnings only. It does not print native record contents.

Default discovery uses `~/.omp`, `~/.claude`, `~/.codex`, and `~/.grok`, plus
`PI_CONFIG_DIR`, `PI_CODING_AGENT_DIR`, `XDG_DATA_HOME`, `XDG_STATE_HOME`,
`CLAUDE_CONFIG_DIR`, `CLAUDE_CODE_PROJECT_DIR_NAME`, `CODEX_HOME`,
`CODEX_SQLITE_HOME` (or the bounded `sqlite_home` field in Codex `config.toml`),
and `GROK_HOME` when set. OMP managed `sessions` trees and nested profile trees
are scanned;
`custom-session-files` registries add evidenced relocated transcripts. Claude
Code discovery scans `projects`, not prompt-only `history.jsonl`. Codex scans
active and archived rollouts (`.jsonl` and `.jsonl.zst`), preferring a plain
rollout when its compressed sibling also exists, state databases for confined
`threads.rollout_path` references, and `thread_history_*` SQLite projections.
Grok Build imports session `updates.jsonl`, chat/telemetry/rewind streams,
compaction checkpoints, summaries, and other session-confined artifacts.
Auth/config/credential files are not import inputs.

JSONL records retain their source bytes without the LF/CRLF delimiter.
SQLite records retain typed JSON projections, not database or page bytes.
Opaque companion artifacts retain their exact bytes in private
`trace_dir/artifacts/sha256` storage. Opaque companion files use 64 KiB
streaming reads into private staging files; they are never accumulated without
a configured bound. The event payload retains the parsed native envelope when
the serialized event, including metadata, fits the 16 MiB envelope; raw byte
length alone does not determine whether a projection fits. JSON companions are
parsed within the configured record and artifact limits. Native IDs/timestamps,
stream/position/format, and a SHA-256 reference remain available even
when the inline projection is omitted. `occurred_at` records a native time or
an import-observation time for untimed records. Defaults cap one record at
256 MiB, one opaque artifact at 1 GiB, and discovery at 100,000 sources.
Override them with `--max-record-bytes`, `--max-artifact-bytes`, and
`--max-sources`; exceeding a cap fails without truncation.
JSONL record limits exclude the LF or CRLF delimiter.
These are per-record, per-artifact and source-count limits, not an aggregate
corpus or disk quota. Compressed histories can expand substantially; reserve
capacity for the complete selected import.

Source/session/snapshot mappings and event insertion share one SQLite
transaction. Reimporting unchanged bytes returns the existing UUID-v4 event;
changed bytes under the same native identity append a numbered observation
revision. Native sessions from unrelated harness/root namespaces remain
separate. Codex rollout and SQLite projection evidence remain separate streams;
infer does not claim they are equivalent or deduplicate them by content.
Codex state rows use `threads.id` as the session and record identity; history
items use their complete turn/item key within the thread. Non-UTF-8 TEXT and
BLOB keys use type-tagged base64 identities rather than rowids, so moving rows
or running `VACUUM` does not create duplicate observations or merge sessions.
Ordinary UTF-8 identities stay unchanged; text beginning with the reserved
`~sqlite:` prefix is escaped to avoid collisions with encoded keys.
Stores populated by older importers may retain state observations in
`codex-sqlite-index`, rowid-keyed binary-key observations, or history items keyed
by item ID alone. Reimporting adds correctly identified observations once and
preserves those immutable legacy events; later replays reuse the corrected
observations. Existing events, including artifact-only projections imported by
older versions, are never moved or rewritten.
Within one selected root, a native Codex rollout keeps its logical stream
identity when it moves from active JSONL to a compressed archive; physical
filenames and compression remain acquisition details.
Completed malformed lines are retained as opaque artifacts and counted.
An invalid unterminated live tail is deferred for the next run. Accepted
prefixes remain durable if a later source fails, so rerunning resumes safely.
Sources are opened read-only and symlinks are skipped/rejected. Arbitrary paths
named inside model/tool content are never followed. OMP `blob:sha256:` values
are the narrow exception: only a 64-hex digest is resolved under the harness's
fixed blob directories, content must match that digest, and missing references
become explicit `missing_reference` observations. Blob size limits are checked
before hashing and enforced during reads, including files that grow after
opening; an oversized blob fails before digest validation.
State-database rollout pointers cannot expand discovery beyond selected roots.

Imported events use the existing `/sessions` inspection and JSONL export
endpoints. Each row includes bounded acquisition receipts. Schema-3 stores
upgrade without dropping recorded source paths or observation times.
Original acquisition positions are recovered from immutable event evidence;
later legacy receipts keep unknown positions rather than guessing.
Download exact bytes using the payload's `raw_artifact.download_path`, for example:

```sh
curl -H "Authorization: Bearer $INFER_CONTROL_TOKEN" \
  http://127.0.0.1:8081/artifacts/SHA256_DIGEST
```

The artifact endpoint is control-authenticated and returns `no-store`.
Source-side truncation, deleted rewind history, missing referenced blobs,
unavailable Claude variants, and hidden reasoning cannot be recovered.
Imported evidence does not assert completeness, outcome, reward, or consent.

### Provider account-export imports

`provider-exports import` imports owner-selected ChatGPT, Claude, and Grok
consumer export data without account access, scraping, inference calls, or
source extraction:

```sh
infer --config infer.toml provider-exports import \
  --provider auto \
  --account-scope personal-account \
  --source /absolute/path/to/export.zip
infer --config infer.toml provider-exports import --dry-run \
  --provider claude \
  --account-scope personal-account \
  --source /absolute/path/to/conversations.json
```

`--source` is repeatable. `--account-scope` is an explicit identity partition,
not a credential or provider account lookup. Provider selection is `auto`,
`chatgpt`, `claude`, or `grok`. Automatic recognition validates native shape;
explicit selection also rejects mismatched JSON. Content recognition allows raw
JSON with no or misleading suffix. Dry run validates and reports structural
counts without opening or creating `trace_dir`.

Supported source-backed shapes:

* ChatGPT native conversation arrays with complete `mapping` graphs, including
  null-message nodes, every branch, parent/child order, `current_node`, native
  message fields, metadata, and unknown fields. ZIP support is limited to the
  evidenced root `conversations.json`; the provider documents numbered shards
  but no exact filename contract was available as of 2026-10-22.
* Claude `uuid` conversations and `chat_messages`, preserving text/content
  variants, parent references when present, attachment/file declarations,
  unknown fields, and literal legacy `antArtifact`/`antThinking` text. Root
  `conversations.json` ZIP packaging is historical third-party evidence; it is
  not a promise covering every current personal or organization export.
* Grok `prod-grok-backend.json` ZIP data and equivalent raw JSON with
  `conversation`/`responses` wrappers, response `_id`, sender/model,
  BSON-style dates, source order, optional thinking-named fields, and unknown
  fields. This does not claim support for X account archives.

The complete selected JSON or ZIP is streamed into private content-addressed
artifact storage. Conversation snapshots use provider + explicit account scope
+ native conversation ID; unchanged records deduplicate across moves and ZIP
repacking, while changed native records append revisions. Acquisition receipts
separately retain source digest, member, position, path, and observation time.
Unknown safe ZIP members are preserved as opaque, unassociated artifacts.
File declarations and pointers remain native evidence; without an established
provider member-link contract they are explicitly unresolved, never empty
successful attachments. Download bytes through the existing authenticated
`/artifacts/SHA256_DIGEST` control endpoint.

ZIPs are read without general filesystem extraction. Imports reject duplicate
or escaping names, absolute/drive/backslash paths, links and special entries,
encryption, unsupported compression, nested archives, malformed members, and
configured resource-limit violations. Defaults: 10,000 members, 256 MiB per
decoded member, 1 GiB aggregate decoded/source bytes, 100:1 compression ratio,
1,000,000 conversations, and JSON nesting depth 128. Override with
`--max-members`, `--max-member-bytes`, `--max-total-bytes`,
`--max-compression-ratio`, `--max-conversations`, and `--max-json-depth`.
Failures are source-local; accepted earlier observations remain replay-safe.

These imports are consumer account-export evidence, not Codex/Claude Code
execution history, API traffic, provider task success, rewards, training
consent, or complete hidden reasoning. Deleted history, omitted upload bytes,
unsupported numbered ChatGPT shards, current Claude packaging/branch variants,
Grok/X variants, and unavailable provider-side data cannot be recovered.
TypeSafe has no evidenced consumer export contract. Cloudflare AI Gateway
Logpush is conditional gzip NDJSON request/response logging with possible
encrypted fields, not a Clairic consumer archive; no adapter is claimed without
an entitled, sanitized retained/decrypted sample and key-handling contract.

## Reverse proxy and operations

Terminate TLS at your existing reverse proxy. Preserve the inference path and body and forward the chosen gateway credential. Do not publish the control port except on a separately protected administrative route. No forwarded client-identity header is trusted: `Forwarded` and `X-Forwarded-*` are stripped before upstream forwarding; incoming `Host` is replaced by the configured upstream authority. Hop-by-hop headers, including names nominated by `Connection`, are removed. Upstream compression is disabled by negotiation; provider content encoding is preserved on native passthrough.

Body rewrites remove `Content-Digest`, `Repr-Digest`, `Digest` and `Content-MD5` rather than forwarding integrity claims about different bytes. This applies independently to rewritten requests, translated responses and reconstructed SSE responses. Native passthrough and otherwise unchanged bodies preserve these headers.

Example nginx inference location for ordinary HTTP and SSE. This example does not forward WebSocket upgrades; Realtime requires a separate reverse-proxy configuration.

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Connection "";
    proxy_buffering off;
    proxy_request_buffering off;
    proxy_cache off;
    proxy_read_timeout 900s;
    proxy_send_timeout 900s;
    client_max_body_size 64m;
}
```

infer sends `X-Accel-Buffering: no`. Set ingress idle/body limits appropriately for long generations, tool calls, and uploads. If the reverse proxy is on another machine/container, bind explicitly to a private reachable address and firewall both listeners; authentication remains mandatory. No CORS policy is enabled. The dedicated `/v1/realtime` WebSocket route requires a compatible model/provider; other upgrades and CONNECT remain unsupported. No automatic inference retry avoids duplicating billed calls and tool execution. Ctrl-C/SIGTERM drains requests for up to 30 seconds; unfinished traces remain incomplete.

The low-latency path reuses a pooled reqwest client, disables Nagle's algorithm, forwards chunks with backpressure and uses async body-file I/O; SQLite work runs off the async executor. Trace recording necessarily adds storage latency. Routed JSON requests are buffered for model selection/translation; use explicit native provider routes to stream large uploads. No numeric production latency claim is made without measurement on the target filesystem/network.

```sh
cargo test --locked -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
cargo build --release --locked
```

## Integration validation

`cargo test --locked -- --test-threads=1` includes real gateway-process regressions against isolated loopback HTTP fixtures. These require no credentials or inference service. Run them alone with:

```sh
cargo test --locked --test gateway_contracts
```

Live inference is explicitly opt-in; the two ignored tests never run in the default suite. Each profile collects all case outcomes before failing. No inference retry or fallback is performed.

Start a compatible cached GGUF with your installed llama.cpp:

```sh
llama-server --model /absolute/path/model.gguf --alias validation-local \
  --host 127.0.0.1 --port 8082 --ctx-size 4096 --parallel 1 \
  --reasoning off --offline --no-webui
```

Wait for `/health` to return `{"status":"ok"}`. Local generation incurs no provider API charge; model loading/tool support still depend on the installed llama.cpp build.

```sh
INFER_LIVE_LLAMA_URL=http://127.0.0.1:8082 \
INFER_LIVE_LLAMA_MODEL=validation-local \
INFER_VALIDATION_REPORT_DIR=/tmp/infer-validation \
cargo test --test live_gateway live_llama_validation -- --ignored --nocapture
```

For Codex, use an existing file-backed login and an account-supported model. Select a model supported by the account and endpoint. The example uses `gpt-6-luna`; it is not a price or availability guarantee.

```sh
INFER_LIVE_CODEX_AUTH_FILE="$HOME/.codex/auth.json" \
INFER_LIVE_CODEX_MODEL=gpt-6-luna \
INFER_VALIDATION_REPORT_DIR=/tmp/infer-validation \
cargo test --test live_gateway live_codex_validation -- --ignored --nocapture
```

The harness reads the original credential file through infer; it never extracts credentials into test output. Normal provider refresh may update that file. Do not run separate refreshers against the same rotating login concurrently.

`INFER_LIVE_CODEX_BASE_URL` optionally overrides the Codex base, including `/backend-api/codex`. Missing required variables fail explicitly.

Reports contain structural evidence and token counts, not prompts, credentials, provider bodies or raw traces.

Set `INFER_VALIDATION_CASE=routed_chat_stream` to run only that named case. Unknown names fail before inference. Filtered runs use case-specific report filenames.

The local profile uses up to eight inference requests, including a forced tool call and follow-up history. Codex uses eight, including a native forced tool call.

Codex removes routed output-token caps, so these runs have no enforceable token-cost ceiling.

Native and translated buffered/SSE routes validate output structure, terminal semantics, trace byte integrity and export visibility.

Provider rejection, model noncompliance and documented translation limits are observations, not automatically new gateway bugs.
