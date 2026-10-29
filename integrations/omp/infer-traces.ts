import type {
	AfterProviderResponseEvent,
	ExtensionAPI,
	ExtensionContext,
} from "@oh-my-pi/pi-coding-agent";
import { randomUUID } from "node:crypto";
import {
	closeSync,
	constants,
	fchmodSync,
	fstatSync,
	fsyncSync,
	mkdirSync,
	openSync,
	writeSync,
} from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

// Pinned API: oh-my-pi v18.12.6. These hooks observe, never rewrite, native events.
// Spools contain sensitive, unredacted conversation/tool data, including successful
// uploads. Recover with `infer import-events FILE`; event UUIDs make replay safe.
// Native hooks are not an audit boundary: OMP isolates handler failures, some
// notifications are unawaited, and a forced process kill cannot emit shutdown.
interface EventEnvelope {
	id: string;
	session_id: string;
	source: "omp";
	kind: string;
	occurred_at: string;
	trace_id?: string;
	payload: unknown;
}

const SESSION_ID = /^[A-Za-z0-9_.-]{1,128}$/;
const TRACE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const RESPONSE_HEADERS: Record<string, true> = {
	"x-infer-trace-id": true,
	"content-type": true,
	"request-id": true,
	"x-request-id": true,
	"openai-request-id": true,
	"anthropic-request-id": true,
	"x-amzn-requestid": true,
	"x-amz-request-id": true,
	"x-goog-request-id": true,
	"x-ms-request-id": true,
	"apim-request-id": true,
};

function configuration(): { url: string; token: string } | undefined {
	const rawUrl = process.env.INFER_EVENTS_URL;
	const token = process.env.INFER_PROXY_TOKEN;
	if (!rawUrl || !token || /[\r\n]/.test(token)) return undefined;
	try {
		const url = new URL(rawUrl);
		if (
			!/^https?:\/\//i.test(rawUrl) ||
			(url.protocol !== "http:" && url.protocol !== "https:") ||
			!url.hostname ||
			url.username ||
			url.password ||
			/^https?:\/\/[^/?#]*@/i.test(rawUrl) ||
			/[?#]/.test(rawUrl)
		) {
			return undefined;
		}
		return { url: url.href, token };
	} catch {
		return undefined;
	}
}

function providerResponse(event: AfterProviderResponseEvent): AfterProviderResponseEvent {
	const headers: Record<string, string> = {};
	for (const [name, value] of Object.entries(event.headers)) {
		const lower = name.toLowerCase();
		if (Object.hasOwn(RESPONSE_HEADERS, lower)) headers[lower] = value;
	}
	return { ...event, headers };
}

// Native events are JSON-shaped except for, e.g., cancellation signals and errors
// in custom tool details. Preserve their exposed data without size/depth limits.
// Cycles throw visibly rather than silently dropping or truncating an event.
function jsonValue(_key: string, value: unknown): unknown {
	if (typeof value === "bigint") return value.toString();
	if (value instanceof Error) {
		return { ...value, name: value.name, message: value.message, stack: value.stack };
	}
	if (value instanceof AbortSignal) return { aborted: value.aborted, reason: value.reason };
	return value;
}

export default function inferTraces(pi: ExtensionAPI): void {
	// Factories are rebound for children, but the module is shared. All mutable
	// state, files, configuration, and upload ordering belong to this binding.
	const captureId = randomUUID();
	const spoolDir = resolve(process.env.INFER_TRACE_SPOOL_DIR || join(homedir(), ".omp", "agent", "infer-spool"));
	const config = configuration();
	const files = new Set<string>();
	const warnings = new Map<string, string>();
	const uiWarnings = new Set<string>();
	let uploadsDisabled = !config;
	let closing = false;
	let activeRequest: AbortController | undefined;
	let queue: Promise<void> = Promise.resolve();

	function warn(code: string, message: string, ctx?: ExtensionContext): void {
		if (!warnings.has(code)) {
			warnings.set(code, message);
			// Never include an exception, HTTP body, configuration value, or token.
			try { pi.logger.warn(message); } catch { /* The host owns logging availability. */ }
		}
		if (ctx?.hasUI && !uiWarnings.has(code)) {
			uiWarnings.add(code);
			try { ctx.ui.notify(message, "warning"); } catch { /* Logging above is independent of UI. */ }
		}
	}

	if (!config) {
		warn("config", "infer traces: uploads disabled. Set INFER_EVENTS_URL to a full HTTP(S) URL without credentials/query/fragment and INFER_PROXY_TOKEN to an inference token. Local spooling remains enabled.");
	}

	function append(sessionId: string, line: string): void {
		mkdirSync(spoolDir, { recursive: true, mode: 0o700 });
		// Refuse symlink destinations and directories owned by another user.
		// Restrict an existing directory too: mkdir's mode affects new paths only.
		const directory = openSync(spoolDir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
		try {
			const stat = fstatSync(directory);
			if (!stat.isDirectory() || (process.getuid && stat.uid !== process.getuid())) {
				throw new Error("Unsafe spool directory");
			}
			fchmodSync(directory, 0o700);
			const path = join(spoolDir, `${sessionId}.${captureId}.jsonl`);
			const isNew = !files.has(path);
			const flags = constants.O_WRONLY | constants.O_APPEND | constants.O_NOFOLLOW |
				(isNew ? constants.O_CREAT | constants.O_EXCL : 0);
			const file = openSync(path, flags, 0o600);
			try {
				const fileStat = fstatSync(file);
				if (!fileStat.isFile() || fileStat.nlink !== 1 || (process.getuid && fileStat.uid !== process.getuid())) {
					throw new Error("Unsafe spool file");
				}
				fchmodSync(file, 0o600);
				const bytes = Buffer.from(`${line}\n`, "utf8");
				let offset = 0;
				while (offset < bytes.length) {
					const written = writeSync(file, bytes, offset, bytes.length - offset);
					if (written === 0) throw new Error("Incomplete spool write");
					offset += written;
				}
				fsyncSync(file);
			} finally {
				closeSync(file);
			}
			if (isNew) fsyncSync(directory);
			files.add(path);
		} finally {
			closeSync(directory);
		}
	}

	async function upload(line: string, shutdown: boolean, ctx: ExtensionContext): Promise<void> {
		if (uploadsDisabled || !config || (closing && !shutdown)) return;
		const controller = new AbortController();
		activeRequest = controller;
		const timeout = setTimeout(() => controller.abort(), 1_500);
		try {
			const response = await fetch(config.url, {
				method: "POST",
				headers: { "content-type": "application/json", authorization: `Bearer ${config.token}` },
				body: line,
				redirect: "error",
				signal: controller.signal,
			});
			// Response bodies are not event data and may contain server diagnostics.
			// Cancel instead of buffering them or logging any sensitive content.
			if (response.body) await response.body.cancel();
			if (!response.ok) throw new Error("Event upload rejected");
		} catch {
			if (closing && !shutdown && controller.signal.aborted) return;
			uploadsDisabled = true;
			warn("upload", "infer traces: upload failed; uploads are disabled for this capture. Events remain in the private local spool, including successful sends. Recover with infer import-events FILE. OMP continues; capture is not fail-closed.", ctx);
		} finally {
			clearTimeout(timeout);
			if (activeRequest === controller) activeRequest = undefined;
		}
	}

	function capture(event: { type: string }, ctx: ExtensionContext): Promise<void> {
		for (const [code, message] of warnings) warn(code, message, ctx);
		try {
			// Read and snapshot live session identity on EVERY hook, before any await
			// or queued work: switch/branch handlers may share the session manager.
			const sessionId = ctx.sessionManager.getSessionId();
			if (!SESSION_ID.test(sessionId)) throw new Error("Invalid session identifier");
			const response = event.type === "after_provider_response"
				? providerResponse(event as AfterProviderResponseEvent)
				: undefined;
			const candidate = response?.headers["x-infer-trace-id"];
			const envelope: EventEnvelope = {
				id: randomUUID(),
				session_id: sessionId,
				source: "omp",
				kind: event.type,
				occurred_at: new Date().toISOString(),
				...(candidate && TRACE_ID.test(candidate) ? { trace_id: candidate } : {}),
				payload: {
					event: response ?? event,
					context: {
						cwd: ctx.cwd,
						session_file: ctx.sessionManager.getSessionFile() ?? null,
						parent_session: ctx.sessionManager.getHeader()?.parentSession ?? null,
						agent: {
							kind: ctx.agent.kind,
							id: ctx.agent.id,
							name: ctx.agent.name,
							depth: ctx.agent.depth,
							parentId: ctx.agent.parentId,
						},
						// Do not serialize ctx, process.env, model headers or registries.
					},
				},
			};
			const line = JSON.stringify(envelope, jsonValue);
			// Synchronous append + fsync also protects unawaited observability hooks
			// and guarantees every POST has a durable local copy already on disk.
			append(sessionId, line);
			const shutdown = event.type === "session_shutdown";
			queue = queue.then(() => upload(line, shutdown, ctx));
		} catch {
			uploadsDisabled = true;
			warn("spool", "infer traces: an event could not be durably spooled or serialized; uploads are disabled and some events may be missing. Check spool permissions and disk space. OMP continues; capture is not fail-closed.", ctx);
		}
		return queue;
	}

	// Decision/transform hooks return only void: observing never changes prompts,
	// tool arguments/results, approval decisions, or provider request payloads.
	pi.on("session_start", capture);
	pi.on("session_before_switch", capture);
	pi.on("session_switch", capture);
	pi.on("session_before_branch", capture);
	pi.on("session_branch", capture);
	pi.on("session_before_tree", capture);
	pi.on("session_tree", capture);
	pi.on("input", capture);
	pi.on("before_agent_start", capture);
	pi.on("before_subagent_spawn", capture);
	pi.on("context", capture);
	pi.on("before_provider_request", capture);
	pi.on("after_provider_response", capture);
	pi.on("assistant_message", capture);
	pi.on("session_stop", capture);
	pi.on("tool_call", capture);
	pi.on("tool_result", capture);
	pi.on("session_before_compact", capture);
	pi.on("session.compacting", capture);
	pi.on("session_compact", capture);
	pi.on("auto_compaction_start", capture);
	pi.on("auto_compaction_end", capture);
	pi.on("auto_retry_start", capture);
	pi.on("auto_retry_end", capture);
	pi.on("retry_fallback_applied", capture);
	pi.on("retry_fallback_succeeded", capture);
	pi.on("cache_warming_decision", capture);
	pi.on("ttsr_triggered", capture);
	pi.on("todo_reminder", capture);
	pi.on("goal_updated", capture);
	pi.on("tool_approval_requested", capture);
	pi.on("tool_approval_resolved", capture);
	pi.on("plan_review_requested", capture);
	pi.on("plan_review_resolved", capture);
	pi.on("user_bash", capture);
	pi.on("user_python", capture);
	pi.on("mcp_notification", capture);

	// Native notification dispatch need not await us. Persist immediately and
	// serialize uploads without making every streamed token await an HTTP call.
	function observe(event: { type: string }, ctx: ExtensionContext): void {
		void capture(event, ctx);
	}
	pi.on("agent_start", observe);
	pi.on("agent_end", observe); // Includes finalized messages + willContinue/awaitingAsyncWork.
	pi.on("turn_start", observe);
	pi.on("turn_end", observe);
	pi.on("message_start", observe);
	pi.on("message_update", observe);
	pi.on("message_end", observe);
	pi.on("tool_execution_start", observe);
	pi.on("tool_execution_update", observe);
	pi.on("tool_execution_end", observe);

	pi.on("session_shutdown", async (event, ctx) => {
		// Teardown is capped at 2s by OMP. All queued events are already durable;
		// abandon pending uploads, cancel the active one, and try shutdown once.
		// A shutdown event is NOT evidence of successful task completion.
		closing = true;
		activeRequest?.abort();
		const drain = capture(event, ctx);
		const deadline = Promise.withResolvers<void>();
		const timer = setTimeout(() => {
			uploadsDisabled = true;
			activeRequest?.abort();
			deadline.resolve();
		}, 1_800);
		try {
			await Promise.race([drain, deadline.promise]);
		} finally {
			clearTimeout(timer);
		}
	});
}
