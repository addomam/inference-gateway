---
name: verify-trace-completion
description: Prove that infer marks a trace complete only after its body files and trace directories are synced and only when the writer has not failed. Use when changing TraceStore::start, TraceWriter::append, or TraceWriter::finish in src/trace.rs.
---

# Verify trace completion

A control client can treat a trace as finished only after the writer has synced the body files and both trace directories, and only if that writer has not failed an append.

Harm: a control read or export can present a partial or not-yet-durable capture as a finished inference record.

## Tool

The check is an exhaustive enumeration of the crash points in one `TraceWriter`. Python is the checker because this environment has no JVM, and the state space is those steps rather than a whole-program proof. TLA+ would be the usual tool for an ordering question. TLC is not required to answer this one, and this skill does not invoke it.

The steps are the awaits and the SQLite commit in the Rust functions, not a separate design:

- `TraceStore::start` commits `INSERT INTO traces` before `create_private_directory` and the two `create_private_file` calls.
- `TraceWriter::append` checks `!self.failed`, sets `self.failed = true` before the first await, flushes, then sets `self.failed = false`.
- `TraceWriter::finish` checks `!self.failed`, calls `sync_all` on each open body, syncs the trace-id directory, syncs the trace root, then runs `UPDATE ... SET complete = 1 ... AND complete = 0`.

`&mut self` on the writer means append and finish do not overlap on one trace. The explored choices are crash, a failed append, and the next durability step.

## Run

From the inference-gateway repository root:

```sh
python3 .cursor/skills/verify-trace-completion/check.py
```

Exit 0 means the three functions still contain those steps in that order, every reachable state keeps the property, and the model reached a finished trace, a process crash, and a failed append. A pass that cannot reach those three is rejected so an empty model cannot pass.

If `src/trace.rs` differs from the sync blob below, the command still exits 0 when the order matches, and it prints a notice. Re-read the three functions before trusting that pass. A notice means the file changed. It does not by itself mean the property failed.

These two commands must each exit 2 and print a violation. If either exits 0, the check can no longer fail:

```sh
python3 .cursor/skills/verify-trace-completion/check.py --broken commit-before-sync
python3 .cursor/skills/verify-trace-completion/check.py --broken finish-after-failed
```

`commit-before-sync` is finish setting `complete = 1` before `sync_all` and the directory syncs. The shortest failure is: start commits the incomplete row, start creates the body files, the broken finish marks the row complete. A control read sees `complete = 1` while the bodies are not durable.

`finish-after-failed` is finish setting `complete = 1` after append has failed. The failure path sets `failed` and then marks the row complete.

## Reading a result

A source mismatch names `TraceStore::start`, `TraceWriter::append`, or `TraceWriter::finish` and the missing marker. Read that function. If the code still refuses a failed writer and still syncs bodies and both directories before the UPDATE, the model is stale: update the markers and the successor steps together, re-run the faithful command and both `--broken` commands, then move the sync commit. If the code now commits `complete = 1` earlier, or after `failed` is set, that is a finding in the product. Leave the finding in place. Do not delete a marker or weaken the property to make the command pass, and do not change product code unless the user asks.

A faithful-model failure prints steps in the words of those functions. Compare them with the function bodies. If the steps do not exist in the code, the successor list is a modeling error. If they do, the finding is the product order.

## Coverage

| Item | Location |
|---|---|
| Sync commit | `41f05d49946908ad5fb800510713f7a95b8d95cd` |
| `src/trace.rs` blob at that commit | `3ab27946e694e8ca98b7bfc99f2a529f0a6e91ad` |
| Covered code | `TraceStore::start`, `TraceWriter::append`, `TraceWriter::finish` |

The same commit and blob are `SYNC_COMMIT` and `TRACE_RS_BLOB` in `.cursor/skills/verify-trace-completion/check.py`. Move the skill values and the constants together. Move them only after you have re-read the three functions at the new commit, the faithful command passes, and both `--broken` commands still exit 2.

`git diff 41f05d49946908ad5fb800510713f7a95b8d95cd -- src/trace.rs` shows whether the covered file has changed. A change outside those three functions still deserves a reading of the diff, because the checker only anchors the markers above.

## Bounds

Checked: one writer lifetime; the incomplete insert before body files exist; crash instead of the next step; a failed append that must not finish; `sync_all`, the trace-id directory sync, and the trace-root directory sync before `complete = 1`.

Not checked: a second process, a second writer, Codex refresh, header redaction, export byte caps, or the SQLite pragma values. The code comment names WAL and `synchronous=FULL`. This checker does not re-prove those pragmas. It also does not require the converse. A crash after the syncs and before the UPDATE leaves the row incomplete, and that state is allowed.

`finish` runs only after `start` returns, so the request and response files already exist. Optional upstream body files are created later by append. The property does not claim those optional files exist on every complete trace.

The closest next target is Codex refresh single-flight in `src/auth.rs` (`codex_headers`, `refresh_and_resolve`, `persist_if_unchanged`, `shared_refresh_lock`). A lost or overwritten refresh token harms the login, and the existing tests do not enumerate those lock steps. It is not this check.
