#!/usr/bin/env python3
"""Exhaustive check of one infer trace writer's completion order.

The property is about crash points in TraceStore::start, TraceWriter::append,
and TraceWriter::finish, not about every byte of a body. Python enumerates
those steps because this machine has no JVM and the state space is the awaits
in one writer. TLA+ would answer the same question; TLC is not required here.

A passing run has seen the writer reach complete, crash, and a failed append,
and none of those states advertise complete too early.
"""

import argparse
import pathlib
import subprocess
import sys
from collections import deque

REPO = pathlib.Path(__file__).resolve().parents[3]
TRACE_RS = REPO / "src" / "trace.rs"

# Move these only after re-reading the covered functions at the new commit
# and confirming this checker still describes them. Keep the same values in
# SKILL.md.
SYNC_COMMIT = "41f05d49946908ad5fb800510713f7a95b8d95cd"
TRACE_RS_BLOB = "3ab27946e694e8ca98b7bfc99f2a529f0a6e91ad"

# row, files, dirs, failed, pc
State = tuple

STEP_WORDS = {
    "StartInsert": "TraceStore::start commits the incomplete trace row.",
    "StartFiles": "TraceStore::start creates the trace directory and the request and response body files.",
    "AppendBegin": "TraceWriter::append sets failed before its first await.",
    "AppendFlush": "TraceWriter::append flushes the chunk and clears failed. This flush is not the finish sync.",
    "AppendAbort": "TraceWriter::append stops on a write or flush error and leaves failed set.",
    "Crash": "The process stops. The in-memory writer is gone, and SQLite still shows the last committed row.",
    "SyncBodies": "TraceWriter::finish calls sync_all on each open body file.",
    "SyncIdDir": "TraceWriter::finish syncs the trace-id directory.",
    "SyncRootDir": "TraceWriter::finish syncs the trace root directory.",
    "CommitComplete": "TraceWriter::finish sets complete = 1 only where complete = 0.",
    "CommitBeforeSync": "The broken finish sets complete = 1 before sync_all and before either directory sync.",
    "CommitAfterFailedAppend": "The broken finish sets complete = 1 after an append has already failed.",
}


def function_body(source, signature):
    lines = source.splitlines(keepends=True)
    start = next(i for i, line in enumerate(lines) if line.startswith(signature))
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith(("pub ", "fn ", "async fn ", "impl ")):
            end = index
            break
    chunks = []
    for line in lines[start:end]:
        code, _, _ = line.partition("//")
        chunks.append(code)
    return "".join(chunks)


def require_order(body, markers, label):
    cursor = 0
    found = []
    for marker in markers:
        at = body.find(marker, cursor)
        if at < 0:
            earlier = body.find(marker)
            where = (
                f"{marker!r} now appears before {found[-1]!r}."
                if found and 0 <= earlier < cursor
                else f"Missing {marker!r} after {found!r}."
            )
            raise SystemExit(
                f"{label} no longer matches the model.\n"
                f"{where}\n"
                "The model requires this order: "
                + ", ".join(markers)
                + ".\nThis is a finding until the new order is an intended change. "
                "Do not drop a marker to make the check pass."
            )
        found.append(marker)
        cursor = at + len(marker)
    return found


def source_matches():
    source = TRACE_RS.read_text(encoding="utf-8")
    start = function_body(source, "    pub async fn start(")
    append = function_body(source, "    async fn append(")
    finish = function_body(source, "    pub async fn finish(")
    require_order(
        start,
        ["INSERT INTO traces", "create_private_directory", "create_private_file", "create_private_file"],
        "TraceStore::start",
    )
    require_order(
        append,
        ["!self.failed", "self.failed = true", "flush()", "self.failed = false"],
        "TraceWriter::append",
    )
    require_order(
        finish,
        [
            "!self.failed",
            "sync_all()",
            "sync_directory(&root.join(&id))",
            "sync_directory(root)",
            "SET complete = 1",
            "AND complete = 0",
        ],
        "TraceWriter::finish",
    )


def holds(state):
    row, files, dirs, failed, _pc = state
    if row != "complete":
        return True
    return files == "synced" and dirs == "both" and failed == 0


def successors(state, broken):
    row, files, dirs, failed, pc = state
    steps = []

    def add(name, nxt):
        steps.append((name, nxt))

    if pc == "init":
        add("StartInsert", ("incomplete", files, dirs, failed, "after_insert"))
    elif pc == "after_insert":
        add("StartFiles", (row, "present", dirs, failed, "idle"))
        add("Crash", (row, files, dirs, 0, "dead"))
    elif pc == "idle":
        add("AppendBegin", (row, files, dirs, 1, "appending"))
        if failed == 0 and files == "present":
            add("SyncBodies", (row, "synced", dirs, failed, "after_bodies"))
        if broken == "commit-before-sync" and failed == 0 and row == "incomplete":
            add("CommitBeforeSync", ("complete", files, dirs, failed, "done"))
        add("Crash", (row, files, dirs, 0, "dead"))
    elif pc == "appending":
        add("AppendFlush", (row, files, dirs, 0, "idle"))
        add("AppendAbort", (row, files, dirs, 1, "refused"))
        add("Crash", (row, files, dirs, 0, "dead"))
    elif pc == "refused":
        if broken == "finish-after-failed":
            add("CommitAfterFailedAppend", ("complete", files, dirs, failed, "done"))
    elif pc == "after_bodies":
        add("SyncIdDir", (row, files, "id", failed, "after_id"))
        add("Crash", (row, files, dirs, 0, "dead"))
    elif pc == "after_id":
        add("SyncRootDir", (row, files, "both", failed, "after_dirs"))
        add("Crash", (row, files, dirs, 0, "dead"))
    elif pc == "after_dirs":
        if failed == 0 and files == "synced" and dirs == "both" and row == "incomplete":
            add("CommitComplete", ("complete", files, dirs, failed, "done"))
        add("Crash", (row, files, dirs, 0, "dead"))
    return steps


def explore(broken):
    start = ("absent", "none", "none", 0, "init")
    seen = {start: (None, None)}
    queue = deque([start])
    violation = None
    while queue:
        state = queue.popleft()
        if not holds(state) and violation is None:
            violation = state
        for name, nxt in successors(state, broken):
            if nxt not in seen:
                seen[nxt] = (state, name)
                queue.append(nxt)
    return seen, violation


def path_of(seen, state):
    steps = []
    while state is not None:
        previous, name = seen[state]
        if name is not None:
            steps.append(name)
        state = previous
    steps.reverse()
    return steps


def worktree_blob():
    return subprocess.check_output(
        ["git", "hash-object", str(TRACE_RS)],
        cwd=REPO,
        text=True,
    ).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--broken",
        choices=("commit-before-sync", "finish-after-failed"),
        help="explore a finish() that breaks the property; must find a violation",
    )
    args = parser.parse_args()
    source_matches()
    seen, violation = explore(args.broken)
    reached = {state[4] for state in seen}
    complete = [state for state in seen if state[0] == "complete" and holds(state)]
    if args.broken is None:
        if violation is not None:
            steps = path_of(seen, violation)
            print("property failed on the faithful model:")
            for step in steps:
                print(f"- {STEP_WORDS[step]}")
            return 1
        if not complete or "dead" not in reached or "refused" not in reached:
            print(
                "the faithful model never reached a finished trace, a crash, and a failed append; "
                "a pass would be vacuous"
            )
            return 1
        blob = worktree_blob()
        print(
            f"pass: start, append, and finish in src/trace.rs match the model "
            f"({len(seen)} reachable states, {len(complete)} finished states)"
        )
        if blob != TRACE_RS_BLOB:
            print(
                f"notice: src/trace.rs blob {blob} differs from sync blob {TRACE_RS_BLOB} "
                f"at commit {SYNC_COMMIT}. Re-read TraceStore::start, TraceWriter::append, "
                "and TraceWriter::finish before treating this pass as current. "
                "Move SYNC_COMMIT and TRACE_RS_BLOB only after that reading still matches the model."
            )
        else:
            print(f"pass: src/trace.rs matches sync blob {TRACE_RS_BLOB} at {SYNC_COMMIT}")
        return 0
    if violation is None:
        print(f"--broken {args.broken} found no violation; the check can no longer fail")
        return 1
    steps = path_of(seen, violation)
    print(f"violation: --broken {args.broken}")
    for step in steps:
        print(f"- {STEP_WORDS[step]}")
    if args.broken == "commit-before-sync":
        print(
            "A control read can see complete=1 after the body files exist and before "
            "sync_all or either directory sync. The index calls the capture finished "
            "while those bytes are not durable."
        )
    else:
        print(
            "An append fails after it has set failed. finish still sets complete=1. "
            "The index calls a failed capture finished."
        )
    return 2


if __name__ == "__main__":
    sys.exit(main())
