#!/usr/bin/env python3
"""Exhaustive check of one infer trace writer's completion order."""

import argparse
import pathlib
import re
import subprocess
import sys
from collections import deque

REPO = pathlib.Path(__file__).resolve().parents[3]
TRACE_RS = REPO / "src" / "trace.rs"

SYNC_COMMIT = "41f05d49946908ad5fb800510713f7a95b8d95cd"
TRACE_RS_BLOB = "3ab27946e694e8ca98b7bfc99f2a529f0a6e91ad"

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


START_ORDER = (
    "INSERT INTO traces",
    "create_private_directory",
    "create_private_file",
    "create_private_file",
)
APPEND_ORDER = (
    "!self.failed",
    "self.failed = true",
    "write_all",
    "flush()",
    "self.failed = false",
)
FINISH_ORDER = (
    "!self.failed",
    "sync_all",
    "sync_directory(&root.join(&id))",
    "sync_directory(root)",
    "SET complete = 1",
    "AND complete = 0",
)
FINISH_BEFORE_COMPLETE = (
    "sync_all",
    "sync_directory(&root.join(&id))",
    "sync_directory(root)",
)
LET_CLOSURE = re.compile(
    r"^let\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
    r"(?:async\b\s*)?(?:move\b\s*)?(?:\|[^|]*\|\s*)?\{",
    re.S,
)
NEEDLES = (
    ("sync_directory(&root.join(&id))", "sync_directory(&root.join(&id))"),
    ("sync_directory(root)", "sync_directory(root)"),
    ("self.failed = true", "self.failed = true"),
    ("self.failed = false", "self.failed = false"),
    ("!self.failed", "!self.failed"),
    ("write_all", "write_all"),
    ("flush()", "flush()"),
    ("SET complete = 1", "SET complete = 1"),
    ("AND complete = 0", "AND complete = 0"),
    ("INSERT INTO traces", "INSERT INTO traces"),
    ("create_private_directory", "create_private_directory"),
    ("create_private_file", "create_private_file"),
    ("sync_all()", None),
)


def strip_line_comments(source):
    pieces = []
    for line in source.splitlines(keepends=True):
        code, sep, _comment = line.partition("//")
        if sep:
            pieces.append(code + ("\n" if line.endswith("\n") else ""))
        else:
            pieces.append(line)
    return "".join(pieces)


def skip_string(text, index):
    quote = text[index]
    i = index + 1
    while i < len(text):
        if text[i] == "\\":
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    return i


def match_delimiter(text, open_index, open_ch, close_ch):
    depth = 0
    i = open_index
    while i < len(text):
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise SystemExit(f"unbalanced {open_ch}{close_ch} in trace function")


def find_body_brace(text):
    paren = 0
    bracket = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif ch == "{" and paren == 0 and bracket == 0:
            return i
        i += 1
    raise SystemExit("missing block body in trace function")


def function_interior(source, signature):
    stripped = strip_line_comments(source)
    at = stripped.find(signature)
    if at < 0:
        raise SystemExit(f"missing {signature!r}")
    text = stripped[at:]
    paren = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "{" and paren == 0:
            end = match_delimiter(text, i, "{", "}")
            return text[i + 1 : end]
        i += 1
    raise SystemExit(f"missing body for {signature!r}")


def split_statements(text):
    statements = []
    start = 0
    paren = 0
    bracket = 0
    brace = 0
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        if ch == "(":
            paren += 1
        elif ch == ")":
            paren -= 1
        elif ch == "[":
            bracket += 1
        elif ch == "]":
            bracket -= 1
        elif ch == "{":
            brace += 1
        elif ch == "}":
            brace -= 1
            if brace == 0 and paren == 0 and bracket == 0:
                rest = text[i + 1 :]
                nxt = rest.lstrip()
                if nxt.startswith(("else", ".", "?")):
                    i += 1
                    continue
                end = i + 1
                if nxt.startswith(";"):
                    end = i + 1 + (len(rest) - len(nxt)) + 1
                statements.append(text[start:end])
                start = end
                i = end
                continue
        elif ch == ";" and paren == 0 and bracket == 0 and brace == 0:
            statements.append(text[start : i + 1])
            start = i + 1
        i += 1
    tail = text[start:]
    if tail.strip():
        statements.append(tail)
    return [item for item in statements if item.strip()]


def awaited_after(segment, index):
    return segment[index:].lstrip().startswith(".await")


def effects_in_code(segment):
    found = []
    for needle, label in NEEDLES:
        start = 0
        while True:
            at = segment.find(needle, start)
            if at < 0:
                break
            if label is None:
                effect = "sync_all" if awaited_after(segment, at + len(needle)) else "sync_all discarded"
            else:
                effect = label
            found.append((at, effect))
            start = at + len(needle)
    found.sort(key=lambda item: item[0])
    return [effect for _at, effect in found]


def ident_at(text, index):
    ch = text[index]
    if not (ch.isalpha() or ch == "_"):
        return False
    if index == 0:
        return True
    prev = text[index - 1]
    return not (prev.isalnum() or prev == "_")


def expr_paths(text, deferred):
    paths = [[]]
    segment_start = 0
    i = 0
    n = len(text)

    def take(end):
        nonlocal paths, segment_start
        extra = effects_in_code(text[segment_start:end])
        if extra:
            paths = [path + extra for path in paths]
        segment_start = end

    while i < n:
        ch = text[i]
        if ch in "\"'":
            i = skip_string(text, i)
            continue
        if ch == "{":
            take(i)
            end = match_delimiter(text, i, "{", "}")
            nested = walk_block(text[i + 1 : end], deferred)
            paths = [path + extra for path in paths for extra in nested]
            i = end + 1
            segment_start = i
            continue
        if ident_at(text, i):
            j = i + 1
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            name = text[i:j]
            k = j
            while k < n and text[k].isspace():
                k += 1
            called = name in deferred and (
                text.startswith(".await", k) or (k < n and text[k] == "(")
            )
            if called:
                take(i)
                nested = walk_block(deferred[name], deferred)
                paths = [path + extra for path in paths for extra in nested]
                if text.startswith(".await", k):
                    i = k + len(".await")
                else:
                    i = match_delimiter(text, k, "(", ")") + 1
                segment_start = i
                continue
            i = j
            continue
        i += 1
    take(n)
    return paths


def if_arms(stmt, deferred):
    options = []
    saw_else = False
    rest = stmt.strip()
    while rest:
        if rest.startswith("else if"):
            rest = rest[len("else ") :].lstrip()
        elif rest.startswith("else"):
            saw_else = True
            rest = rest[len("else") :].lstrip()
        elif not (rest.startswith("if ") or rest.startswith("if(") or rest.startswith("{")):
            break
        brace = find_body_brace(rest)
        end = match_delimiter(rest, brace, "{", "}")
        options.extend(walk_block(rest[brace + 1 : end], deferred))
        rest = rest[end + 1 :].lstrip()
        if not rest.startswith("else"):
            break
    if not saw_else:
        options.append([])
    if rest.strip():
        tails = expr_paths(rest, deferred)
        options = [head + tail for head in options for tail in tails]
    return options


def stmt_paths(stmt, deferred):
    stripped = stmt.strip()
    match = LET_CLOSURE.match(stripped)
    if match:
        brace = match.end() - 1
        end = match_delimiter(stripped, brace, "{", "}")
        deferred[match.group(1)] = stripped[brace + 1 : end]
        return [[]]
    if stripped.startswith(("for ", "for(", "while ", "while(", "loop ", "loop{")):
        brace = find_body_brace(stripped)
        end = match_delimiter(stripped, brace, "{", "}")
        return walk_block(stripped[brace + 1 : end], deferred)
    if stripped.startswith("if ") or stripped.startswith("if("):
        return if_arms(stripped, deferred)
    return expr_paths(stmt, deferred)


def walk_block(text, deferred=None):
    local = {} if deferred is None else dict(deferred)
    paths = [[]]
    for stmt in split_statements(text):
        options = stmt_paths(stmt, local)
        if not options:
            options = [[]]
        paths = [path + extra for path in paths for extra in options]
    return paths


def index_of(path, effect):
    try:
        return path.index(effect)
    except ValueError:
        return None


def subsequence_miss(path, required):
    cursor = 0
    for marker in required:
        while cursor < len(path) and path[cursor] != marker:
            cursor += 1
        if cursor == len(path):
            return marker
        cursor += 1
    return None


def check_start(path):
    miss = subsequence_miss(path, START_ORDER)
    if miss:
        return f"misses {miss} in execution order"
    return None


def check_append(path):
    write_at = index_of(path, "write_all")
    set_at = index_of(path, "self.failed = true")
    if write_at is not None and (set_at is None or write_at < set_at):
        return "sets failed only after write_all"
    miss = subsequence_miss(path, APPEND_ORDER)
    if miss:
        return f"misses {miss} in execution order"
    return None


def check_finish(path):
    if "sync_all discarded" in path:
        return "discards sync_all"
    complete_at = index_of(path, "SET complete = 1")
    if complete_at is not None:
        for marker in FINISH_BEFORE_COMPLETE:
            at = index_of(path, marker)
            if at is None or complete_at < at:
                return f"executes complete = 1 before {marker}"
    miss = subsequence_miss(path, FINISH_ORDER)
    if miss:
        return f"misses {miss} in execution order"
    return None


def execution_violations(source):
    checks = (
        ("TraceStore::start", "    pub async fn start(", check_start),
        ("TraceWriter::append", "    async fn append(", check_append),
        ("TraceWriter::finish", "    pub async fn finish(", check_finish),
    )
    found = []
    for label, signature, check in checks:
        interior = function_interior(source, signature)
        for path in walk_block(interior):
            reason = check(path)
            if reason:
                found.append((label, reason, path))
                break
    return found


def read_source(source):
    if source is None:
        return TRACE_RS.read_text(encoding="utf-8")
    path = pathlib.Path(source)
    if not path.is_file():
        path = REPO / source
    if not path.is_file():
        raise SystemExit(f"missing source {source}")
    return path.read_text(encoding="utf-8")


def report_violations(violations):
    for label, reason, path in violations:
        print(f"violation: {label} {reason}")
        for effect in path:
            print(f"- {effect}")
    return 2


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
        "source",
        nargs="?",
        help="Rust file to check instead of src/trace.rs",
    )
    parser.add_argument(
        "--broken",
        choices=("commit-before-sync", "finish-after-failed"),
        help="explore a finish() that breaks the property; must find a violation",
    )
    args = parser.parse_args()
    violations = execution_violations(read_source(args.source))
    if violations:
        return report_violations(violations)
    if args.source is not None and args.broken is None:
        print("pass: start, append, and finish execute in order")
        return 0
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
