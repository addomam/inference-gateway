# Third-party notices

Original infer material is dedicated under CC0-1.0; see [LICENSE](LICENSE).
The third-party portions identified below retain their own terms.

## Codex schema test fixtures

OpenAI Codex
Copyright 2025 OpenAI

The SQL declarations in `tests/fixtures/codex_state.sql` and
`tests/fixtures/codex_history.sql` are adapted from OpenAI Codex and are retained
under the [Apache License 2.0](LICENSES/Apache-2.0.txt).
The files carry modification notices. This is the repository's Apache-2.0 exception
to the CC0 dedication of original material.

The reference revision is [`8531184b49bcb160175a84e140b659a83a426df7`](https://github.com/openai/codex/tree/8531184b49bcb160175a84e140b659a83a426df7):

- [Thread schema](https://github.com/openai/codex/blob/8531184b49bcb160175a84e140b659a83a426df7/codex-rs/state/migrations/0001_threads.sql): retain the table declaration; omit upstream query indexes.
- [Thread-history schema](https://github.com/openai/codex/blob/8531184b49bcb160175a84e140b659a83a426df7/codex-rs/state/thread_history_migrations/0001_thread_history.sql): retain selected table/index declarations.
- [Realtime-item schema](https://github.com/openai/codex/blob/8531184b49bcb160175a84e140b659a83a426df7/codex-rs/state/thread_history_migrations/0005_thread_realtime_items.sql): retain the table declaration; omit indexes and the cleanup trigger.

The upstream [NOTICE](https://github.com/openai/codex/blob/8531184b49bcb160175a84e140b659a83a426df7/NOTICE)
also attributes Ratatui. No Ratatui or Codex terminal-UI code is included in these
schema fixtures; that unrelated attribution does not apply to these portions.

## Dependencies and distribution scope

`Cargo.lock` identifies the Rust dependencies. This source repository and its
Cargo source package do not vendor those dependency sources or contain compiled
third-party libraries. Referencing or downloading dependencies does not change
their licenses to CC0.

If distributing an infer executable, include the applicable copyright notices,
license texts, and required notices for the dependencies actually linked into
that build, including bundled native components. The Codex-fixture notice above
is not a replacement for those binary-distribution notices. The OMP extension
uses its host's APIs; the OMP host is not bundled in this repository.
