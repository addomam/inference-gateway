# Development conventions

infer is a Rust gateway and CLI using Axum, Tokio, and SQLite. The OMP capture extension is TypeScript.
See [architecture](docs/architecture.md), [data flow](docs/data-flow.md), and [database schema](docs/database-schema.md).
Reuse the existing module boundaries and keep changes focused.

## Checks

Run from the repository root:

```sh
cargo test --locked -- --test-threads=1
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --check
cargo build --release --locked
```

Use `--offline` with Cargo when the locked dependencies are already cached and network access is unavailable.
The two live inference tests are ignored by default and may make billable requests when explicitly enabled.
Use isolated temporary directories, loopback fixture servers, and dummy credentials for ordinary tests.
Follow the in-memory verification procedure in the database guide when changing storage schemas.

## Evidence and data

Record checks actually run and their limitations. Do not describe fixture results as production or provider-entitlement validation.
Raw traces, imported histories, exports, and event spools can contain credentials, personal data, or source code.
Keep them outside version control. Header redaction does not sanitize model content.

## Contributions

Preserve unrelated changes and architectural intent. Use Conventional Commits.
Repository-owned material is dedicated under CC0-1.0; retain applicable third-party terms and attribution.
