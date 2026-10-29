# Working on infer

Read `README.md`, `CONVENTIONS.md`, and the architecture guides in `docs/` before changing the gateway.
Preserve the existing routing, translation, authentication, and storage boundaries.

Use isolated test directories and dummy credentials. Keep default tests offline and deterministic.
Run the relevant checks in `CONVENTIONS.md`; distinguish observed results from assumptions.
Live inference, private-history imports, credential rotation, and publication require explicit authorization.

Never commit credentials, raw traces, provider exports, local agent state, or private development records.
Preserve unrelated changes. Use Conventional Commits and the configured Git identity.
Do not push, deploy, publish, or rewrite shared history without explicit authorization.
