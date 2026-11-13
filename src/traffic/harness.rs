//! One implementation per first-party client. Codex is the only harness so far.

pub trait Harness: Send + Sync {
    fn id(&self) -> &'static str;
    /// Path prefix of the upstream API on its origin.
    /// Codex requests `POST /backend-api/codex/responses`; comparisons use `/responses`.
    fn api_base_path(&self) -> &'static str;
    /// Headers that must match after normalization, including matching absence.
    fn compared_headers(&self) -> &'static [&'static str];
    /// Headers the upstream request must not carry.
    fn forbidden_headers(&self) -> &'static [&'static str];
}
