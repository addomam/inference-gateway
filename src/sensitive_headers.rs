/// Header names whose values must not be persisted in trace metadata.
///
/// Keep this shared by the HTTP serializer and TraceStore so credentials
/// cannot bypass redaction at either boundary.
pub(crate) fn is_sensitive_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "authorization"
            | "proxy-authorization"
            | "api-key"
            | "x-auth-key"
            | "x-auth-email"
            | "x-infer-key"
            | "cookie"
            | "set-cookie"
            | "x-auth-token"
            | "x-access-token"
            | "chatgpt-account-id"
    ) || name.ends_with("-api-key")
        || name.contains("token")
        || name.contains("secret")
}
