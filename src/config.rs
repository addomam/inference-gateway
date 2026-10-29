use std::{collections::BTreeMap, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::{auth::AuthConfig, catalog, translate::Protocol};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "inference_bind")]
    pub listen: SocketAddr,
    #[serde(default = "control_bind")]
    pub control_listen: SocketAddr,
    pub proxy_token_env: String,
    pub control_token_env: String,
    #[serde(default = "trace_dir")]
    pub trace_dir: PathBuf,
    pub default_provider: String,
    #[serde(default = "max_request")]
    pub max_request_bytes: usize,
    #[serde(default = "max_response")]
    pub max_buffered_response_bytes: usize,
    #[serde(default = "connect_timeout")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "read_timeout")]
    pub read_timeout_seconds: u64,
    pub providers: BTreeMap<String, Provider>,
    #[serde(default)]
    pub models: BTreeMap<String, ModelRoute>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub kind: Kind,
    pub base_url: String,
    #[serde(default)]
    pub auth: AuthConfig,
    /// Client model prefix, such as `xai` in `xai/grok-4.7`. Without this value,
    /// the provider claims no namespace. Aliases, catalog routing, the default,
    /// and explicit provider paths can still select it.
    #[serde(default)]
    pub namespace: Option<String>,
    /// Opt this System One provider into experimental images and Box questions.
    /// infer then sends `TypeSafe-Danger-Zone-Images: true` on every request.
    #[serde(default)]
    pub danger_zone_images: bool,
    /// Local ceiling for OpenAI `access_programs.cyber`. OpenAI does not publish
    /// this entitlement. `standard` hides Daybreak models. `blue` and `red` allow
    /// those programs and list the matching models.
    #[serde(default)]
    pub daybreak: DaybreakLevel,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DaybreakLevel {
    #[default]
    Standard,
    Blue,
    Red,
}

impl DaybreakLevel {
    pub fn allows(self, program: &str) -> bool {
        match self {
            Self::Standard => program == "standard",
            Self::Blue => matches!(program, "standard" | "daybreak_blue"),
            Self::Red => matches!(program, "standard" | "daybreak_blue" | "daybreak_red"),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Blue => "blue",
            Self::Red => "red",
        }
    }
}

/// Coarse route family. A provider profile's dialects, not this enum, decide
/// whether it can serve a request. System One is a Decisions dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Generation,
    Decisions,
    Extraction,
    Embeddings,
}

impl std::fmt::Display for Capability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Generation => "generation",
            Self::Decisions => "decisions",
            Self::Extraction => "extraction",
            Self::Embeddings => "embeddings",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Anthropic,
    Openai,
    Grok,
    Llama,
    Codex,
    OpenaiDecisions,
    Clairic,
    SystemOne,
}

impl Kind {
    pub fn family(self) -> catalog::Family {
        match self {
            Self::Openai | Self::OpenaiDecisions => catalog::Family::Openai,
            Self::Anthropic => catalog::Family::Anthropic,
            Self::Grok => catalog::Family::Xai,
            Self::Llama => catalog::Family::Llama,
            Self::Codex => catalog::Family::Codex,
            Self::Clairic => catalog::Family::Cloudflare,
            Self::SystemOne => catalog::Family::TypeSafe,
        }
    }

    pub fn dialects(self) -> &'static [catalog::Dialect] {
        match self {
            Self::Openai => catalog::OPENAI,
            Self::Grok => catalog::CHAT_AND_RESPONSES,
            Self::Llama => catalog::LLAMA,
            Self::Codex => catalog::RESPONSES,
            Self::Anthropic => catalog::MESSAGES,
            Self::OpenaiDecisions => catalog::DECISIONS,
            Self::SystemOne => catalog::SYSTEM_ONE,
            Self::Clairic => catalog::CLAIRIC,
        }
    }

    pub fn capability(self) -> Capability {
        match self.dialects()[0] {
            catalog::Dialect::Chat | catalog::Dialect::Responses | catalog::Dialect::Messages => {
                Capability::Generation
            }
            catalog::Dialect::Decisions | catalog::Dialect::SystemOne => Capability::Decisions,
            catalog::Dialect::Extraction => Capability::Extraction,
            catalog::Dialect::Embeddings => Capability::Embeddings,
            catalog::Dialect::Transcription
            | catalog::Dialect::Speech
            | catalog::Dialect::Realtime
            | catalog::Dialect::Diarization => Capability::Generation,
        }
    }

    /// Decision and extraction APIs do not use a generation protocol.
    pub fn protocol(self, source: Protocol) -> Option<Protocol> {
        Some(match self {
            Self::OpenaiDecisions | Self::SystemOne | Self::Clairic => return None,
            Self::Anthropic => Protocol::Anthropic,
            Self::Codex => Protocol::Responses,
            _ if source == Protocol::Responses => Protocol::Responses,
            _ => Protocol::Chat,
        })
    }
}

#[derive(Debug)]
pub struct ModelSelection<'a> {
    pub provider: &'a str,
    pub upstream_model: String,
    pub access_program: Option<&'static str>,
    pub operations: Vec<catalog::Operation>,
    pub operations_declared: bool,
    pub modalities: Option<Vec<catalog::Modality>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRoute {
    pub provider: String,
    pub model: String,
    /// Empty inherits the upstream catalog record. A non-empty list declares a
    /// local model that is not in the compiled catalog.
    #[serde(default)]
    pub operations: Vec<catalog::Operation>,
    /// Empty inherits the upstream catalog record. A non-empty list declares
    /// which image, audio, and video inputs a local model accepts.
    #[serde(default)]
    pub modalities: Vec<catalog::Modality>,
}

impl Config {
    pub async fn load(path: &std::path::Path) -> Result<Self> {
        let config: Self = toml::from_str(
            &tokio::fs::read_to_string(path)
                .await
                .context("reading configuration")?,
        )
        .context("parsing configuration")?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        if self.listen == self.control_listen {
            bail!("inference and control listeners must differ");
        }
        if !self.providers.contains_key(&self.default_provider) {
            bail!("default_provider is not configured");
        }
        if self.max_request_bytes == 0
            || self.max_buffered_response_bytes == 0
            || self.connect_timeout_seconds == 0
            || self.read_timeout_seconds == 0
        {
            bail!("body limits and timeouts must be positive");
        }
        for (name, provider) in &self.providers {
            if provider.danger_zone_images && provider.kind != Kind::SystemOne {
                bail!("provider {name}: danger_zone_images is only valid for system_one");
            }
            if provider.daybreak != DaybreakLevel::Standard && provider.kind != Kind::Openai {
                bail!("provider {name}: daybreak is only valid for openai");
            }
            if name.is_empty()
                || !name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            {
                bail!("provider names must contain only ASCII letters, digits, _ or -");
            }
            let url =
                reqwest::Url::parse(&provider.base_url).context("invalid provider base_url")?;
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
            {
                bail!(
                    "provider {name}: base_url must be an HTTP(S) URL without credentials, query, or fragment"
                );
            }
        }
        let mut namespaces = BTreeMap::<(&str, catalog::Dialect), &str>::new();
        for (name, provider) in &self.providers {
            let Some(namespace) = provider.namespace.as_deref() else {
                continue;
            };
            if !valid_name(namespace) {
                bail!("provider {name}: namespace must contain only ASCII letters, digits, _ or -");
            }
            for dialect in provider.kind.dialects() {
                if let Some(existing) = namespaces.insert((namespace, *dialect), name) {
                    bail!(
                        "namespace {namespace} is claimed by both {existing} and {name} for {dialect}"
                    );
                }
            }
        }
        for (alias, target) in &self.models {
            if alias.is_empty()
                || target.model.is_empty()
                || !self.providers.contains_key(&target.provider)
            {
                bail!("invalid model route {alias}");
            }
        }
        Ok(())
    }

    /// Exact `[models]` alias, then `namespace/model`, then a compiled catalog
    /// hit, otherwise the default provider.
    ///
    /// A configured namespace is an explicit backend selection. A slash in an
    /// unconfigured prefix stays part of the model id so local ids such as
    /// `meta-llama/Llama-3.1-8B` still reach the default provider. A catalog
    /// hit never guesses a different family.
    pub fn resolve_model(
        &self,
        model: &str,
        client: catalog::Dialect,
    ) -> Result<ModelSelection<'_>> {
        if let Some(route) = self.models.get(model) {
            return Ok(ModelSelection {
                provider: route.provider.as_str(),
                upstream_model: route.model.clone(),
                access_program: None,
                operations: if route.operations.is_empty() {
                    catalog::lookup(&route.model)
                        .map(|record| record.operations.to_vec())
                        .unwrap_or_default()
                } else {
                    route.operations.clone()
                },
                operations_declared: !route.operations.is_empty()
                    || catalog::lookup(&route.model).is_some(),
                modalities: if route.modalities.is_empty() {
                    catalog::lookup(&route.model)
                        .and_then(|record| record.modalities.map(|items| items.to_vec()))
                } else {
                    Some(route.modalities.clone())
                },
            });
        }
        if let Some((namespace, remainder)) = model.split_once('/')
            && !namespace.is_empty()
            && self
                .providers
                .values()
                .any(|provider| provider.namespace.as_deref() == Some(namespace))
        {
            if remainder.is_empty() {
                bail!("namespaced model {model} is missing an upstream model");
            }
            match catalog::resolve(remainder) {
                Ok(Some(hit)) => return self.catalog_provider(Some(namespace), client, hit),
                Ok(None) => tracing::warn!(
                    model = remainder,
                    dialect = %client,
                    "catalog has no record; using the provider profile"
                ),
                Err(error) => bail!("{error}"),
            }
            let mut matches = self.providers.iter().filter(|(_, provider)| {
                provider.namespace.as_deref() == Some(namespace)
                    && catalog::target_dialect(client, provider.kind.dialects()).is_some()
            });
            let Some((name, _)) = matches.next() else {
                bail!("namespace {namespace} has no {client} provider");
            };
            if matches.next().is_some() {
                bail!("namespace {namespace} is ambiguous for {client}");
            }
            return Ok(ModelSelection {
                provider: name.as_str(),
                upstream_model: remainder.to_owned(),
                access_program: None,
                operations: catalog::lookup(remainder)
                    .map(|record| record.operations.to_vec())
                    .unwrap_or_default(),
                operations_declared: catalog::lookup(remainder).is_some(),
                modalities: catalog::lookup(remainder)
                    .and_then(|record| record.modalities.map(|items| items.to_vec())),
            });
        }
        match catalog::resolve(model) {
            Ok(Some(hit)) => return self.catalog_provider(None, client, hit),
            Ok(None) => tracing::warn!(
                model,
                dialect = %client,
                "catalog has no record; using the provider profile"
            ),
            Err(error) => bail!("{error}"),
        }
        Ok(ModelSelection {
            provider: self.default_provider.as_str(),
            upstream_model: model.to_owned(),
            access_program: None,
            operations: Vec::new(),
            operations_declared: false,
            modalities: None,
        })
    }

    fn catalog_provider(
        &self,
        namespace: Option<&str>,
        client: catalog::Dialect,
        hit: catalog::Hit,
    ) -> Result<ModelSelection<'_>> {
        let Some(target) = catalog::target_dialect(client, hit.record.dialects) else {
            bail!(
                "generation, embeddings, System One, OpenAI Decisions, and Clairic APIs cannot be translated; {} does not speak {client}",
                hit.upstream_model
            );
        };
        let mut matches = self.providers.iter().filter(|(_, provider)| {
            hit.record.families.contains(&provider.kind.family())
                && provider.kind.dialects().contains(&target)
                && namespace
                    .is_none_or(|namespace| provider.namespace.as_deref() == Some(namespace))
        });
        let Some((name, _)) = matches.next() else {
            let where_ = namespace.map_or_else(
                || "configured providers".to_owned(),
                |namespace| format!("namespace {namespace}"),
            );
            bail!(
                "generation, embeddings, System One, OpenAI Decisions, and Clairic APIs cannot be translated; {where_} has no {client} provider for {}",
                hit.upstream_model
            );
        };
        if matches.next().is_some() {
            bail!("model {} is ambiguous for {client}", hit.upstream_model);
        }
        Ok(ModelSelection {
            provider: name.as_str(),
            upstream_model: hit.upstream_model,
            access_program: hit.inject_cyber,
            operations: hit.record.operations.to_vec(),
            operations_declared: true,
            modalities: hit.record.modalities.map(|items| items.to_vec()),
        })
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

fn inference_bind() -> SocketAddr {
    "127.0.0.1:8080".parse().unwrap()
}
fn control_bind() -> SocketAddr {
    "127.0.0.1:8081".parse().unwrap()
}
fn trace_dir() -> PathBuf {
    "./data".into()
}
fn max_request() -> usize {
    32 * 1024 * 1024
}
fn max_response() -> usize {
    32 * 1024 * 1024
}
fn connect_timeout() -> u64 {
    10
}
fn read_timeout() -> u64 {
    300
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(extra: &str) -> Config {
        let raw = format!(
            "proxy_token_env = \"INFER_PROXY_TOKEN\"\n\
             control_token_env = \"INFER_CONTROL_TOKEN\"\n\
             default_provider = \"local\"\n\
             [providers.local]\n\
             kind = \"llama\"\n\
             base_url = \"http://127.0.0.1:8082\"\n\
             [providers.openai]\n\
             kind = \"openai\"\n\
             base_url = \"https://api.openai.com\"\n\
             namespace = \"openai\"\n\
             [providers.decisions]\n\
             kind = \"openai_decisions\"\n\
             base_url = \"https://api.openai.com\"\n\
             namespace = \"openai\"\n\
             [providers.grok]\n\
             kind = \"grok\"\n\
             base_url = \"https://api.x.ai\"\n\
             namespace = \"xai\"\n\
             [models.local]\n\
             provider = \"local\"\n\
             model = \"llama-model\"\n\
             [models.\"xai/grok-4.7\"]\n\
             provider = \"local\"\n\
             model = \"pinned\"\n\
             {extra}"
        );
        let config: Config = toml::from_str(&raw).unwrap();
        config.validate().unwrap();
        config
    }

    #[test]
    fn model_resolution_prefers_alias_then_capability_namespace() {
        let config = parsed("");
        let alias = config
            .resolve_model("xai/grok-4.7", catalog::Dialect::Chat)
            .unwrap();
        assert_eq!(alias.provider, "local");
        assert_eq!(alias.upstream_model, "pinned");

        let grok = config
            .resolve_model("xai/grok-4", catalog::Dialect::Chat)
            .unwrap();
        assert_eq!(grok.provider, "grok");
        assert_eq!(grok.upstream_model, "grok-4");

        let chat = config
            .resolve_model("openai/gpt-6.1-sol", catalog::Dialect::Chat)
            .unwrap();
        assert_eq!(chat.provider, "openai");
        assert_eq!(chat.upstream_model, "gpt-6.1-sol");
        let decisions = config
            .resolve_model("openai/gpt-6-luna", catalog::Dialect::Decisions)
            .unwrap();
        assert_eq!(decisions.provider, "decisions");
        assert_eq!(decisions.upstream_model, "gpt-6-luna");
        let denied = config
            .resolve_model("openai/gpt-6.1-sol", catalog::Dialect::Decisions)
            .unwrap_err()
            .to_string();
        assert!(denied.contains("does not speak decisions"), "{denied}");

        let local = config
            .resolve_model("meta-llama/Llama-3.1-8B", catalog::Dialect::Chat)
            .unwrap();
        assert_eq!(local.provider, "local");
        assert_eq!(local.upstream_model, "meta-llama/Llama-3.1-8B");
        let bare = config
            .resolve_model("grok-4", catalog::Dialect::Chat)
            .unwrap();
        assert_eq!(bare.provider, "local");
        assert_eq!(bare.upstream_model, "grok-4");

        let wrong = config
            .resolve_model("xai/grok-4", catalog::Dialect::Decisions)
            .unwrap_err()
            .to_string();
        assert!(wrong.contains("no decisions provider"), "{wrong}");
        let empty = config
            .resolve_model("xai/", catalog::Dialect::Chat)
            .unwrap_err()
            .to_string();
        assert!(empty.contains("missing an upstream model"), "{empty}");
    }

    #[test]
    fn cataloged_model_selects_the_family_that_speaks_its_dialect() {
        let config = parsed("");
        let decisions = config
            .resolve_model("gpt-6-luna-2026-10-01", catalog::Dialect::Decisions)
            .unwrap();
        assert_eq!(decisions.provider, "decisions");
        assert_eq!(decisions.upstream_model, "gpt-6-luna-2026-10-01");
        let responses = config
            .resolve_model("gpt-6-luna", catalog::Dialect::Chat)
            .unwrap();
        assert_eq!(responses.provider, "openai");
        let system_one = config
            .resolve_model("gpt-6-luna", catalog::Dialect::SystemOne)
            .unwrap();
        assert_eq!(system_one.provider, "decisions");
        assert_eq!(system_one.upstream_model, "gpt-6-luna");
    }

    #[test]
    fn duplicate_namespace_for_one_capability_is_rejected() {
        let raw = "\
proxy_token_env = \"INFER_PROXY_TOKEN\"
control_token_env = \"INFER_CONTROL_TOKEN\"
default_provider = \"a\"
[providers.a]
kind = \"openai\"
base_url = \"https://api.openai.com\"
namespace = \"openai\"
[providers.b]
kind = \"grok\"
base_url = \"https://api.x.ai\"
namespace = \"openai\"
";
        let config: Config = toml::from_str(raw).unwrap();
        let error = config.validate().unwrap_err().to_string();
        assert!(error.contains("claimed by both"), "{error}");
    }
}
