//! Decisions and System One. Each direction rejects fields it cannot represent.
//! Decisions to System One lets a Decisions client use a System One model.
//! System One to Decisions lets a System One client use an OpenAI Decisions model.

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

#[derive(Clone, Debug)]
pub struct DecisionPlan {
    questions: Vec<Question>,
}

#[derive(Clone, Debug)]
struct Question {
    name: Option<String>,
    key: String,
    kind: QuestionKind,
}

#[derive(Clone, Debug)]
enum QuestionKind {
    Predicate,
    Choice(Vec<(String, Value)>),
    Score(Vec<ScoreLevel>),
}

#[derive(Clone, Debug)]
struct ScoreLevel {
    label: String,
    value: u64,
}

pub fn request(body: &Value) -> Result<(Value, DecisionPlan)> {
    let object = body
        .as_object()
        .context_msg("Decisions request must be an object")?;
    for key in object.keys() {
        if !matches!(key.as_str(), "model" | "input" | "questions" | "stream") {
            bail!("Decisions field {key} cannot be represented by System One");
        }
    }
    if object
        .get("stream")
        .is_some_and(|value| value != &Value::Bool(false))
    {
        bail!("Decisions streaming cannot be represented by System One");
    }
    let state = state_from_input(
        object
            .get("input")
            .context_msg("Decisions request missing input")?,
    )?;
    let questions = object
        .get("questions")
        .and_then(Value::as_array)
        .context_msg("Decisions questions must be an array")?;
    if questions.is_empty() {
        bail!("Decisions questions must not be empty");
    }
    let mut plan = Vec::new();
    let mut named = Map::new();
    for (index, question) in questions.iter().enumerate() {
        let question = question
            .as_object()
            .context_msg("Decisions question must be an object")?;
        let kind = question
            .get("type")
            .and_then(Value::as_str)
            .context_msg("Decisions question missing type")?;
        let name = match question.get("name") {
            None | Some(Value::Null) => None,
            Some(Value::String(name)) if !name.is_empty() => Some(name.clone()),
            _ => bail!("Decisions question name must be a non-empty string"),
        };
        let key = name.clone().unwrap_or_else(|| format!("q{index}"));
        if named.contains_key(&key) {
            bail!("Decisions question name {key} is duplicated");
        }
        let instructions = question
            .get("instructions")
            .and_then(Value::as_str)
            .context_msg("Decisions question instructions must be a string")?;
        let allowed = match kind {
            "predicate" => &["type", "name", "instructions"][..],
            "choice" => &["type", "name", "instructions", "choices"][..],
            "score" => &["type", "name", "instructions", "levels"][..],
            _ => &[][..],
        };
        if !allowed.is_empty() {
            for key in question.keys() {
                if !allowed.contains(&key.as_str()) {
                    bail!("Decisions question field {key} cannot be represented by System One");
                }
            }
        }
        let (system, mapped) = match kind {
            "predicate" => (
                json!({"type":"noul","instructions":instructions}),
                QuestionKind::Predicate,
            ),
            "choice" => {
                let choices = question
                    .get("choices")
                    .and_then(Value::as_array)
                    .context_msg("Decisions choice question missing choices")?;
                if choices.is_empty() {
                    bail!("Decisions choice question has no choices");
                }
                let mut criteria = Map::new();
                let mut values = Vec::new();
                for choice in choices {
                    let choice = choice
                        .as_object()
                        .context_msg("Decisions choice must be an object")?;
                    for key in choice.keys() {
                        if !matches!(key.as_str(), "value" | "description") {
                            bail!(
                                "Decisions choice field {key} cannot be represented by System One"
                            );
                        }
                    }
                    let value = choice
                        .get("value")
                        .context_msg("Decisions choice missing value")?;
                    let key = serde_json::to_string(value)?;
                    if values.iter().any(|(existing, _)| existing == &key) {
                        bail!("Decisions choice value {key} is duplicated");
                    }
                    let description = choice
                        .get("description")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .map(str::to_owned)
                        .unwrap_or_else(|| key.clone());
                    criteria.insert(key.clone(), Value::String(description));
                    values.push((key, value.clone()));
                }
                (
                    json!({"type":"choice","instructions":instructions,"criteria":criteria}),
                    QuestionKind::Choice(values),
                )
            }
            "score" => {
                let levels = question
                    .get("levels")
                    .and_then(Value::as_array)
                    .context_msg("Decisions score question missing levels")?;
                if levels.is_empty() {
                    bail!("Decisions score question has no levels");
                }
                let mut criteria = Vec::new();
                let mut mapped = Vec::new();
                for (value, level) in levels.iter().enumerate() {
                    let level = level
                        .as_object()
                        .context_msg("Decisions score level must be an object")?;
                    for key in level.keys() {
                        if !matches!(key.as_str(), "label" | "description") {
                            bail!(
                                "Decisions score level field {key} cannot be represented by System One"
                            );
                        }
                    }
                    let label = level
                        .get("label")
                        .and_then(Value::as_str)
                        .context_msg("Decisions score level missing label")?
                        .to_owned();
                    let text = level
                        .get("description")
                        .and_then(Value::as_str)
                        .filter(|text| !text.is_empty())
                        .unwrap_or(label.as_str());
                    criteria.push(Value::String(text.to_owned()));
                    mapped.push(ScoreLevel {
                        label,
                        value: u64::try_from(value)?,
                    });
                }
                (
                    json!({"type":"score","instructions":instructions,"criteria":criteria}),
                    QuestionKind::Score(mapped),
                )
            }
            other => bail!("Decisions question type {other} cannot be represented by System One"),
        };
        named.insert(key.clone(), system);
        plan.push(Question {
            name,
            key,
            kind: mapped,
        });
    }
    let mut out = Map::new();
    if let Some(model) = object.get("model") {
        out.insert("model".into(), model.clone());
    }
    out.insert("state".into(), state);
    out.insert("questions".into(), Value::Object(named));
    Ok((Value::Object(out), DecisionPlan { questions: plan }))
}

pub fn response(body: Value, plan: &DecisionPlan) -> Result<Value> {
    let object = body
        .as_object()
        .context_msg("System One response must be an object")?;
    let answers = object
        .get("answers")
        .and_then(Value::as_object)
        .context_msg("System One response missing answers")?;
    let mut translated = Vec::new();
    for question in &plan.questions {
        let answer = answers
            .get(&question.key)
            .and_then(Value::as_object)
            .with_context(|| format!("System One answer {} is missing", question.key))?;
        let mut out = Map::new();
        out.insert(
            "name".into(),
            question.name.clone().map_or(Value::Null, Value::String),
        );
        match &question.kind {
            QuestionKind::Predicate => {
                let probability = answer
                    .get("noul")
                    .and_then(Value::as_f64)
                    .context_msg("System One noul answer missing noul")?;
                out.insert("type".into(), Value::String("predicate".into()));
                out.insert("probability".into(), json!(probability));
            }
            QuestionKind::Choice(values) => {
                let choice = answer
                    .get("choice")
                    .and_then(Value::as_str)
                    .context_msg("System One choice answer missing choice")?;
                let value = values
                    .iter()
                    .find(|(key, _)| key == choice)
                    .with_context(|| format!("System One choice {choice} was not requested"))?
                    .1
                    .clone();
                out.insert("type".into(), Value::String("choice".into()));
                out.insert("choice".into(), value);
                if let Some(confidence) = answer.get("confidence") {
                    out.insert("confidence".into(), confidence.clone());
                }
                if let Some(probabilities) = answer.get("probabilities").and_then(Value::as_object)
                {
                    let mut items = Vec::new();
                    for (key, value) in values {
                        if let Some(probability) = probabilities.get(key) {
                            items.push(json!({"value":value,"probability":probability}));
                        }
                    }
                    out.insert("probabilities".into(), Value::Array(items));
                }
            }
            QuestionKind::Score(levels) => {
                let score = answer
                    .get("score")
                    .context_msg("System One score answer missing score")?;
                out.insert("type".into(), Value::String("score".into()));
                out.insert("score".into(), score.clone());
                if let Some(confidence) = answer.get("confidence") {
                    out.insert("confidence".into(), confidence.clone());
                }
                if let Some(probabilities) = answer.get("probabilities").and_then(Value::as_object)
                {
                    let mut items = Vec::new();
                    for (key, probability) in probabilities {
                        let index: usize = key.parse().with_context(|| {
                            format!("System One score probability {key} is not an index")
                        })?;
                        let level = levels.get(index).with_context(|| {
                            format!("System One score probability {key} was not requested")
                        })?;
                        items.push(json!({
                            "label": level.label,
                            "value": level.value,
                            "probability": probability
                        }));
                    }
                    out.insert("probabilities".into(), Value::Array(items));
                }
            }
        }
        translated.push(Value::Object(out));
    }
    let mut out = Map::new();
    if let Some(model) = object.get("model") {
        out.insert("model".into(), model.clone());
    }
    out.insert("answers".into(), Value::Array(translated));
    if let Some(usage) = object.get("usage") {
        out.insert("usage".into(), usage.clone());
    }
    Ok(Value::Object(out))
}

#[derive(Clone, Debug)]
pub struct SystemOnePlan {
    questions: Vec<ReverseQuestion>,
}

#[derive(Clone, Debug)]
struct ReverseQuestion {
    key: String,
    kind: ReverseKind,
}

#[derive(Clone, Debug)]
enum ReverseKind {
    Noul,
    Choice(Vec<String>),
    Score,
}

pub fn from_system_one(body: &Value) -> Result<(Value, SystemOnePlan)> {
    let object = body
        .as_object()
        .context_msg("System One request must be an object")?;
    for key in object.keys() {
        if !matches!(key.as_str(), "model" | "state" | "questions") {
            bail!("System One field {key} cannot be represented by Decisions");
        }
    }
    let state = object
        .get("state")
        .and_then(Value::as_str)
        .context_msg("System One state must be a string to translate to Decisions")?;
    let questions = object
        .get("questions")
        .and_then(Value::as_object)
        .context_msg("System One questions must be an object")?;
    if questions.is_empty() {
        bail!("System One questions must not be empty");
    }
    let mut plan = Vec::new();
    let mut encoded = Vec::new();
    for (key, question) in questions {
        let question = question
            .as_object()
            .context_msg("System One question must be an object")?;
        let kind = question
            .get("type")
            .and_then(Value::as_str)
            .context_msg("System One question missing type")?;
        let instructions = question
            .get("instructions")
            .and_then(Value::as_str)
            .context_msg("System One instructions must be a string")?;
        let (mapped, item) = match kind {
            "noul" => {
                if question.contains_key("criteria") {
                    bail!("System One noul question cannot include criteria");
                }
                (
                    ReverseKind::Noul,
                    json!({"type":"predicate","name":key,"instructions":instructions}),
                )
            }
            "choice" => {
                let criteria = question
                    .get("criteria")
                    .and_then(Value::as_object)
                    .context_msg("System One choice question missing criteria")?;
                if criteria.is_empty() {
                    bail!("System One choice question has no criteria");
                }
                let mut keys = Vec::new();
                let mut choices = Vec::new();
                for (name, description) in criteria {
                    let description = description
                        .as_str()
                        .context_msg("System One choice criteria must be strings")?;
                    keys.push(name.clone());
                    choices.push(json!({"value":name,"description":description}));
                }
                (
                    ReverseKind::Choice(keys),
                    json!({"type":"choice","name":key,"instructions":instructions,"choices":choices}),
                )
            }
            "score" => {
                let criteria = question
                    .get("criteria")
                    .and_then(Value::as_array)
                    .context_msg("System One score question missing criteria")?;
                if criteria.is_empty() {
                    bail!("System One score question has no criteria");
                }
                let mut levels = Vec::new();
                for label in criteria {
                    let label = label
                        .as_str()
                        .context_msg("System One score criteria must be strings")?;
                    levels.push(json!({"label":label}));
                }
                (
                    ReverseKind::Score,
                    json!({"type":"score","name":key,"instructions":instructions,"levels":levels}),
                )
            }
            "box" => bail!("System One Box questions cannot be represented by Decisions"),
            other => bail!("System One question type {other} cannot be represented by Decisions"),
        };
        for extra in question.keys() {
            if !matches!(extra.as_str(), "type" | "instructions" | "criteria") {
                bail!("System One question field {extra} cannot be represented by Decisions");
            }
        }
        plan.push(ReverseQuestion {
            key: key.clone(),
            kind: mapped,
        });
        encoded.push(item);
    }
    let mut out = Map::new();
    if let Some(model) = object.get("model") {
        out.insert("model".into(), model.clone());
    }
    out.insert("input".into(), Value::String(state.to_owned()));
    out.insert("questions".into(), Value::Array(encoded));
    Ok((Value::Object(out), SystemOnePlan { questions: plan }))
}

pub fn to_system_one(body: Value, plan: &SystemOnePlan) -> Result<Value> {
    let object = body
        .as_object()
        .context_msg("Decisions response must be an object")?;
    let answers = object
        .get("answers")
        .and_then(Value::as_array)
        .context_msg("Decisions response missing answers")?;
    let mut named = Map::new();
    for question in &plan.questions {
        let answer = answers
            .iter()
            .find(|answer| {
                answer.get("name").and_then(Value::as_str) == Some(question.key.as_str())
            })
            .and_then(Value::as_object)
            .with_context(|| format!("Decisions answer {} is missing", question.key))?;
        let mut out = Map::new();
        match &question.kind {
            ReverseKind::Noul => {
                let probability = answer
                    .get("probability")
                    .and_then(Value::as_f64)
                    .context_msg("Decisions predicate answer missing probability")?;
                out.insert("type".into(), Value::String("noul".into()));
                out.insert("noul".into(), json!(probability));
            }
            ReverseKind::Choice(keys) => {
                let choice = answer
                    .get("choice")
                    .and_then(Value::as_str)
                    .context_msg("Decisions choice answer missing choice")?;
                if !keys.iter().any(|key| key == choice) {
                    bail!("Decisions choice {choice} was not requested");
                }
                out.insert("type".into(), Value::String("choice".into()));
                out.insert("choice".into(), Value::String(choice.to_owned()));
                if let Some(confidence) = answer.get("confidence") {
                    out.insert("confidence".into(), confidence.clone());
                }
            }
            ReverseKind::Score => {
                let score = answer
                    .get("score")
                    .context_msg("Decisions score answer missing score")?;
                out.insert("type".into(), Value::String("score".into()));
                out.insert("score".into(), score.clone());
                if let Some(confidence) = answer.get("confidence") {
                    out.insert("confidence".into(), confidence.clone());
                }
            }
        }
        named.insert(question.key.clone(), Value::Object(out));
    }
    let mut out = Map::new();
    if let Some(model) = object.get("model") {
        out.insert("model".into(), model.clone());
    }
    out.insert("answers".into(), Value::Object(named));
    if let Some(usage) = object.get("usage") {
        out.insert("usage".into(), usage.clone());
    }
    Ok(Value::Object(out))
}

fn state_from_input(input: &Value) -> Result<Value> {
    match input {
        Value::String(text) => Ok(Value::String(text.clone())),
        Value::Array(items) => {
            let mut lines = Vec::new();
            for item in items {
                lines.push(message_line(item)?);
            }
            Ok(Value::String(lines.join("\n")))
        }
        _ => bail!("Decisions input must be a string or array to translate to System One"),
    }
}

fn message_line(item: &Value) -> Result<String> {
    if let Some(text) = item.as_str() {
        return Ok(text.to_owned());
    }
    let object = item
        .as_object()
        .context_msg("Decisions input item must be a string or message")?;
    let role = object
        .get("role")
        .and_then(Value::as_str)
        .context_msg("Decisions input message missing role")?;
    let content = object
        .get("content")
        .context_msg("Decisions input message missing content")?;
    Ok(format!("{role}: {}", message_text(content)?))
}

fn message_text(content: &Value) -> Result<String> {
    if let Some(text) = content.as_str() {
        return Ok(text.to_owned());
    }
    let parts = content
        .as_array()
        .context_msg("Decisions message content must be a string or array")?;
    let mut text = Vec::new();
    for part in parts {
        let part = part
            .as_object()
            .context_msg("Decisions content part must be an object")?;
        let kind = part
            .get("type")
            .and_then(Value::as_str)
            .context_msg("Decisions content part missing type")?;
        if !matches!(kind, "input_text" | "text") {
            bail!("Decisions content part {kind} cannot be represented by System One");
        }
        text.push(
            part.get("text")
                .and_then(Value::as_str)
                .context_msg("Decisions text part missing text")?
                .to_owned(),
        );
    }
    Ok(text.join("\n"))
}

trait ContextMsg<T> {
    fn context_msg(self, message: &'static str) -> Result<T>;
}

impl<T> ContextMsg<T> for Option<T> {
    fn context_msg(self, message: &'static str) -> Result<T> {
        self.ok_or_else(|| anyhow::anyhow!(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions_round_trip_preserves_choice_identity_and_score_labels() {
        let input = json!({
            "model":"kev",
            "input":[{"role":"user","content":[{"type":"input_text","text":"Inspect"}]}],
            "questions":[
                {"type":"predicate","instructions":"Is it damaged?"},
                {"type":"choice","name":"typed","instructions":"Choose","choices":[{"value":true},{"value":"true","description":"text"}]},
                {"type":"score","name":"priority","instructions":"Rate","levels":[{"label":"low","description":"wait"},{"label":"high"}]}
            ]
        });
        let (request, plan) = request(&input).unwrap();
        assert_eq!(request["state"], "user: Inspect");
        assert_eq!(request["questions"]["q0"]["type"], "noul");
        assert_eq!(request["questions"]["typed"]["criteria"]["true"], "true");
        assert_eq!(
            request["questions"]["typed"]["criteria"]["\"true\""],
            "text"
        );
        assert_eq!(
            request["questions"]["priority"]["criteria"],
            json!(["wait", "high"])
        );

        let upstream = json!({
            "model":"kev-local",
            "answers":{
                "q0":{"type":"noul","noul":0.9},
                "typed":{"type":"choice","choice":"\"true\"","confidence":0.2,"probabilities":{"true":0.4,"\"true\"":0.6}},
                "priority":{"type":"score","score":1.2,"confidence":0.5,"probabilities":{"0":0.2,"1":0.8}}
            },
            "usage":{"input_tokens":8,"output_tokens":0}
        });
        let translated = response(upstream, &plan).unwrap();
        assert_eq!(translated["model"], "kev-local");
        assert_eq!(translated["answers"][0]["probability"], 0.9);
        assert_eq!(translated["answers"][0]["name"], Value::Null);
        assert_eq!(translated["answers"][1]["choice"], "true");
        assert_eq!(translated["answers"][1]["probabilities"][0]["value"], true);
        assert_eq!(
            translated["answers"][2]["probabilities"][1]["label"],
            "high"
        );
        assert_eq!(translated["answers"][2]["probabilities"][1]["value"], 1);
    }

    #[test]
    fn decisions_question_constraints_are_not_silently_dropped() {
        let input = json!({
            "model":"kev",
            "input":"Inspect",
            "questions":[{"type":"predicate","instructions":"Is it damaged?","required":true}]
        });
        let error = request(&input).unwrap_err().to_string();
        assert!(error.contains("required"), "{error}");
    }

    #[test]
    fn decisions_translation_rejects_unrepresentable_fields() {
        let image = json!({
            "model":"kev",
            "input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.test/a.png"}]}],
            "questions":[{"type":"predicate","instructions":"Shown?"}]
        });
        assert!(request(&image).is_err());
        let extra = json!({
            "model":"kev",
            "input":"text",
            "questions":[{"type":"predicate","instructions":"Yes?"}],
            "safety_identifier":"user"
        });
        assert!(request(&extra).is_err());
    }

    #[test]
    fn system_one_round_trip_maps_named_answers_back() {
        let input = json!({
            "model":"gpt-6-luna",
            "state":"Inspect this item",
            "questions":{
                "damaged":{"type":"noul","instructions":"Is it damaged?"},
                "route":{"type":"choice","instructions":"Choose","criteria":{"hold":"Wait","ship":"Send"}}
            }
        });
        let (request, plan) = from_system_one(&input).unwrap();
        assert_eq!(request["input"], "Inspect this item");
        assert_eq!(
            request["questions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|question| question["name"] == "route")
                .unwrap()["type"],
            "choice"
        );
        assert_eq!(
            request["questions"]
                .as_array()
                .unwrap()
                .iter()
                .find(|question| question["name"] == "damaged")
                .unwrap()["type"],
            "predicate"
        );
        let upstream = json!({
            "model":"gpt-6-luna",
            "answers":[
                {"name":"damaged","type":"predicate","probability":0.2},
                {"name":"route","type":"choice","choice":"ship","confidence":0.8}
            ],
            "usage":{"input_tokens":4,"output_tokens":1}
        });
        let translated = to_system_one(upstream, &plan).unwrap();
        assert_eq!(translated["answers"]["damaged"]["noul"], 0.2);
        assert_eq!(translated["answers"]["route"]["choice"], "ship");
        assert!(from_system_one(&json!({"model":"x","state":{"a":1},"questions":{"q":{"type":"noul","instructions":"?"}}})).is_err());
    }
}
