use super::{Protocol, Usage, arguments, stop, validate_reasoning};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use serde_json::{Value, json};
use std::collections::BTreeMap;

// Bound unfinished frames, retained tool headers, tool validation data, and later
// content blocked behind the active Anthropic block. Active text is not accumulated.
const MAX_PENDING: usize = 8 * 1024 * 1024;
const MAX_BLOCKS: usize = 4096;

#[derive(Default)]
struct Sse {
    line: Vec<u8>,
    data: Vec<u8>,
    event: String,
    size: usize,
    after_cr: bool,
    line_read: bool,
}
#[derive(Debug)]
struct Frame {
    event: String,
    data: Vec<u8>,
}
impl Sse {
    fn byte(&mut self, byte: u8) -> Result<Option<Frame>> {
        if self.after_cr {
            self.after_cr = false;
            if byte == b'\n' {
                return Ok(None);
            }
        }
        self.size += 1;
        if self.size > MAX_PENDING {
            bail!("upstream SSE frame exceeds 8 MiB; refusing unbounded pending frame growth");
        }
        if byte == b'\r' || byte == b'\n' {
            self.after_cr = byte == b'\r';
            let line = std::mem::take(&mut self.line);
            let line = std::str::from_utf8(&line).context("upstream SSE line is not UTF-8")?;
            // Decode first, so a BOM split between network chunks is still one prefix.
            let line = if std::mem::replace(&mut self.line_read, true) {
                line
            } else {
                line.strip_prefix('\u{feff}').unwrap_or(line)
            };
            if line.is_empty() {
                self.size = 0;
                let data = std::mem::take(&mut self.data);
                let event = std::mem::take(&mut self.event);
                return Ok(if data.is_empty() {
                    None
                } else {
                    Some(Frame { event, data })
                });
            }
            if !line.starts_with(':') {
                let (field, value) = line.split_once(':').unwrap_or((line, ""));
                let value = value.strip_prefix(' ').unwrap_or(value);
                match field {
                    "data" => {
                        if !self.data.is_empty() {
                            self.data.push(b'\n');
                        }
                        self.data.extend_from_slice(value.as_bytes());
                    }
                    "event" => {
                        self.event.clear();
                        self.event.push_str(value);
                    }
                    "id" | "retry" => {}
                    _ => {} // Unknown SSE fields are ignored by the SSE specification.
                }
            }
        } else {
            self.line.push(byte);
        }
        Ok(None)
    }
    fn pending(&self) -> bool {
        !self.line.is_empty() || !self.data.is_empty() || !self.event.is_empty()
    }
}

fn validate_responses_terminal(response: &Value, kind: &str) -> Result<()> {
    if response.get("error").is_some_and(|error| !error.is_null()) {
        bail!(
            "Responses terminal response contains an error: {}",
            response["error"]
        );
    }
    let status = response["status"]
        .as_str()
        .context("terminal Responses response missing status")?;
    let expected = match kind {
        "response.completed" => "completed",
        "response.incomplete" => "incomplete",
        _ => bail!("invalid terminal Responses event {kind}"),
    };
    if status != expected {
        bail!("Responses terminal event {kind} disagrees with response status {status}");
    }
    Ok(())
}

fn responses_part_content(part: &Value) -> Result<(&str, bool)> {
    let kind = part
        .get("type")
        .and_then(Value::as_str)
        .context("Responses content part missing type")?;
    match kind {
        "output_text" => Ok((
            part.get("text")
                .and_then(Value::as_str)
                .context("Responses output_text missing text")?,
            false,
        )),
        "refusal" => Ok((
            part.get("refusal")
                .and_then(Value::as_str)
                .context("Responses refusal missing text")?,
            true,
        )),
        _ => bail!("unsupported Responses message content part {kind}"),
    }
}

fn validate_responses_part_metadata(part: &Value) -> Result<()> {
    if part
        .get("annotations")
        .is_some_and(|value| value.as_array().is_none_or(|items| !items.is_empty()))
    {
        bail!("Responses annotations require native protocol");
    }
    if part.get("logprobs").is_some_and(|value| {
        !value.is_null() && value.as_array().is_none_or(|items| !items.is_empty())
    }) {
        bail!("Responses logprobs require native protocol");
    }
    Ok(())
}

pub(crate) fn collect_response_sse(bytes: &[u8], to: Protocol) -> Result<Value> {
    let mut parser = Sse::default();
    let mut completed = None;
    for &byte in bytes {
        let Some(frame) = parser.byte(byte)? else {
            continue;
        };
        if frame.data == b"[DONE]" {
            if completed.is_none() {
                bail!("Responses stream ended before a terminal response");
            }
            continue;
        }
        let event = crate::json::from_slice(&frame.data).context("invalid Responses SSE JSON")?;
        let kind = event["type"].as_str().unwrap_or(&frame.event);
        if !frame.event.is_empty() && kind != frame.event {
            bail!("Responses SSE event name disagrees with payload type");
        }
        if completed.is_some() {
            bail!("Responses stream emitted data after its terminal response");
        }
        if matches!(kind, "error" | "response.failed")
            || event.get("error").is_some_and(|v| !v.is_null())
        {
            bail!("Responses upstream reported a semantic stream failure");
        }
        if to != Protocol::Responses
            && matches!(
                kind,
                "response.output_item.added" | "response.output_item.done"
            )
            && event["item"]["type"] == "message"
        {
            super::validate_phase(&event["item"])?;
        }
        if matches!(kind, "response.completed" | "response.incomplete") {
            let response = event
                .get("response")
                .filter(|v| v.is_object())
                .context("terminal Responses event is missing its response object")?;
            validate_responses_terminal(response, kind)?;
            if to != Protocol::Responses
                && let Some(output) = response["output"].as_array()
            {
                for item in output {
                    if item["type"] == "message" {
                        super::validate_phase(item)?;
                    }
                }
            }
            completed = Some(response.clone());
        }
    }
    if parser.pending() {
        bail!("truncated Responses SSE frame at EOF");
    }
    completed.context("SSE ended without a terminal Responses object")
}

#[derive(Debug)]
struct Block {
    index: usize,
    position: usize,
    tool_index: Option<usize>,
    id: String,
    name: String,
    args: String,
    pending_text: String,
    sent_args: usize,
    ready: bool,
    emitted: bool,
    closed: bool,
    output_closed: bool,
    text: bool,
    refusal: bool,
    saw_delta: bool,
    bytes: usize,
    digest: u64,
}

/// Incremental native SSE converter. `push` accepts arbitrary byte boundaries,
/// including splits inside UTF-8, JSON, CRLF and tool argument deltas. Call
/// `finish` on EOF: missing protocol terminal markers and unfinished frames fail.
/// Cross-protocol streaming targets are Anthropic and Chat; Responses streaming
/// output requires a Responses backend (complete Responses conversion is supported).
pub struct StreamTranslator {
    from: Protocol,
    to: Protocol,
    model: String,
    id: String,
    parser: Sse,
    blocks: BTreeMap<String, Block>,
    order: Vec<String>,
    output_cursor: usize,
    output_index: usize,
    response_order: BTreeMap<(u64, u64), String>,
    response_done: BTreeMap<u64, bool>,
    response_cursor: (u64, u64),
    chat_tool_order: BTreeMap<u64, usize>,
    chat_tool_cursor: u64,
    next_tool: usize,
    pending_args: usize,
    pending_text: usize,
    retained_headers: usize,
    started: bool,
    terminal: bool,
    failed: bool,
    upstream_failed: bool,
    source_started: bool,
    source_finished: bool,
    finish_reason: Option<String>,
    include_usage: bool,
    usage: Usage,
}
impl StreamTranslator {
    pub fn new(from: Protocol, to: Protocol, model: String, include_usage: bool) -> Self {
        Self {
            from,
            to,
            model,
            id: format!("msg_{}", uuid::Uuid::new_v4().simple()),
            parser: Sse::default(),
            blocks: BTreeMap::new(),
            order: Vec::new(),
            output_cursor: 0,
            output_index: 0,
            response_order: BTreeMap::new(),
            response_done: BTreeMap::new(),
            response_cursor: (0, 0),
            chat_tool_order: BTreeMap::new(),
            chat_tool_cursor: 0,
            next_tool: 0,
            pending_args: 0,
            pending_text: 0,
            retained_headers: 0,
            started: false,
            terminal: false,
            failed: false,
            upstream_failed: false,
            source_started: false,
            source_finished: false,
            finish_reason: None,
            include_usage,
            usage: Usage::default(),
        }
    }
    /// Distinguishes a cleanly framed provider error from a successful generation.
    pub fn upstream_failed(&self) -> bool {
        self.upstream_failed
    }

    pub fn push(&mut self, chunk: &[u8]) -> Result<Vec<Bytes>> {
        if self.from == self.to {
            return Ok(if chunk.is_empty() {
                Vec::new()
            } else {
                vec![Bytes::copy_from_slice(chunk)]
            });
        }
        if self.to == Protocol::Responses {
            bail!(
                "cross-protocol streaming to Responses is not supported; use native Responses or stream=false"
            );
        }
        if self.failed {
            bail!("stream translator cannot continue after a previous protocol error");
        }
        let mut output = Vec::new();
        for &byte in chunk {
            let frame = match self.parser.byte(byte) {
                Ok(frame) => frame,
                Err(e) => {
                    self.failed = true;
                    return Err(e);
                }
            };
            if let Some(frame) = frame
                && let Err(e) = self.frame(frame, &mut output)
            {
                self.failed = true;
                return Err(e);
            }
        }
        Ok(output)
    }
    pub fn finish(&mut self) -> Result<Vec<Bytes>> {
        if self.from == self.to {
            return Ok(Vec::new());
        }
        if self.failed {
            bail!("translated stream failed before EOF");
        }
        if self.parser.pending() {
            self.failed = true;
            bail!("truncated upstream SSE frame at EOF (missing blank-line terminator)");
        }
        if !self.terminal {
            self.failed = true;
            bail!(
                "truncated upstream {:?} stream: missing {}",
                self.from,
                match self.from {
                    Protocol::Chat => "[DONE]",
                    Protocol::Anthropic => "message_stop",
                    Protocol::Responses => "response.completed/response.incomplete",
                }
            );
        }
        Ok(Vec::new())
    }
    fn frame(&mut self, frame: Frame, output: &mut Vec<Bytes>) -> Result<()> {
        if frame.data == b"[DONE]" {
            if self.from != Protocol::Chat {
                if self.terminal {
                    return Ok(());
                }
                bail!("unexpected [DONE] without a native terminal event");
            }
            if self.terminal {
                return Ok(());
            }
            if self.finish_reason.is_none() {
                bail!("Chat [DONE] arrived before finish_reason");
            }
            let reason = self.finish_reason.clone().unwrap();
            return self.complete(&reason, Protocol::Chat, output);
        }
        let value =
            crate::json::from_slice(&frame.data).context("upstream SSE data is invalid JSON")?;
        if value.get("error").is_some_and(|v| !v.is_null())
            || frame.event == "error"
            || value["type"] == "error"
            || value["type"] == "response.failed"
        {
            if self.terminal {
                bail!("upstream emitted an error after terminal event");
            }
            let error = value
                .get("error")
                .cloned()
                .or_else(|| value.pointer("/response/error").cloned())
                .unwrap_or_else(
                    || json!({"type":"upstream_error","message":"upstream stream failed"}),
                );
            if self.to == Protocol::Anthropic {
                emit(
                    output,
                    Some("error"),
                    json!({"type":"error","error":{"type":"api_error","message":error.get("message").and_then(Value::as_str).unwrap_or("upstream stream failed"),"upstream_error":error}}),
                );
            } else {
                emit(output, None, json!({"error":error}));
                output.push(Bytes::from_static(b"data: [DONE]\n\n"));
            }
            self.terminal = true;
            self.upstream_failed = true;
            return Ok(());
        }
        if self.terminal {
            bail!("upstream emitted semantic data after terminal event");
        }
        match self.from {
            Protocol::Responses => self.responses(value, &frame.event, output),
            Protocol::Chat => self.chat(value, output),
            Protocol::Anthropic => self.anthropic(value, &frame.event, output),
        }
    }
    fn start(&mut self, output: &mut Vec<Bytes>) {
        if self.started {
            return;
        }
        self.started = true;
        if self.to == Protocol::Anthropic {
            emit(
                output,
                Some("message_start"),
                json!({"type":"message_start","message":{"id":self.id,"type":"message","role":"assistant","model":self.model,"content":[],"stop_reason":null,"stop_sequence":null,"usage":self.usage.json(self.to)}}),
            );
        } else {
            self.chat_chunk(
                json!({"role":"assistant","content":""}),
                Value::Null,
                output,
            );
        }
    }
    fn chat_chunk(&self, delta: Value, finish: Value, output: &mut Vec<Bytes>) {
        emit(
            output,
            None,
            json!({"id":self.id,"object":"chat.completion.chunk","created":0,"model":self.model,"choices":[{"index":0,"delta":delta,"finish_reason":finish,"logprobs":null}]}),
        );
    }
    fn new_block(&mut self, key: &str, text: bool) -> Result<()> {
        if self.blocks.contains_key(key) {
            return Ok(());
        }
        if self.blocks.len() >= MAX_BLOCKS {
            bail!("upstream exceeded 4096 content blocks in one response");
        }
        let tool_index = if text || self.from == Protocol::Responses {
            None
        } else {
            let n = self.next_tool;
            self.next_tool += 1;
            Some(n)
        };
        self.blocks.insert(
            key.into(),
            Block {
                index: 0,
                position: self.order.len(),
                tool_index,
                id: String::new(),
                name: String::new(),
                args: String::new(),
                pending_text: String::new(),
                sent_args: 0,
                ready: false,
                emitted: false,
                closed: false,
                output_closed: false,
                text,
                refusal: false,
                saw_delta: false,
                bytes: 0,
                digest: 0xcbf29ce484222325,
            },
        );
        self.order.push(key.into());
        Ok(())
    }
    fn response_item(&mut self, index: u64) -> Result<()> {
        if !self.response_done.contains_key(&index) {
            if self.response_done.len() >= MAX_BLOCKS {
                bail!("upstream exceeded 4096 Responses output items");
            }
            self.response_done.insert(index, false);
        }
        Ok(())
    }
    fn response_block(&mut self, index: u64, part: u64, key: &str) -> Result<()> {
        self.response_item(index)?;
        if !self.response_order.contains_key(&(index, part)) {
            if self.response_order.len() >= MAX_BLOCKS {
                bail!("upstream exceeded 4096 content blocks in one response");
            }
            self.response_order.insert((index, part), key.into());
        }
        Ok(())
    }
    fn response_item_done(&mut self, index: u64, output: &mut Vec<Bytes>) -> Result<()> {
        self.response_item(index)?;
        self.response_done.insert(index, true);
        self.drain_ordered(output)
    }
    fn chat_tool(&mut self, index: u64, key: &str) -> Result<()> {
        if let Some(&position) = self.chat_tool_order.get(&index) {
            if self.order[position] != key {
                bail!("Chat tool index {index} changed identity");
            }
            return Ok(());
        }
        if self.chat_tool_order.len() >= MAX_BLOCKS {
            bail!("upstream exceeded 4096 Chat tool calls");
        }
        let position = self.blocks[key].position;
        self.chat_tool_order.insert(index, position);
        Ok(())
    }
    fn next_output_position(&mut self) -> Option<usize> {
        if self.from == Protocol::Responses {
            loop {
                if let Some(key) = self.response_order.get(&self.response_cursor) {
                    if self
                        .blocks
                        .get(key)
                        .is_some_and(|block| block.output_closed)
                    {
                        self.response_cursor.1 += 1;
                        continue;
                    }
                    return self.blocks.get(key).map(|block| block.position);
                }
                if self.response_done.get(&self.response_cursor.0) == Some(&true) {
                    self.response_cursor = (self.response_cursor.0 + 1, 0);
                } else {
                    return None;
                }
            }
        }
        if self.from == Protocol::Chat
            && self.to == Protocol::Anthropic
            && !self.chat_tool_order.is_empty()
        {
            while let Some(key) = self.order.get(self.output_cursor) {
                let block = &self.blocks[key];
                if !block.text {
                    break;
                }
                if block.output_closed {
                    self.output_cursor += 1;
                } else {
                    return Some(self.output_cursor);
                }
            }
            loop {
                let &position = self.chat_tool_order.get(&self.chat_tool_cursor)?;
                let block = &self.blocks[&self.order[position]];
                if block.output_closed {
                    self.chat_tool_cursor += 1;
                    continue;
                }
                return Some(position);
            }
        }
        while let Some(key) = self.order.get(self.output_cursor) {
            if self.blocks[key].output_closed {
                self.output_cursor += 1;
            } else {
                return Some(self.output_cursor);
            }
        }
        None
    }
    fn drain_anthropic(&mut self, output: &mut Vec<Bytes>) {
        while let Some(position) = self.next_output_position() {
            let block = self.blocks.get_mut(&self.order[position]).unwrap();
            if !block.ready {
                break;
            }
            if !block.emitted {
                block.index = self.output_index;
                self.output_index += 1;
                let content = if block.text {
                    json!({"type":"text","text":""})
                } else {
                    json!({"type":"tool_use","id":block.id,"name":block.name,"input":{}})
                };
                emit(
                    output,
                    Some("content_block_start"),
                    json!({"type":"content_block_start","index":block.index,"content_block":content}),
                );
                block.emitted = true;
            }
            if !block.pending_text.is_empty() {
                emit(
                    output,
                    Some("content_block_delta"),
                    json!({"type":"content_block_delta","index":block.index,"delta":{"type":"text_delta","text":block.pending_text}}),
                );
                self.pending_text -= block.pending_text.len();
                block.pending_text = String::new();
            }
            if block.sent_args < block.args.len() {
                emit(
                    output,
                    Some("content_block_delta"),
                    json!({"type":"content_block_delta","index":block.index,"delta":{"type":"input_json_delta","partial_json":&block.args[block.sent_args..]}}),
                );
                block.sent_args = block.args.len();
            }
            if !block.closed {
                break;
            }
            emit(
                output,
                Some("content_block_stop"),
                json!({"type":"content_block_stop","index":block.index}),
            );
            block.output_closed = true;
            self.pending_args -= block.args.len();
            // Retain only the snapshot consistency fingerprints after delivery.
            block.args = String::new();
        }
    }
    fn drain_ordered(&mut self, output: &mut Vec<Bytes>) -> Result<()> {
        if self.to == Protocol::Anthropic {
            self.drain_anthropic(output);
            Ok(())
        } else {
            self.drain_chat_responses(output)
        }
    }
    fn drain_chat_responses(&mut self, output: &mut Vec<Bytes>) -> Result<()> {
        while let Some(position) = self.next_output_position() {
            let key = self.order[position].clone();
            let block = &self.blocks[&key];
            if !block.ready {
                break;
            }
            if block.text && !block.emitted && self.next_tool > 0 {
                bail!(
                    "Chat cannot preserve streamed text after tool calls; use native Anthropic/Responses for interleaved output"
                );
            }
            let (header, text, refusal, arguments, closed) = {
                let block = self.blocks.get_mut(&key).unwrap();
                let header = if block.emitted || block.text {
                    None
                } else {
                    let index = self.next_tool;
                    self.next_tool += 1;
                    block.tool_index = Some(index);
                    Some((index, block.id.clone(), block.name.clone()))
                };
                block.emitted = true;
                let text = std::mem::take(&mut block.pending_text);
                self.pending_text -= text.len();
                let arguments = block.args[block.sent_args..].to_owned();
                block.sent_args = block.args.len();
                let closed = block.closed;
                if closed {
                    block.output_closed = true;
                    self.pending_args -= block.args.len();
                    block.args = String::new();
                }
                (header, text, block.refusal, arguments, closed)
            };
            if let Some((index, id, name)) = header {
                self.chat_chunk(
                    json!({"tool_calls":[{"index":index,"id":id,"type":"function","function":{"name":name,"arguments":""}}]}),
                    Value::Null,
                    output,
                );
            }
            if !text.is_empty() {
                let delta = if refusal {
                    json!({"refusal":text})
                } else {
                    json!({"content":text})
                };
                self.chat_chunk(delta, Value::Null, output);
            }
            if !arguments.is_empty() {
                let index = self.blocks[&key].tool_index.unwrap();
                self.chat_chunk(
                    json!({"tool_calls":[{"index":index,"function":{"arguments":arguments}}]}),
                    Value::Null,
                    output,
                );
            }
            if !closed {
                break;
            }
        }
        Ok(())
    }
    fn text(&mut self, key: &str, text: &str, output: &mut Vec<Bytes>) -> Result<()> {
        if self.from != Protocol::Responses && self.to == Protocol::Chat && self.next_tool > 0 {
            bail!(
                "Chat cannot preserve streamed text after tool calls; use native Anthropic/Responses for interleaved output"
            );
        }
        self.new_block(key, true)?;
        self.start(output);
        let block = self.blocks.get_mut(key).unwrap();
        if block.closed || !block.text {
            bail!("text delta references a closed/non-text block");
        }
        block.bytes = block
            .bytes
            .checked_add(text.len())
            .context("streamed text size overflow")?;
        block.digest = digest(block.digest, text.as_bytes());
        block.ready = true;
        if self.from == Protocol::Responses {
            self.drain_ordered(output)?;
            let block = self.blocks.get_mut(key).unwrap();
            if block.emitted {
                if !text.is_empty() {
                    if self.to == Protocol::Anthropic {
                        emit(
                            output,
                            Some("content_block_delta"),
                            json!({"type":"content_block_delta","index":block.index,"delta":{"type":"text_delta","text":text}}),
                        );
                    } else {
                        let delta = if block.refusal {
                            json!({"refusal":text})
                        } else {
                            json!({"content":text})
                        };
                        self.chat_chunk(delta, Value::Null, output);
                    }
                }
            } else {
                if self.retained_headers + self.pending_args + self.pending_text + text.len()
                    > MAX_PENDING
                {
                    bail!("pending content and retained tool headers exceed 8 MiB in aggregate");
                }
                self.pending_text += text.len();
                block.pending_text.push_str(text);
            }
        } else if self.to == Protocol::Anthropic {
            self.drain_anthropic(output);
            let block = self.blocks.get_mut(key).unwrap();
            if block.emitted && !text.is_empty() {
                emit(
                    output,
                    Some("content_block_delta"),
                    json!({"type":"content_block_delta","index":block.index,"delta":{"type":"text_delta","text":text}}),
                );
            }
        } else if !text.is_empty() {
            let delta = if block.refusal {
                json!({"refusal":text})
            } else {
                json!({"content":text})
            };
            self.chat_chunk(delta, Value::Null, output);
        }
        Ok(())
    }
    fn refusal(&mut self, key: &str, text: &str, output: &mut Vec<Bytes>) -> Result<()> {
        self.new_block(key, true)?;
        let block = self.blocks.get_mut(key).unwrap();
        if block.bytes > 0 && !block.refusal {
            bail!("upstream changed a text block into refusal");
        }
        block.refusal = true;
        self.text(key, text, output)
    }
    fn tool_header(&mut self, key: &str, id: &str, name: &str, append: bool) -> Result<()> {
        self.new_block(key, false)?;
        let block = self.blocks.get_mut(key).unwrap();
        if block.text || block.closed {
            bail!("tool header references closed/non-tool block");
        }
        if block.ready
            && ((!id.is_empty() && id != block.id) || (!name.is_empty() && name != block.name))
        {
            bail!(
                "tool ID/name changed after argument streaming started; upstream tool header must precede arguments"
            );
        }
        let previous = block.id.len() + block.name.len();
        let next = if append {
            previous
                + if block.ready {
                    0
                } else {
                    id.len() + name.len()
                }
        } else {
            id.len() + name.len()
        };
        let retained_headers = self.retained_headers - previous + next;
        if retained_headers + self.pending_args + self.pending_text > MAX_PENDING {
            bail!("pending content and retained tool headers exceed 8 MiB in aggregate");
        }
        // Keep completed headers for Responses snapshot validation, charging them
        // for the entire stream lifetime. Check before copying incoming fragments.
        self.retained_headers = retained_headers;
        if append {
            if !id.is_empty() {
                if block.ready {
                    if id != block.id {
                        bail!("late tool ID fragment");
                    }
                } else {
                    block.id.push_str(id);
                }
            }
            if !name.is_empty() {
                if block.ready {
                    if name != block.name {
                        bail!("late tool name fragment");
                    }
                } else {
                    block.name.push_str(name);
                }
            }
        } else {
            block.id = id.into();
            block.name = name.into();
        }
        Ok(())
    }
    fn emit_tool(&mut self, key: &str, output: &mut Vec<Bytes>) -> Result<()> {
        self.start(output);
        let block = self
            .blocks
            .get_mut(key)
            .context("tool block not initialized")?;
        if block.text || block.closed {
            bail!("tool delta references a closed/non-tool block");
        }
        if block.ready {
            return Ok(());
        }
        if block.id.is_empty() || block.name.is_empty() {
            bail!("tool arguments arrived before complete tool ID/name");
        }
        block.ready = true;
        if self.from == Protocol::Responses {
            self.drain_ordered(output)?;
        } else if self.to == Protocol::Anthropic {
            self.drain_anthropic(output);
        } else {
            block.emitted = true;
            let delta = json!({"tool_calls":[{"index":block.tool_index.unwrap(),"id":block.id,"type":"function","function":{"name":block.name,"arguments":""}}]});
            self.chat_chunk(delta, Value::Null, output);
        }
        Ok(())
    }
    fn tool_delta(&mut self, key: &str, delta: &str, output: &mut Vec<Bytes>) -> Result<()> {
        self.emit_tool(key, output)?;
        let (emitted, block_index, tool_index) = {
            let block = self.blocks.get_mut(key).unwrap();
            if block.closed {
                bail!("tool arguments arrived after block end");
            }
            if self.retained_headers + self.pending_args + self.pending_text + delta.len()
                > MAX_PENDING
            {
                bail!(
                    "pending content and retained tool headers exceed 8 MiB in aggregate; cannot safely validate unfinished JSON"
                );
            }
            self.pending_args += delta.len();
            block.args.push_str(delta);
            block.bytes += delta.len();
            block.digest = digest(block.digest, delta.as_bytes());
            block.saw_delta = true;
            if block.emitted {
                block.sent_args = block.args.len();
            }
            (block.emitted, block.index, block.tool_index)
        };
        if emitted && !delta.is_empty() {
            if self.to == Protocol::Anthropic {
                emit(
                    output,
                    Some("content_block_delta"),
                    json!({"type":"content_block_delta","index":block_index,"delta":{"type":"input_json_delta","partial_json":delta}}),
                );
            } else {
                let delta = json!({"tool_calls":[{"index":tool_index.unwrap(),"function":{"arguments":delta}}]});
                self.chat_chunk(delta, Value::Null, output);
            }
        }
        Ok(())
    }
    fn close(&mut self, key: &str, output: &mut Vec<Bytes>) -> Result<()> {
        let block = self
            .blocks
            .get(key)
            .context("block end references unknown block")?;
        if block.closed {
            bail!("duplicate block end");
        }
        if !block.text {
            if block.args.is_empty() {
                self.tool_delta(key, "{}", output)?;
            }
            arguments(&self.blocks[key].args)?;
            self.emit_tool(key, output)?;
        }
        let block = self.blocks.get_mut(key).unwrap();
        block.closed = true;
        if self.from == Protocol::Responses {
            self.drain_ordered(output)?;
        } else if self.to == Protocol::Anthropic {
            self.drain_anthropic(output);
        } else {
            self.pending_args -= block.args.len();
            block.args = String::new();
        }
        Ok(())
    }
    fn complete(&mut self, reason: &str, from: Protocol, output: &mut Vec<Bytes>) -> Result<()> {
        let mut reason = stop(reason, from, self.to)?;
        if self.to == Protocol::Anthropic {
            reason = super::anthropic_refusal_reason(
                reason,
                self.blocks.values().any(|block| block.refusal),
            )?;
        }
        let keys: Vec<_> = self
            .order
            .iter()
            .filter(|key| !self.blocks[*key].closed)
            .cloned()
            .collect();
        for key in keys {
            self.close(&key, output)?;
        }
        if self.from == Protocol::Responses {
            self.drain_ordered(output)?;
            if self.blocks.values().any(|block| !block.output_closed) {
                bail!("Responses output order is incomplete or inconsistent");
            }
        } else if self.to == Protocol::Anthropic {
            self.drain_anthropic(output);
            if self.from == Protocol::Chat
                && self
                    .chat_tool_order
                    .values()
                    .any(|&position| !self.blocks[&self.order[position]].output_closed)
            {
                bail!("Chat tool indices must be contiguous from zero");
            }
        }
        self.start(output);
        if self.to == Protocol::Anthropic {
            emit(
                output,
                Some("message_delta"),
                json!({"type":"message_delta","delta":{"stop_reason":reason,"stop_sequence":null},"usage":self.usage.json(self.to)}),
            );
            emit(output, Some("message_stop"), json!({"type":"message_stop"}));
        } else {
            self.chat_chunk(json!({}), json!(reason), output);
            if self.include_usage {
                emit(
                    output,
                    None,
                    json!({"id":self.id,"object":"chat.completion.chunk","created":0,"model":self.model,"choices":[],"usage":self.usage.json(self.to)}),
                );
            }
            output.push(Bytes::from_static(b"data: [DONE]\n\n"));
        }
        self.terminal = true;
        Ok(())
    }
    fn check_text(&mut self, key: &str, full: &str, output: &mut Vec<Bytes>) -> Result<()> {
        if self
            .blocks
            .get(key)
            .is_none_or(|b| b.bytes == 0 && !b.closed)
        {
            if self.blocks.get(key).is_some_and(|block| block.refusal) {
                self.refusal(key, full, output)?;
            } else {
                self.text(key, full, output)?;
            }
        }
        let block = self
            .blocks
            .get(key)
            .context("completed text has no corresponding content block")?;
        if !block.text
            || block.bytes != full.len()
            || block.digest != digest(0xcbf29ce484222325, full.as_bytes())
        {
            bail!(
                "Responses completed text differs from streamed deltas; upstream stream is truncated or inconsistent"
            );
        }
        Ok(())
    }
    fn snapshot_item(
        &mut self,
        index: u64,
        item: &Value,
        output: &mut Vec<Bytes>,
    ) -> Result<usize> {
        match item["type"].as_str() {
            Some("function_call") => {
                let key = format!("rtool:{index}");
                self.response_block(index, 0, &key)?;
                let full = item["arguments"]
                    .as_str()
                    .context("completed function call missing arguments")?;
                if !self.blocks.contains_key(&key) {
                    self.tool_header(
                        &key,
                        item["call_id"]
                            .as_str()
                            .context("function call missing call_id")?,
                        item["name"]
                            .as_str()
                            .context("function call missing name")?,
                        false,
                    )?;
                }
                let block = &self.blocks[&key];
                if block.id
                    != item["call_id"]
                        .as_str()
                        .context("function call missing call_id")?
                    || block.name
                        != item["name"]
                            .as_str()
                            .context("function call missing name")?
                {
                    bail!("completed tool ID/name differs from streamed header");
                }
                if !block.saw_delta && !block.closed {
                    self.tool_delta(&key, full, output)?;
                }
                let block = &self.blocks[&key];
                if block.bytes != full.len()
                    || block.digest != digest(0xcbf29ce484222325, full.as_bytes())
                {
                    bail!("Responses completed tool arguments differ from streamed deltas");
                }
                if !block.closed {
                    self.close(&key, output)?;
                }
                Ok(1)
            }
            Some("message") => {
                super::validate_phase(item)?;
                if item["role"] != "assistant" {
                    bail!("Responses output message must have assistant role");
                }
                let parts = item["content"]
                    .as_array()
                    .context("completed message content missing")?;
                for (part_index, part) in parts.iter().enumerate() {
                    validate_responses_part_metadata(part)?;
                    let (text, refusal) = responses_part_content(part)?;
                    let key = format!("r:{index}:{part_index}");
                    self.response_block(index, part_index as u64, &key)?;
                    if !self.blocks.contains_key(&key) && refusal {
                        self.refusal(&key, "", output)?;
                    }
                    if self.blocks.get(&key).is_some_and(|b| b.refusal != refusal) {
                        bail!("completed Responses content type differs from streamed block");
                    }
                    self.check_text(&key, text, output)?;
                    if !self.blocks[&key].closed {
                        self.close(&key, output)?;
                    }
                }
                Ok(parts.len())
            }
            Some("reasoning") => {
                validate_reasoning(item)?;
                Ok(0)
            }
            _ => bail!(
                "unsupported completed Responses output item {}; use native Responses for built-in tools",
                item["type"]
            ),
        }
    }
    fn responses(&mut self, v: Value, event: &str, output: &mut Vec<Bytes>) -> Result<()> {
        let kind = v["type"].as_str().unwrap_or(event);
        if !event.is_empty() && kind != event {
            bail!("Responses SSE event name disagrees with payload type");
        }
        if (kind.starts_with("response.output_item.")
            || kind.starts_with("response.content_part.")
            || kind.starts_with("response.output_text.")
            || kind.starts_with("response.refusal.")
            || kind.starts_with("response.function_call_arguments."))
            && v["output_index"].as_u64().is_none()
        {
            bail!("Responses content/tool event is missing a nonnegative output_index");
        }
        if (kind.starts_with("response.content_part.")
            || kind.starts_with("response.output_text.")
            || kind.starts_with("response.refusal."))
            && v["content_index"].as_u64().is_none()
        {
            bail!("Responses text event is missing a nonnegative content_index");
        }
        let item_index = v["output_index"].as_u64().unwrap_or(0);
        let part_index = v["content_index"].as_u64().unwrap_or(0);
        let key = format!("r:{item_index}:{part_index}");
        let tool_key = format!("rtool:{item_index}");
        if kind.starts_with("response.output_item.") {
            self.response_item(item_index)?;
            if kind == "response.output_item.added" && v["item"]["type"] == "function_call" {
                self.response_block(item_index, 0, &tool_key)?;
            }
        } else if kind.starts_with("response.content_part.")
            || kind.starts_with("response.output_text.")
            || kind.starts_with("response.refusal.")
        {
            self.response_block(item_index, part_index, &key)?;
        } else if kind.starts_with("response.function_call_arguments.") {
            self.response_block(item_index, 0, &tool_key)?;
        }
        match kind {
            "response.created" => {
                if self.source_started {
                    bail!("duplicate response.created");
                }
                self.source_started = true;
                if let Some(id) = v.pointer("/response/id").and_then(Value::as_str) {
                    self.id = id.into();
                }
                self.start(output);
            }
            "response.in_progress" | "response.queued" => {}
            "response.output_item.added" => match v["item"]["type"].as_str() {
                Some("function_call") => {
                    self.tool_header(
                        &tool_key,
                        v["item"]["call_id"]
                            .as_str()
                            .context("function call missing call_id")?,
                        v["item"]["name"]
                            .as_str()
                            .context("function call missing name")?,
                        false,
                    )?;
                    self.emit_tool(&tool_key, output)?;
                    if let Some(args) = v["item"]["arguments"].as_str().filter(|s| !s.is_empty()) {
                        self.tool_delta(&tool_key, args, output)?;
                    }
                }
                Some("message") => super::validate_phase(&v["item"])?,
                Some("reasoning") => validate_reasoning(&v["item"])?,
                _ => bail!(
                    "unsupported Responses streamed output item {}; use native Responses for server tools",
                    v["item"]["type"]
                ),
            },
            "response.content_part.added" => {
                let part = v
                    .get("part")
                    .context("Responses content_part.added missing part")?;
                validate_responses_part_metadata(part)?;
                let (text, refusal) = responses_part_content(part)?;
                if refusal {
                    self.refusal(&key, text, output)?;
                } else {
                    self.text(&key, text, output)?;
                }
            }
            "response.output_text.delta" => {
                if v.get("logprobs")
                    .is_some_and(|v| !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty()))
                {
                    bail!("Responses logprobs require native protocol");
                }
                self.text(
                    &key,
                    v["delta"]
                        .as_str()
                        .context("output_text.delta missing delta")?,
                    output,
                )?;
            }
            "response.refusal.delta" => self.refusal(
                &key,
                v["delta"].as_str().context("refusal.delta missing delta")?,
                output,
            )?,
            "response.function_call_arguments.delta" => self.tool_delta(
                &tool_key,
                v["delta"]
                    .as_str()
                    .context("function_call_arguments.delta missing delta")?,
                output,
            )?,
            "response.function_call_arguments.done" => {
                let full = v["arguments"]
                    .as_str()
                    .context("function_call_arguments.done missing arguments")?;
                let block = self
                    .blocks
                    .get(&tool_key)
                    .context("arguments.done missing tool start")?;
                if !block.saw_delta {
                    self.tool_delta(&tool_key, full, output)?;
                } else if block.args != full {
                    bail!("Responses completed tool arguments differ from streamed deltas");
                }
            }
            "response.output_text.done" => self.check_text(
                &key,
                v["text"]
                    .as_str()
                    .context("output_text.done missing text")?,
                output,
            )?,
            "response.refusal.done" => {
                if !self.blocks.contains_key(&key) {
                    self.refusal(&key, "", output)?;
                }
                self.check_text(
                    &key,
                    v["refusal"]
                        .as_str()
                        .context("refusal.done missing refusal")?,
                    output,
                )?;
            }
            "response.content_part.done" => {
                let part = v
                    .get("part")
                    .context("Responses content_part.done missing part")?;
                validate_responses_part_metadata(part)?;
                let (text, refusal) = responses_part_content(part)?;
                let block_refusal = self
                    .blocks
                    .get(&key)
                    .context("Responses content_part.done has no corresponding block")?
                    .refusal;
                if block_refusal != refusal {
                    bail!("Responses completed content type differs from streamed block");
                }
                self.check_text(&key, text, output)?;
                if self.blocks.get(&key).is_some_and(|b| !b.closed) {
                    self.close(&key, output)?;
                }
            }
            "response.output_item.done" => {
                self.snapshot_item(item_index, &v["item"], output)?;
                self.response_item_done(item_index, output)?;
            }
            "response.completed" | "response.incomplete" => {
                let response = &v["response"];
                validate_responses_terminal(response, kind)?;
                self.usage = Usage::parse(&response["usage"], Protocol::Responses)?;
                let mut count = 0;
                for (index, item) in response["output"]
                    .as_array()
                    .context("completed Responses output missing")?
                    .iter()
                    .enumerate()
                {
                    count += self.snapshot_item(index as u64, item, output)?;
                    self.response_item_done(index as u64, output)?;
                }
                if count != self.blocks.len() {
                    bail!("completed Responses output omits streamed content blocks");
                }
                let reason = if kind == "response.incomplete" {
                    response["incomplete_details"]["reason"]
                        .as_str()
                        .context("incomplete response missing reason")?
                } else {
                    "completed"
                };
                let has_tool = self.blocks.values().any(|block| !block.text);
                if reason == "completed" && has_tool {
                    self.complete("tool_calls", Protocol::Chat, output)?;
                } else {
                    self.complete(reason, Protocol::Responses, output)?;
                }
            }
            "response.output_text.annotation.added" => {
                bail!("Responses annotations cannot be translated losslessly; use native Responses")
            }
            k if k.starts_with("response.reasoning") => bail!(
                "Responses reasoning summaries cannot be represented losslessly; disable summaries or use native Responses"
            ),
            _ => bail!("unsupported Responses SSE event {kind}; use native Responses"),
        }
        Ok(())
    }
    fn chat_text(&mut self, text: &str, refusal: bool, output: &mut Vec<Bytes>) -> Result<()> {
        // Empty fields carry no content and must not end or resume a block.
        // The caller has already required a string, so invalid types still fail.
        if text.is_empty() {
            return Ok(());
        }
        let (key, previous) = if refusal {
            ("chat:refusal", "chat:text")
        } else {
            ("chat:text", "chat:refusal")
        };
        if self.next_tool > 0 || self.blocks.get(key).is_some_and(|block| block.closed) {
            bail!(
                "Chat cannot preserve interleaved streamed content/refusal or text after tool calls; use native protocol"
            );
        }
        // Chat has no text-stop marker. Switching fields ends the preceding
        // block; resuming it later would require overlapping/reordered output.
        if self.blocks.get(previous).is_some_and(|block| !block.closed) {
            self.close(previous, output)?;
        }
        if refusal {
            self.refusal(key, text, output)
        } else {
            self.text(key, text, output)
        }
    }
    fn chat(&mut self, v: Value, output: &mut Vec<Bytes>) -> Result<()> {
        if let Some(id) = v["id"].as_str()
            && !self.started
        {
            self.id = id.into();
        }
        if let Some(usage) = v.get("usage").filter(|v| !v.is_null()) {
            self.usage = Usage::parse(usage, Protocol::Chat)?;
        }
        let choices = v["choices"]
            .as_array()
            .context("Chat SSE chunk missing choices")?;
        if choices.len() > 1 {
            bail!("Chat streaming translation requires n=1");
        }
        for choice in choices {
            if choice["index"].as_u64() != Some(0) {
                bail!("Chat streaming translation requires choice index 0");
            }
            if self.source_finished && choice["delta"].as_object().is_some_and(|m| !m.is_empty()) {
                bail!("Chat emitted delta after finish_reason");
            }
            if choice.get("logprobs").is_some_and(|v| !v.is_null()) {
                bail!("Chat logprobs require native protocol");
            }
            let mut delta = choice["delta"]
                .as_object()
                .context("Chat chunk delta must be an object")?
                .clone();
            if let Some(role) = delta.remove("role") {
                if role != "assistant" {
                    bail!("Chat stream role must be assistant");
                }
                self.start(output);
            }
            if let Some(text) = delta.remove("content").filter(|v| !v.is_null()) {
                self.chat_text(
                    text.as_str()
                        .context("Chat streamed content must be text")?,
                    false,
                    output,
                )?;
            }
            if let Some(refusal) = delta.remove("refusal").filter(|v| !v.is_null()) {
                self.chat_text(
                    refusal
                        .as_str()
                        .context("Chat streamed refusal must be text")?,
                    true,
                    output,
                )?;
            }
            if let Some(tools) = delta.remove("tool_calls").filter(|v| !v.is_null()) {
                let tools = tools
                    .as_array()
                    .context("streamed tool_calls must be array")?;
                // Chat has no content-stop marker. Starting tools ends its
                // preceding text, while parallel tool blocks stay open until
                // the source finish marker settles all argument deltas.
                if self.next_tool == 0 && !tools.is_empty() {
                    for position in 0..self.order.len() {
                        let key = &self.order[position];
                        if self.blocks[key].text && !self.blocks[key].closed {
                            let key = key.clone();
                            self.close(&key, output)?;
                        }
                    }
                }
                for call in tools {
                    let mut call = super::obj(call.clone(), "streamed tool call")?;
                    let index = call
                        .remove("index")
                        .and_then(|v| v.as_u64())
                        .context("streamed tool call missing index")?;
                    let key = format!("chat:tool:{index}");
                    if call
                        .remove("type")
                        .is_some_and(|v| !v.is_null() && v != "function")
                    {
                        bail!("only function tools are translatable");
                    }
                    let id = optional_string(call.remove("id"), "tool id")?;
                    let mut function = match call.remove("function") {
                        None | Some(Value::Null) => serde_json::Map::new(),
                        Some(v) => super::obj(v, "streamed function")?,
                    };
                    let name = optional_string(function.remove("name"), "tool name")?;
                    let args = optional_string(function.remove("arguments"), "tool arguments")?;
                    super::strict(&function, "streamed tool function")?;
                    super::strict(&call, "streamed tool call")?;
                    self.tool_header(&key, &id, &name, true)?;
                    self.chat_tool(index, &key)?;
                    if !args.is_empty() {
                        self.tool_delta(&key, &args, output)?;
                    }
                }
            }
            if let Some(reasoning) = delta.remove("reasoning_content")
                && !reasoning.is_null()
                && reasoning != ""
            {
                bail!("Chat reasoning content requires native protocol");
            }
            super::strict(&delta, "Chat stream delta")?;
            if let Some(reason) = choice["finish_reason"].as_str() {
                stop(reason, Protocol::Chat, self.to)?;
                if self.finish_reason.is_some() {
                    bail!("duplicate Chat finish_reason");
                }
                self.finish_reason = Some(reason.into());
                self.source_finished = true;
            }
        }
        Ok(())
    }
    fn anthropic(&mut self, v: Value, event: &str, output: &mut Vec<Bytes>) -> Result<()> {
        let kind = v["type"].as_str().unwrap_or(event);
        if !event.is_empty() && kind != event {
            bail!("Anthropic SSE event name disagrees with payload type");
        }
        if !self.source_started && kind != "message_start" && kind != "ping" {
            bail!("Anthropic stream is missing message_start");
        }
        if kind.starts_with("content_block_") && v["index"].as_u64().is_none() {
            bail!("Anthropic content event is missing a nonnegative index");
        }
        let index = v["index"].as_u64().unwrap_or(0);
        let key = format!("anth:{index}");
        match kind {
            "ping" => {}
            "message_start" => {
                if self.source_started {
                    bail!("duplicate Anthropic message_start");
                }
                self.source_started = true;
                if let Some(id) = v["message"]["id"].as_str() {
                    self.id = id.into();
                }
                self.usage = Usage::parse(&v["message"]["usage"], Protocol::Anthropic)?;
                if v["message"]["content"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty())
                {
                    bail!("Anthropic message_start content must be empty");
                }
                self.start(output);
            }
            "content_block_start" => {
                if self.blocks.contains_key(&key) {
                    bail!("duplicate Anthropic content block index");
                }
                let block = &v["content_block"];
                match block["type"].as_str() {
                    Some("text") => {
                        if block.get("citations").is_some_and(|v| {
                            !v.is_null() && v.as_array().is_none_or(|a| !a.is_empty())
                        }) {
                            bail!("Anthropic citations require native protocol");
                        }
                        self.text(
                            &key,
                            block["text"].as_str().context("text block missing text")?,
                            output,
                        )?;
                    }
                    Some("tool_use") => {
                        self.tool_header(
                            &key,
                            block["id"].as_str().context("tool_use missing id")?,
                            block["name"].as_str().context("tool_use missing name")?,
                            false,
                        )?;
                        self.emit_tool(&key, output)?;
                        if block["input"].as_object().is_none() {
                            bail!("tool_use input must be object");
                        }
                        if block["input"].as_object().is_some_and(|m| !m.is_empty()) {
                            self.tool_delta(
                                &key,
                                &serde_json::to_string(&block["input"])?,
                                output,
                            )?;
                        }
                    }
                    _ => bail!(
                        "unsupported Anthropic streamed content {}; thinking/server tools require native Anthropic",
                        block["type"]
                    ),
                }
            }
            "content_block_delta" => match v["delta"]["type"].as_str() {
                Some("text_delta") => {
                    if !self.blocks.contains_key(&key) {
                        bail!("text_delta arrived before content_block_start");
                    }
                    self.text(
                        &key,
                        v["delta"]["text"]
                            .as_str()
                            .context("text_delta missing text")?,
                        output,
                    )?;
                }
                Some("input_json_delta") => self.tool_delta(
                    &key,
                    v["delta"]["partial_json"]
                        .as_str()
                        .context("input_json_delta missing partial_json")?,
                    output,
                )?,
                _ => bail!(
                    "unsupported Anthropic delta {}; thinking/citations require native protocol",
                    v["delta"]["type"]
                ),
            },
            "content_block_stop" => self.close(&key, output)?,
            "message_delta" => {
                if let Some(reason) = v["delta"]["stop_reason"].as_str() {
                    if reason == "refusal"
                        && self.to == Protocol::Chat
                        && self
                            .blocks
                            .values()
                            .any(|block| block.text && !block.refusal && block.bytes > 0)
                    {
                        bail!(
                            "Anthropic refusal arrived after text was already streamed as Chat content; use a buffered translated request or native Anthropic"
                        );
                    }
                    stop(reason, Protocol::Anthropic, self.to)?;
                    self.finish_reason = Some(reason.into());
                }
                if let Some(usage) = v.get("usage") {
                    self.usage.merge_anthropic(usage)?;
                }
            }
            "message_stop" => {
                if self.blocks.values().any(|b| !b.closed) {
                    bail!("Anthropic message_stop arrived with unfinished content blocks");
                }
                let reason = self
                    .finish_reason
                    .clone()
                    .context("Anthropic message_stop missing message_delta stop_reason")?;
                self.complete(&reason, Protocol::Anthropic, output)?;
            }
            _ => bail!("unsupported Anthropic SSE event {kind}"),
        }
        Ok(())
    }
}
fn optional_string(value: Option<Value>, name: &str) -> Result<String> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s),
        _ => bail!("{name} must be a string"),
    }
}
fn digest(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
    }
    hash
}
fn emit(output: &mut Vec<Bytes>, event: Option<&str>, value: Value) {
    let mut frame = String::new();
    if let Some(event) = event {
        frame.push_str("event: ");
        frame.push_str(event);
        frame.push('\n');
    }
    frame.push_str("data: ");
    frame.push_str(&value.to_string());
    frame.push_str("\n\n");
    output.push(Bytes::from(frame));
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(event: &str, value: Value) -> Vec<u8> {
        format!("event: {event}\r\ndata: {value}\r\n\r\n").into_bytes()
    }
    fn joined(parts: Vec<Bytes>) -> String {
        parts
            .into_iter()
            .map(|b| String::from_utf8(b.to_vec()).unwrap())
            .collect()
    }
    fn events(output: &str) -> Vec<Value> {
        let mut parser = Sse::default();
        output
            .bytes()
            .filter_map(|byte| parser.byte(byte).unwrap())
            .filter(|frame| frame.data != b"[DONE]")
            .map(|frame| serde_json::from_slice(&frame.data).unwrap())
            .collect()
    }
    // Anthropic consumers append on start, address deltas by index, and finish
    // the current block on stop. Enforce that contract while reconstructing.
    fn anthropic_blocks(output: &str) -> Vec<Value> {
        let mut blocks = Vec::new();
        let mut active = None;
        for event in events(output) {
            match event["type"].as_str() {
                Some("content_block_start") => {
                    let index = event["index"].as_u64().unwrap() as usize;
                    assert_eq!(active, None, "content blocks must not overlap");
                    assert_eq!(index, blocks.len(), "block starts must be sequential");
                    blocks.push(event["content_block"].clone());
                    active = Some(index);
                }
                Some("content_block_delta") => {
                    let index = event["index"].as_u64().unwrap() as usize;
                    assert_eq!(active, Some(index), "delta must address the active block");
                    let field = if event["delta"]["type"] == "text_delta" {
                        "text"
                    } else {
                        "partial_json"
                    };
                    let delta = event["delta"][field].as_str().unwrap();
                    if field == "text" {
                        let text = blocks[index]["text"].as_str().unwrap().to_owned() + delta;
                        blocks[index]["text"] = json!(text);
                    } else {
                        let args =
                            blocks[index]["arguments"].as_str().unwrap_or("").to_owned() + delta;
                        blocks[index]["arguments"] = json!(args);
                    }
                }
                Some("content_block_stop") => {
                    let index = event["index"].as_u64().unwrap() as usize;
                    assert_eq!(active.take(), Some(index), "each block must stop once");
                    if blocks[index]["type"] == "tool_use" {
                        blocks[index]["input"] =
                            serde_json::from_str(blocks[index]["arguments"].as_str().unwrap())
                                .unwrap();
                        blocks[index].as_object_mut().unwrap().remove("arguments");
                    }
                }
                _ => {}
            }
        }
        assert_eq!(active, None, "all content blocks must finish");
        blocks
    }
    fn chat_frame(delta: Value, reason: Value) -> Vec<u8> {
        format!(
            "data: {}\n\n",
            json!({"choices":[{"index":0,"delta":delta,"finish_reason":reason}]})
        )
        .into_bytes()
    }
    #[test]
    fn leading_bom_preserves_first_chat_frame_at_arbitrary_boundaries() {
        let stream = [
            b"\xef\xbb\xbf".to_vec(),
            chat_frame(json!({"role":"assistant","content":"FIRST "}), Value::Null),
            chat_frame(json!({"content":"\u{feff}SECOND"}), Value::Null),
            chat_frame(json!({}), json!("stop")),
            b"data: [DONE]\n\n".to_vec(),
        ]
        .concat();
        for size in [1, 2, 3, 7, stream.len()] {
            let mut translator =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            let mut output = String::new();
            for chunk in stream.chunks(size) {
                output.push_str(&joined(translator.push(chunk).unwrap()));
            }
            translator.finish().unwrap();
            assert_eq!(
                anthropic_blocks(&output),
                vec![json!({"type":"text","text":"FIRST \u{feff}SECOND"})],
            );
        }
    }

    #[test]
    fn leading_bom_preserves_terminal_responses_frame() {
        let response = json!({"id":"r","status":"completed","output":[],"usage":{}});
        let mut stream = b"\xef\xbb\xbf".to_vec();
        stream.extend_from_slice(
            format!(
                "data: {}\n\n",
                json!({"type":"response.completed","response":response})
            )
            .as_bytes(),
        );
        assert_eq!(
            collect_response_sse(&stream, Protocol::Responses).unwrap(),
            response
        );
    }

    #[test]
    fn buffered_responses_rejects_early_phase_even_when_terminal_is_unphased() {
        for early_event in ["response.output_item.added", "response.output_item.done"] {
            for terminal_event in ["response.completed", "response.incomplete"] {
                for explicit_null in [false, true] {
                    for phase in [
                        json!("commentary"),
                        json!("final_answer"),
                        json!(""),
                        json!(false),
                        json!(42),
                        json!([]),
                        json!({}),
                    ] {
                        let mut message = json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello café"}]});
                        if explicit_null {
                            message["phase"] = Value::Null;
                        }
                        let mut phased = message.clone();
                        phased["phase"] = phase;
                        let response = json!({"id":"r","status":terminal_event.strip_prefix("response.").unwrap(),"output":[message],"usage":{}});
                        let stream = [
                            frame(
                                "response.output_item.added",
                                json!({"type":"response.output_item.added","output_index":0,"item":if early_event == "response.output_item.added" { &phased } else { &message }}),
                            ),
                            frame(
                                "response.output_item.done",
                                json!({"type":"response.output_item.done","output_index":0,"item":if early_event == "response.output_item.done" { &phased } else { &message }}),
                            ),
                            frame(terminal_event, json!({"type":terminal_event,"response":response})),
                        ]
                        .concat();
                        for target in [Protocol::Chat, Protocol::Anthropic] {
                            assert!(collect_response_sse(&stream, target).is_err());
                        }
                        assert_eq!(
                            collect_response_sse(&stream, Protocol::Responses).unwrap(),
                            response
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn buffered_responses_rejects_phase_in_terminal_output() {
        for terminal_event in ["response.completed", "response.incomplete"] {
            for phase in [
                json!("commentary"),
                json!("final_answer"),
                json!(""),
                json!(false),
                json!(42),
                json!([]),
                json!({}),
            ] {
                let message = json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello café"}]});
                let mut phased = message.clone();
                phased["phase"] = phase;
                let response = json!({"id":"r","status":terminal_event.strip_prefix("response.").unwrap(),"output":[phased],"usage":{}});
                let stream = [
                    frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":message})),
                    frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":0,"item":message})),
                    frame(terminal_event, json!({"type":terminal_event,"response":response})),
                ]
                .concat();
                for target in [Protocol::Chat, Protocol::Anthropic] {
                    assert!(collect_response_sse(&stream, target).is_err());
                }
                assert_eq!(
                    collect_response_sse(&stream, Protocol::Responses).unwrap(),
                    response
                );
            }
        }
    }

    #[test]
    fn buffered_responses_absent_or_null_phase_preserves_exact_terminal_content() {
        for terminal_event in ["response.completed", "response.incomplete"] {
            for null_snapshots in 0..8 {
                let mut snapshots: [Value; 3] = std::array::from_fn(
                    |_| json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello café\nexact content","annotations":[]}]}),
                );
                for (index, message) in snapshots.iter_mut().enumerate() {
                    if null_snapshots & (1 << index) != 0 {
                        message["phase"] = Value::Null;
                    }
                }
                let response = json!({"id":"r","status":terminal_event.strip_prefix("response.").unwrap(),"output":[snapshots[2]],"usage":{"input_tokens":4,"output_tokens":2}});
                let stream = [
                    frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":snapshots[0]})),
                    frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":0,"item":snapshots[1]})),
                    frame(terminal_event, json!({"type":terminal_event,"response":response})),
                ]
                .concat();
                for target in [Protocol::Chat, Protocol::Anthropic, Protocol::Responses] {
                    assert_eq!(collect_response_sse(&stream, target).unwrap(), response);
                }
            }
        }
    }

    #[test]
    fn buffered_responses_event_names_preserve_phase_validation() {
        for early in ["response.output_item.added", "response.output_item.done"] {
            for terminal in ["response.completed", "response.incomplete"] {
                for phase in [Value::Null, json!("commentary"), json!("final_answer")] {
                    let message = json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello café","annotations":[]}]});
                    let mut phased = message.clone();
                    phased["phase"] = phase.clone();
                    let response = json!({"id":"r","status":terminal.strip_prefix("response.").unwrap(),"output":[message],"usage":{}});
                    let bytes = [
                        frame(early, json!({"output_index":0,"item":phased})),
                        frame(terminal, json!({"response":response})),
                    ]
                    .concat();
                    for target in [Protocol::Chat, Protocol::Anthropic, Protocol::Responses] {
                        let collected = collect_response_sse(&bytes, target);
                        if !phase.is_null() && target != Protocol::Responses {
                            assert!(collected.is_err());
                        } else {
                            assert_eq!(collected.unwrap(), response);
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn buffered_responses_reject_inconsistent_or_failed_event_envelopes() {
        for target in [Protocol::Chat, Protocol::Anthropic, Protocol::Responses] {
            let response = json!({"id":"r","status":"completed","output":[],"usage":{}});
            let mismatch = frame(
                "response.in_progress",
                json!({"type":"response.completed","response":response}),
            );
            assert!(collect_response_sse(&mismatch, target).is_err());
            for kind in ["error", "response.failed"] {
                let bytes = [
                    frame(kind, json!({"response":{"error":{"message":"failed"}}})),
                    frame("response.completed", json!({"response":response})),
                ]
                .concat();
                assert!(collect_response_sse(&bytes, target).is_err());
            }
        }
    }

    #[test]
    fn responses_terminal_event_requires_matching_success_status_and_null_error() {
        let invalid = [
            (
                "response.completed",
                json!({"status":"failed","error":null,"output":[],"usage":{}}),
            ),
            (
                "response.completed",
                json!({"status":"completed","error":{"message":"failed"},"output":[],"usage":{}}),
            ),
            (
                "response.incomplete",
                json!({"status":"completed","error":null,"output":[],"usage":{},"incomplete_details":{"reason":"max_output_tokens"}}),
            ),
            (
                "response.incomplete",
                json!({"status":"incomplete","error":{"message":"failed"},"output":[],"usage":{},"incomplete_details":{"reason":"max_output_tokens"}}),
            ),
        ];
        for target in [Protocol::Chat, Protocol::Anthropic] {
            for (kind, response) in &invalid {
                let terminal = frame(kind, json!({"type":kind,"response":response}));
                assert!(
                    collect_response_sse(&terminal, target).is_err(),
                    "collector accepted {target:?} {kind} {response}"
                );
                let mut translator =
                    StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
                assert!(
                    translator.push(&terminal).is_err(),
                    "translator accepted {target:?} {kind} {response}"
                );
            }

            for error in [None, Some(Value::Null)] {
                let mut response = json!({"status":"incomplete","output":[],"usage":{},"incomplete_details":{"reason":"max_output_tokens"}});
                if let Some(error) = error {
                    response["error"] = error;
                }
                let terminal = frame(
                    "response.incomplete",
                    json!({"type":"response.incomplete","response":response}),
                );
                assert_eq!(
                    collect_response_sse(&terminal, target).unwrap()["status"],
                    "incomplete"
                );
                let mut translator =
                    StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
                let output = joined(translator.push(&terminal).unwrap());
                translator.finish().unwrap();
                if target == Protocol::Chat {
                    assert!(output.contains("\"finish_reason\":\"length\""));
                    assert!(output.ends_with("data: [DONE]\n\n"));
                } else {
                    assert!(output.contains("\"stop_reason\":\"max_tokens\""));
                    assert!(output.contains("message_stop"));
                }
            }
        }
    }

    #[test]
    fn chat_stream_null_tool_calls_preserves_text_and_completion() {
        for nullable in [false, true] {
            let mut t =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            let mut output = String::new();
            for (index, text) in ["hello", " world"].into_iter().enumerate() {
                let mut delta = json!({"content":text});
                if index == 0 {
                    delta["role"] = json!("assistant");
                }
                if nullable {
                    delta["tool_calls"] = Value::Null;
                }
                output.push_str(&joined(t.push(&chat_frame(delta, Value::Null)).unwrap()));
            }
            let terminal = if nullable {
                json!({"tool_calls":null})
            } else {
                json!({})
            };
            output.push_str(&joined(
                t.push(&chat_frame(terminal, json!("stop"))).unwrap(),
            ));
            output.push_str(&joined(t.push(b"data: [DONE]\n\n").unwrap()));
            output.push_str(&joined(t.finish().unwrap()));
            assert_eq!(
                anthropic_blocks(&output),
                vec![json!({"type":"text","text":"hello world"})]
            );
            let events = events(&output);
            assert_eq!(events.last().unwrap()["type"], "message_stop");
            assert_eq!(
                events
                    .iter()
                    .find(|event| event["type"] == "message_delta")
                    .unwrap()["delta"]["stop_reason"],
                "end_turn"
            );
            assert!(!t.upstream_failed());
        }
    }

    #[test]
    fn chat_stream_rejects_non_array_tool_calls() {
        for calls in [json!("invalid"), json!({}), json!(true), json!(1)] {
            let mut t =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            let error = t
                .push(&chat_frame(
                    json!({"content":"hello","tool_calls":calls}),
                    Value::Null,
                ))
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("streamed tool_calls must be array")
            );
        }
    }

    #[test]
    fn chat_text_refusal_transitions_emit_before_finish() {
        for initial in ["", "before café"] {
            for refusal_first in [false, true] {
                let mut t =
                    StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
                let first = if refusal_first {
                    json!({"role":"assistant","refusal":initial})
                } else {
                    json!({"role":"assistant","content":initial})
                };
                let mut output = joined(t.push(&chat_frame(first, Value::Null)).unwrap());
                let block_index = usize::from(!initial.is_empty());
                for (index, fragment) in ["I cannot", " help"].into_iter().enumerate() {
                    let delta = if refusal_first {
                        json!({"content":fragment,"refusal":""})
                    } else {
                        json!({"content":"","refusal":fragment})
                    };
                    let part = joined(t.push(&chat_frame(delta, Value::Null)).unwrap());
                    let mut expected = Vec::new();
                    if index == 0 {
                        if !initial.is_empty() {
                            expected.push(json!({"type":"content_block_stop","index":0}));
                        }
                        expected.push(json!({
                            "type":"content_block_start","index":block_index,
                            "content_block":{"type":"text","text":""}
                        }));
                    }
                    expected.push(json!({
                        "type":"content_block_delta","index":block_index,
                        "delta":{"type":"text_delta","text":fragment}
                    }));
                    assert_eq!(events(&part), expected);
                    output.push_str(&part);
                }
                let finish = joined(t.push(&chat_frame(json!({}), json!("stop"))).unwrap());
                assert!(finish.is_empty(), "finish_reason must wait for [DONE]");
                output.push_str(&joined(t.push(b"data: [DONE]\n\n").unwrap()));
                t.finish().unwrap();
                let mut expected = Vec::new();
                if !initial.is_empty() {
                    expected.push(json!({"type":"text","text":initial}));
                }
                expected.push(json!({"type":"text","text":"I cannot help"}));
                assert_eq!(anthropic_blocks(&output), expected);
                let all = events(&output);
                assert_eq!(
                    all.iter()
                        .filter(|event| event["type"] == "content_block_start")
                        .count(),
                    block_index + 1
                );
                assert_eq!(
                    all.iter()
                        .filter(|event| event["type"] == "content_block_stop")
                        .count(),
                    block_index + 1
                );
                assert_eq!(
                    all.iter()
                        .find(|event| event["type"] == "message_delta")
                        .unwrap()["delta"]["stop_reason"],
                    if refusal_first && initial.is_empty() {
                        "end_turn"
                    } else {
                        "refusal"
                    }
                );
            }
        }
    }
    #[test]
    fn chat_empty_fields_preserve_incremental_text_and_refusal() {
        for refusal in [false, true] {
            let mut t =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            let mut output = joined(
                t.push(&chat_frame(
                    json!({"role":"assistant","content":"","refusal":""}),
                    Value::Null,
                ))
                .unwrap(),
            );
            for (index, fragment) in ["I cannot", " help"].into_iter().enumerate() {
                let delta = if refusal {
                    json!({"content":"","refusal":fragment})
                } else {
                    json!({"content":fragment,"refusal":""})
                };
                let part = joined(t.push(&chat_frame(delta, Value::Null)).unwrap());
                let mut expected = Vec::new();
                if index == 0 {
                    expected.push(json!({
                        "type":"content_block_start","index":0,
                        "content_block":{"type":"text","text":""}
                    }));
                }
                expected.push(json!({
                    "type":"content_block_delta","index":0,
                    "delta":{"type":"text_delta","text":fragment}
                }));
                assert_eq!(events(&part), expected);
                output.push_str(&part);
            }
            assert!(
                t.push(&chat_frame(json!({}), json!("stop")))
                    .unwrap()
                    .is_empty()
            );
            let terminal = joined(t.push(b"data: [DONE]\n\n").unwrap());
            assert_eq!(
                events(&terminal),
                vec![
                    json!({"type":"content_block_stop","index":0}),
                    json!({
                        "type":"message_delta",
                        "delta":{"stop_reason":if refusal { "refusal" } else { "end_turn" },"stop_sequence":null},
                        "usage":t.usage.json(Protocol::Anthropic)
                    }),
                    json!({"type":"message_stop"})
                ]
            );
            output.push_str(&terminal);
            assert_eq!(
                anthropic_blocks(&output),
                vec![json!({"type":"text","text":"I cannot help"})]
            );
            t.finish().unwrap();
        }
    }
    #[test]
    fn chat_empty_fields_do_not_cross_tool_boundaries() {
        let mut t = StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        let mut output = joined(
            t.push(&chat_frame(json!({"content":"before"}), Value::Null))
                .unwrap(),
        );
        output.push_str(&joined(
            t.push(&chat_frame(
                json!({"content":"","refusal":"","tool_calls":[
                    {"index":0,"id":"a","function":{"name":"first","arguments":"{"}}
                ]}),
                Value::Null,
            ))
            .unwrap(),
        ));
        assert!(
            t.push(&chat_frame(json!({"content":"","refusal":""}), Value::Null))
                .unwrap()
                .is_empty()
        );
        output.push_str(&joined(
            t.push(&chat_frame(
                json!({"content":"","refusal":"","tool_calls":[
                    {"index":0,"function":{"arguments":"}"}}
                ]}),
                Value::Null,
            ))
            .unwrap(),
        ));
        t.push(&chat_frame(json!({}), json!("tool_calls"))).unwrap();
        output.push_str(&joined(t.push(b"data: [DONE]\n\n").unwrap()));
        assert_eq!(
            anthropic_blocks(&output),
            vec![
                json!({"type":"text","text":"before"}),
                json!({"type":"tool_use","id":"a","name":"first","input":{}})
            ]
        );
        t.finish().unwrap();
    }
    #[test]
    fn chat_empty_fields_do_not_hide_invalid_text_types() {
        for delta in [
            json!({"content":"","refusal":false}),
            json!({"content":[],"refusal":""}),
        ] {
            let mut t =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            assert!(
                t.push(&chat_frame(delta, Value::Null))
                    .unwrap_err()
                    .to_string()
                    .contains("must be text")
            );
        }
    }
    #[test]
    fn chat_rejects_resuming_closed_text_or_refusal() {
        for first in [json!({"content":"text"}), json!({"refusal":"refusal"})] {
            let second = if first.get("content").is_some() {
                json!({"refusal":"refusal"})
            } else {
                json!({"content":"text"})
            };
            let mut t =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            t.push(&chat_frame(first.clone(), Value::Null)).unwrap();
            t.push(&chat_frame(second, Value::Null)).unwrap();
            assert!(
                t.push(&chat_frame(first, Value::Null))
                    .unwrap_err()
                    .to_string()
                    .contains("cannot preserve interleaved")
            );
        }
    }
    #[test]
    fn chat_rejects_text_or_refusal_after_tool_calls() {
        for delta in [json!({"content":"text"}), json!({"refusal":"refusal"})] {
            let mut t =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            t.push(&chat_frame(
                json!({"tool_calls":[
                    {"index":0,"id":"a","function":{"name":"first","arguments":"{}"}}
                ]}),
                Value::Null,
            ))
            .unwrap();
            assert!(
                t.push(&chat_frame(delta, Value::Null))
                    .unwrap_err()
                    .to_string()
                    .contains("text after tool calls")
            );
        }
    }
    #[test]
    fn chat_active_refusal_is_not_accumulated_after_text_transition() {
        let mut t = StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        t.push(&chat_frame(json!({"content":"before"}), Value::Null))
            .unwrap();
        let text = "x".repeat(1024 * 1024);
        let chunk = chat_frame(json!({"refusal":text}), Value::Null);
        for _ in 0..9 {
            let output = joined(t.push(&chunk).unwrap());
            assert_eq!(
                events(&output)
                    .iter()
                    .find_map(|event| event["delta"]["text"].as_str())
                    .unwrap()
                    .len(),
                text.len()
            );
        }
        t.push(&chat_frame(json!({}), json!("stop"))).unwrap();
        let output = joined(t.push(b"data: [DONE]\n\n").unwrap());
        assert_eq!(
            events(&output)
                .iter()
                .find(|event| event["type"] == "message_delta")
                .unwrap()["delta"]["stop_reason"],
            "refusal"
        );
        t.finish().unwrap();
    }

    #[test]
    fn streamed_anthropic_refusal_rejects_competing_terminal_reasons() {
        for reason in ["length", "tool_calls"] {
            let mut translator =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            translator
                .push(&chat_frame(json!({"refusal":"denied"}), Value::Null))
                .unwrap();
            translator
                .push(&chat_frame(json!({}), json!(reason)))
                .unwrap();
            let error = translator.push(b"data: [DONE]\n\n").unwrap_err();
            assert!(error.to_string().contains("refusal"));
            assert!(error.to_string().contains("stop reason"));
        }

        let refusal = json!({"type":"message","role":"assistant","content":[{"type":"refusal","refusal":"denied"}]});
        let terminal = frame(
            "response.incomplete",
            json!({"type":"response.incomplete","response":{"status":"incomplete","error":null,"output":[refusal],"usage":{},"incomplete_details":{"reason":"max_output_tokens"}}}),
        );
        let mut translator =
            StreamTranslator::new(Protocol::Responses, Protocol::Anthropic, "x".into(), true);
        let error = translator.push(&terminal).unwrap_err();
        assert!(error.to_string().contains("refusal"));

        for (from, terminal) in [
            (
                Protocol::Chat,
                [
                    chat_frame(json!({"refusal":"denied"}), Value::Null),
                    chat_frame(json!({}), json!("stop")),
                    b"data: [DONE]\n\n".to_vec(),
                ]
                .concat(),
            ),
            (
                Protocol::Responses,
                frame(
                    "response.completed",
                    json!({"type":"response.completed","response":{"status":"completed","error":null,"output":[refusal],"usage":{}}}),
                ),
            ),
        ] {
            let mut translator = StreamTranslator::new(from, Protocol::Anthropic, "x".into(), true);
            let output = joined(translator.push(&terminal).unwrap());
            translator.finish().unwrap();
            let terminal = events(&output)
                .into_iter()
                .find(|event| event["type"] == "message_delta")
                .unwrap();
            assert_eq!(terminal["delta"]["stop_reason"], "refusal");
        }
    }
    #[test]
    fn chat_delayed_first_tool_preserves_consumer_identity_at_every_byte() {
        let first = chat_frame(
            json!({"role":"assistant","tool_calls":[
                {"index":0,"id":"call_zero","type":"function","function":{"name":"first","arguments":""}},
                {"index":1,"id":"call_one","type":"function","function":{"name":"second","arguments":"{\"y\":2}"}}
            ]}),
            Value::Null,
        );
        let second = chat_frame(
            json!({"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":1}"}}]}),
            Value::Null,
        );
        for size in [1, 2, 7, 31, 1024] {
            let mut t =
                StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
            let mut output = String::new();
            for chunk in first.chunks(size).chain(second.chunks(size)) {
                output.push_str(&joined(t.push(chunk).unwrap()));
            }
            let early = events(&output);
            assert!(
                early
                    .iter()
                    .any(|e| e["delta"]["partial_json"] == "{\"x\":1}")
            );
            assert!(!early.iter().any(|e| e["content_block"]["id"] == "call_one"));
            output.push_str(&joined(
                t.push(&chat_frame(json!({}), json!("tool_calls"))).unwrap(),
            ));
            output.push_str(&joined(t.push(b"data: [DONE]\n\n").unwrap()));
            t.finish().unwrap();
            let blocks = anthropic_blocks(&output);
            assert_eq!(
                blocks,
                vec![
                    json!({"type":"tool_use","id":"call_zero","name":"first","input":{"x":1}}),
                    json!({"type":"tool_use","id":"call_one","name":"second","input":{"y":2}}),
                ]
            );
        }
    }
    #[test]
    fn chat_text_then_many_parallel_tools_close_in_source_order() {
        let mut t = StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        let mut output = joined(
            t.push(&chat_frame(json!({"content":"before café"}), Value::Null))
                .unwrap(),
        );
        assert!(
            events(&output)
                .iter()
                .any(|e| e["delta"]["text"] == "before café")
        );
        let tools: Vec<_> = (0..12).map(|index| json!({
            "index":index,"id":format!("call_{index}"),"type":"function",
            "function":{"name":format!("tool_{index}"),"arguments":format!("{{\"n\":{index}}}")}
        })).collect();
        output.push_str(&joined(
            t.push(&chat_frame(json!({"tool_calls":tools}), Value::Null))
                .unwrap(),
        ));
        output.push_str(&joined(
            t.push(&chat_frame(json!({}), json!("tool_calls"))).unwrap(),
        ));
        output.push_str(&joined(t.push(b"data: [DONE]\n\n").unwrap()));
        t.finish().unwrap();
        let blocks = anthropic_blocks(&output);
        assert_eq!(blocks[0], json!({"type":"text","text":"before café"}));
        for index in 0..12 {
            assert_eq!(
                blocks[index + 1],
                json!({
                    "type":"tool_use","id":format!("call_{index}"),
                    "name":format!("tool_{index}"),"input":{"n":index}
                })
            );
        }
    }
    #[test]
    fn chat_tools_follow_numeric_indices_when_higher_indices_arrive_first() {
        let mut translator =
            StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        let mut output = joined(
            translator
                .push(&chat_frame(json!({"content":"before tools"}), Value::Null))
                .unwrap(),
        );
        output.push_str(&joined(
            translator
                .push(&chat_frame(
                    json!({"tool_calls":[{"index":10,"id":"call_10","function":{"name":"tool_10","arguments":"{\"n\":10}"}}]}),
                    Value::Null,
                ))
                .unwrap(),
        ));
        assert!(
            !events(&output)
                .iter()
                .any(|event| event["content_block"]["id"] == "call_10")
        );

        output.push_str(&joined(
            translator
                .push(&chat_frame(
                    json!({"tool_calls":[{"index":0,"id":"call_0","function":{"name":"tool_0","arguments":"{\"n\":0}"}}]}),
                    Value::Null,
                ))
                .unwrap(),
        ));
        let early = events(&output);
        assert!(
            early
                .iter()
                .any(|event| event["content_block"]["id"] == "call_0")
        );
        assert!(
            early
                .iter()
                .any(|event| event["delta"]["partial_json"] == "{\"n\":0}")
        );
        for index in (1..10).rev() {
            output.push_str(&joined(
                translator
                    .push(&chat_frame(
                        json!({"tool_calls":[{"index":index,"id":format!("call_{index}"),"function":{"name":format!("tool_{index}"),"arguments":format!("{{\"n\":{index}}}")}}]}),
                        Value::Null,
                    ))
                    .unwrap(),
            ));
        }
        output.push_str(&joined(
            translator
                .push(&chat_frame(json!({}), json!("tool_calls")))
                .unwrap(),
        ));
        output.push_str(&joined(translator.push(b"data: [DONE]\n\n").unwrap()));
        translator.finish().unwrap();
        let blocks = anthropic_blocks(&output);
        assert_eq!(blocks[0], json!({"type":"text","text":"before tools"}));
        for index in 0..=10 {
            assert_eq!(
                blocks[index + 1],
                json!({
                    "type":"tool_use",
                    "id":format!("call_{index}"),
                    "name":format!("tool_{index}"),
                    "input":{"n":index}
                })
            );
        }
    }

    #[test]
    fn chat_tool_index_gap_fails_at_terminal() {
        let mut translator =
            StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        translator
            .push(&chat_frame(
                json!({"tool_calls":[{"index":1,"id":"call_1","function":{"name":"tool_1","arguments":"{}"}}]}),
                Value::Null,
            ))
            .unwrap();
        translator
            .push(&chat_frame(json!({}), json!("tool_calls")))
            .unwrap();
        let error = translator.push(b"data: [DONE]\n\n").unwrap_err();
        assert!(error.to_string().contains("contiguous"));
    }

    #[test]
    fn blocked_tool_arguments_are_bounded_across_frames() {
        let mut t = StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        t.push(&chat_frame(
            json!({"tool_calls":[
                {"index":0,"id":"a","function":{"name":"first","arguments":""}},
                {"index":1,"id":"b","function":{"name":"later","arguments":"{\"text\":\""}}
            ]}),
            Value::Null,
        ))
        .unwrap();
        let chunk = "x".repeat(1024 * 1024);
        for _ in 0..7 {
            let output = joined(
                t.push(&chat_frame(
                    json!({"tool_calls":[{"index":1,"function":{"arguments":chunk}}]}),
                    Value::Null,
                ))
                .unwrap(),
            );
            assert!(
                !events(&output)
                    .iter()
                    .any(|e| e["type"] == "content_block_start")
            );
        }
        assert!(
            t.push(&chat_frame(
                json!({"tool_calls":[{"index":1,"function":{"arguments":chunk}}]}),
                Value::Null
            ))
            .is_err()
        );
    }
    #[test]
    fn responses_preserve_output_and_message_part_order_at_arbitrary_boundaries() {
        let message = json!({"type":"message","role":"assistant","content":[
            {"type":"output_text","text":"first café","annotations":[]},
            {"type":"output_text","text":"tail","annotations":[]}
        ]});
        let tool = json!({"type":"function_call","call_id":"call_later","name":"later","arguments":"{\"y\":2}"});
        let prefix = [
            frame("response.created", json!({"type":"response.created","response":{"id":"r"}})),
            frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}})),
            frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"call_later","name":"later","arguments":""}})),
            frame("response.function_call_arguments.delta", json!({"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"y\":2}"})),
            frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":0,"content_index":1,"delta":"tail"})),
            frame("response.content_part.added", json!({"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":""}})),
            frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"first café"})),
        ].concat();
        let suffix = [
            frame("response.content_part.done", json!({"type":"response.content_part.done","output_index":0,"content_index":1,"part":message["content"][1]})),
            frame("response.content_part.done", json!({"type":"response.content_part.done","output_index":0,"content_index":0,"part":message["content"][0]})),
            frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":1,"item":tool})),
            frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":0,"item":message})),
        ].concat();
        let terminal = frame(
            "response.completed",
            json!({"type":"response.completed","response":{"status":"completed","output":[message,tool],"usage":{"input_tokens":1,"output_tokens":2}}}),
        );
        for size in [1, 2, 7, 31, 1024] {
            let mut t =
                StreamTranslator::new(Protocol::Responses, Protocol::Anthropic, "x".into(), true);
            let mut output = String::new();
            for chunk in prefix.chunks(size) {
                output.push_str(&joined(t.push(chunk).unwrap()));
            }
            let early = events(&output);
            assert!(early.iter().any(|e| e["delta"]["text"] == "first café"));
            assert!(
                !early
                    .iter()
                    .any(|e| e["content_block"]["type"] == "tool_use")
            );
            assert!(!early.iter().any(|e| e["delta"]["text"] == "tail"));
            for chunk in suffix.chunks(size) {
                output.push_str(&joined(t.push(chunk).unwrap()));
            }
            // Earlier item completion releases later content before the
            // terminal response snapshot, without duplicate block callbacks.
            assert_eq!(
                anthropic_blocks(&output),
                vec![
                    json!({"type":"text","text":"first café"}),
                    json!({"type":"text","text":"tail"}),
                    json!({"type":"tool_use","id":"call_later","name":"later","input":{"y":2}}),
                ]
            );
            for chunk in terminal.chunks(size) {
                output.push_str(&joined(t.push(chunk).unwrap()));
            }
            t.finish().unwrap();
            assert_eq!(anthropic_blocks(&output).len(), 3);
        }
    }

    #[test]
    fn responses_chat_releases_text_and_tools_in_canonical_order_before_terminal() {
        let message = json!({"type":"message","role":"assistant","content":[
            {"type":"output_text","text":"first café","annotations":[]},
            {"type":"output_text","text":"tail","annotations":[]}
        ]});
        let tool = json!({"type":"function_call","call_id":"call_later","name":"later","arguments":"{\"y\":2}"});
        let prefix = [
            frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}})),
            frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"call_later","name":"later","arguments":""}})),
            frame("response.function_call_arguments.delta", json!({"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"y\":2}"})),
            frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":0,"content_index":1,"delta":"tail"})),
            frame("response.content_part.added", json!({"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":""}})),
            frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"first café"})),
        ]
        .concat();
        let suffix = [
            frame("response.content_part.done", json!({"type":"response.content_part.done","output_index":0,"content_index":1,"part":message["content"][1]})),
            frame("response.content_part.done", json!({"type":"response.content_part.done","output_index":0,"content_index":0,"part":message["content"][0]})),
            frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":1,"item":tool})),
            frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":0,"item":message})),
        ]
        .concat();
        for size in [1, 7, 1024] {
            let mut translator =
                StreamTranslator::new(Protocol::Responses, Protocol::Chat, "x".into(), false);
            let mut output = String::new();
            for chunk in prefix.chunks(size) {
                output.push_str(&joined(translator.push(chunk).unwrap()));
            }
            let early = events(&output);
            assert!(
                early
                    .iter()
                    .any(|event| event["choices"][0]["delta"]["content"] == "first café")
            );
            assert!(
                !early
                    .iter()
                    .any(|event| event["choices"][0]["delta"]["content"] == "tail")
            );
            assert!(
                !early
                    .iter()
                    .any(|event| event["choices"][0]["delta"].get("tool_calls").is_some())
            );
            for chunk in suffix.chunks(size) {
                output.push_str(&joined(translator.push(chunk).unwrap()));
            }
            let emitted = events(&output);
            let text = emitted
                .iter()
                .filter_map(|event| event["choices"][0]["delta"]["content"].as_str())
                .collect::<String>();
            assert_eq!(text, "first cafétail");
            let calls: Vec<_> = emitted
                .iter()
                .filter_map(|event| event["choices"][0]["delta"]["tool_calls"][0].as_object())
                .collect();
            assert_eq!(calls[0]["index"], 0);
            assert_eq!(calls[0]["id"], "call_later");
            assert_eq!(calls[0]["function"]["name"], "later");
            assert_eq!(calls[1]["index"], 0);
            assert_eq!(calls[1]["function"]["arguments"], "{\"y\":2}");
            let terminal = frame(
                "response.completed",
                json!({"type":"response.completed","response":{"status":"completed","output":[message,tool],"usage":{}}}),
            );
            output.push_str(&joined(translator.push(&terminal).unwrap()));
            translator.finish().unwrap();
            assert!(output.ends_with("data: [DONE]\n\n"));
        }
    }

    #[test]
    fn responses_chat_rejects_actual_canonical_text_after_tool() {
        let mut translator =
            StreamTranslator::new(Protocol::Responses, Protocol::Chat, "x".into(), false);
        let tool =
            json!({"type":"function_call","call_id":"first","name":"lookup","arguments":"{}"});
        let message = json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"after","annotations":[]}]});
        translator.push(&frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"first","name":"lookup","arguments":""}}))).unwrap();
        translator.push(&frame("response.function_call_arguments.delta", json!({"type":"response.function_call_arguments.delta","output_index":0,"delta":"{}"}))).unwrap();
        assert!(translator.push(&frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"after"}))).unwrap().is_empty());
        translator
            .push(&frame(
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":1,"item":message}),
            ))
            .unwrap();
        let error = translator
            .push(&frame(
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":0,"item":tool}),
            ))
            .unwrap_err();
        assert!(error.to_string().contains("text after tool calls"));
    }

    #[test]
    fn responses_chat_stream_preserves_interleaved_text_and_refusal_order() {
        let message = json!({"type":"message","role":"assistant","content":[
            {"type":"output_text","text":"A","annotations":[]},
            {"type":"refusal","refusal":"B"},
            {"type":"output_text","text":"C","annotations":[]}
        ]});
        let terminal = frame(
            "response.completed",
            json!({"type":"response.completed","response":{"status":"completed","output":[message],"usage":{}}}),
        );
        let mut translator =
            StreamTranslator::new(Protocol::Responses, Protocol::Chat, "x".into(), false);
        let output = joined(translator.push(&terminal).unwrap());
        translator.finish().unwrap();
        let deltas: Vec<_> = events(&output)
            .into_iter()
            .filter_map(|event| {
                let delta = &event["choices"][0]["delta"];
                if let Some(text) = delta["content"].as_str().filter(|text| !text.is_empty()) {
                    Some(json!({"content":text}))
                } else {
                    delta["refusal"]
                        .as_str()
                        .map(|text| json!({"refusal":text}))
                }
            })
            .collect();
        assert_eq!(
            deltas,
            vec![
                json!({"content":"A"}),
                json!({"refusal":"B"}),
                json!({"content":"C"})
            ]
        );
        assert!(output.ends_with("data: [DONE]\n\n"));
    }

    fn responses_text_stream(logprobs: Option<Value>) -> Vec<u8> {
        let message = json!({"type":"message","role":"assistant","content":[
            {"type":"output_text","text":"hello","annotations":[],"logprobs":null}
        ]});
        let mut delta = json!({
            "type":"response.output_text.delta",
            "output_index":0,
            "content_index":0,
            "delta":"hello"
        });
        if let Some(logprobs) = logprobs {
            delta["logprobs"] = logprobs;
        }
        [
            frame("response.created", json!({"type":"response.created","response":{"id":"r"}})),
            frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}})),
            frame("response.content_part.added", json!({"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}})),
            frame("response.output_text.delta", delta),
            frame("response.output_text.done", json!({"type":"response.output_text.done","output_index":0,"content_index":0,"text":"hello"})),
            frame("response.content_part.done", json!({"type":"response.content_part.done","output_index":0,"content_index":0,"part":message["content"][0]})),
            frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":0,"item":message})),
            frame("response.completed", json!({"type":"response.completed","response":{"status":"completed","output":[message],"usage":{"input_tokens":2,"output_tokens":1}}})),
        ]
        .concat()
    }

    fn empty_response_message(part: Value) -> Value {
        json!({"type":"message","role":"assistant","content":[part]})
    }

    fn response_part_events(
        added: Value,
        done: Option<Value>,
        item_snapshot: Value,
        terminal_snapshot: Value,
    ) -> Vec<u8> {
        let mut events = vec![
            frame(
                "response.created",
                json!({"type":"response.created","response":{"id":"r"}}),
            ),
            frame(
                "response.output_item.added",
                json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}}),
            ),
            frame(
                "response.content_part.added",
                json!({"type":"response.content_part.added","output_index":0,"content_index":0,"part":added}),
            ),
        ];
        if let Some(part) = done {
            events.push(frame(
                "response.content_part.done",
                json!({"type":"response.content_part.done","output_index":0,"content_index":0,"part":part}),
            ));
        }
        events.extend([
            frame(
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":0,"item":empty_response_message(item_snapshot)}),
            ),
            frame(
                "response.completed",
                json!({"type":"response.completed","response":{"status":"completed","output":[empty_response_message(terminal_snapshot)],"usage":{}}}),
            ),
        ]);
        events.concat()
    }

    fn translate_responses_stream(bytes: &[u8], target: Protocol) -> Result<String> {
        let mut translator = StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
        let mut output = joined(translator.push(bytes)?);
        output.push_str(&joined(translator.finish()?));
        Ok(output)
    }

    #[test]
    fn responses_content_part_added_requires_valid_text_and_refusal_fields() {
        for target in [Protocol::Anthropic, Protocol::Chat] {
            for (kind, field) in [("output_text", "text"), ("refusal", "refusal")] {
                for malformed in [None, Some(Value::Null), Some(json!(7))] {
                    let mut part = json!({"type":kind});
                    if let Some(value) = malformed {
                        part[field] = value;
                    }
                    let terminal = if kind == "output_text" {
                        json!({"type":"output_text","text":"","annotations":[]})
                    } else {
                        json!({"type":"refusal","refusal":""})
                    };
                    let stream = response_part_events(
                        part.clone(),
                        None,
                        terminal.clone(),
                        terminal.clone(),
                    );
                    assert!(
                        translate_responses_stream(&stream, target).is_err(),
                        "{target:?} added {kind}.{field}"
                    );

                    let mut done = terminal.clone();
                    if let Some(value) = part.get(field) {
                        done[field] = value.clone();
                    } else {
                        done.as_object_mut().unwrap().remove(field);
                    }
                    let stream = response_part_events(
                        terminal.clone(),
                        Some(done),
                        terminal.clone(),
                        terminal.clone(),
                    );
                    assert!(
                        translate_responses_stream(&stream, target).is_err(),
                        "{target:?} done {kind}.{field}"
                    );

                    let stream = response_part_events(
                        terminal.clone(),
                        Some(terminal.clone()),
                        part.clone(),
                        terminal.clone(),
                    );
                    assert!(
                        translate_responses_stream(&stream, target).is_err(),
                        "{target:?} output_item.done {kind}.{field}"
                    );

                    let stream = response_part_events(
                        terminal.clone(),
                        Some(terminal.clone()),
                        terminal.clone(),
                        part,
                    );
                    assert!(
                        translate_responses_stream(&stream, target).is_err(),
                        "{target:?} terminal {kind}.{field}"
                    );
                }
            }
        }
    }

    #[test]
    fn responses_content_part_added_and_done_validate_annotations_and_logprobs() {
        for target in [Protocol::Anthropic, Protocol::Chat] {
            for (metadata, malformed) in [
                ("annotations", json!([{"type":"url_citation"}])),
                ("annotations", json!({})),
                ("annotations", Value::Null),
                ("logprobs", json!([{"token":"x"}])),
                ("logprobs", json!({})),
                ("logprobs", json!(false)),
            ] {
                let mut added = json!({"type":"output_text","text":""});
                added[metadata] = malformed.clone();
                let valid = json!({"type":"output_text","text":"","annotations":[]});
                let stream = response_part_events(added, None, valid.clone(), valid.clone());
                assert!(
                    translate_responses_stream(&stream, target).is_err(),
                    "{target:?} added {metadata}={malformed}"
                );

                let mut done = json!({"type":"output_text","text":""});
                done[metadata] = malformed.clone();
                let stream = response_part_events(valid.clone(), Some(done), valid.clone(), valid);
                assert!(
                    translate_responses_stream(&stream, target).is_err(),
                    "{target:?} done {metadata}={malformed}"
                );
            }
        }
    }

    #[test]
    fn responses_content_part_snapshots_validate_annotations_and_logprobs() {
        for target in [Protocol::Anthropic, Protocol::Chat] {
            for (metadata, malformed) in [
                ("annotations", json!([{"type":"url_citation"}])),
                ("annotations", json!({})),
                ("logprobs", json!([{"token":"x"}])),
                ("logprobs", json!({})),
            ] {
                let mut snapshot = json!({"type":"output_text","text":"","annotations":[]});
                snapshot[metadata] = malformed.clone();
                let valid = json!({"type":"output_text","text":"","annotations":[]});
                let item_stream = response_part_events(
                    valid.clone(),
                    Some(valid.clone()),
                    snapshot.clone(),
                    valid.clone(),
                );
                assert!(
                    translate_responses_stream(&item_stream, target).is_err(),
                    "{target:?} output_item.done {metadata}={malformed}"
                );

                let terminal_stream = response_part_events(
                    valid.clone(),
                    Some(valid.clone()),
                    valid.clone(),
                    snapshot,
                );
                assert!(
                    translate_responses_stream(&terminal_stream, target).is_err(),
                    "{target:?} terminal {metadata}={malformed}"
                );
            }
        }
    }

    #[test]
    fn responses_valid_empty_parts_and_optional_logprobs_remain_translatable() {
        for target in [Protocol::Anthropic, Protocol::Chat] {
            for kind in ["output_text", "refusal"] {
                for logprobs in [None, Some(Value::Null), Some(json!([]))] {
                    let field = if kind == "output_text" {
                        "text"
                    } else {
                        "refusal"
                    };
                    let mut part = json!({"type":kind});
                    part[field] = json!("");
                    if let Some(logprobs) = &logprobs {
                        part["logprobs"] = logprobs.clone();
                    }
                    let mut added = part.clone();
                    added["annotations"] = json!([]);
                    let stream =
                        response_part_events(added, Some(part.clone()), part.clone(), part);
                    assert!(
                        translate_responses_stream(&stream, target).is_ok(),
                        "{target:?} {kind} {logprobs:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn responses_stream_null_and_empty_logprobs_are_absent_for_both_targets() {
        for target in [Protocol::Anthropic, Protocol::Chat] {
            for logprobs in [None, Some(Value::Null), Some(json!([]))] {
                let mut translator =
                    StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
                let output = joined(translator.push(&responses_text_stream(logprobs)).unwrap());
                translator.finish().unwrap();
                assert!(output.contains("hello"), "{target:?}: {output}");
                if target == Protocol::Chat {
                    assert!(output.contains("[DONE]"), "{output}");
                } else {
                    assert!(output.contains("message_stop"), "{output}");
                }
            }
        }
    }

    #[test]
    fn responses_stream_rejects_nonempty_and_malformed_logprobs() {
        for target in [Protocol::Anthropic, Protocol::Chat] {
            for logprobs in [
                json!([{"token":"hello","logprob":-0.1}]),
                json!({}),
                json!(""),
                json!(false),
                json!(0),
            ] {
                let mut translator =
                    StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
                assert!(
                    translator
                        .push(&responses_text_stream(Some(logprobs)))
                        .is_err(),
                    "{target:?}"
                );
            }
        }
    }

    #[test]
    fn chat_usage_chunk_follows_downstream_preference_for_translated_backends() {
        let anthropic = [
            frame("message_start", json!({"type":"message_start","message":{"id":"m","content":[],"usage":{"input_tokens":5,"output_tokens":0}}})),
            frame("content_block_start", json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}})),
            frame("content_block_delta", json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}})),
            frame("content_block_stop", json!({"type":"content_block_stop","index":0})),
            frame("message_delta", json!({"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null},"usage":{"output_tokens":2}})),
            frame("message_stop", json!({"type":"message_stop"})),
        ]
        .concat();
        for (from, stream) in [
            (Protocol::Responses, responses_text_stream(None)),
            (Protocol::Anthropic, anthropic),
        ] {
            for include_usage in [false, true] {
                let mut translator =
                    StreamTranslator::new(from, Protocol::Chat, "x".into(), include_usage);
                let output = joined(translator.push(&stream).unwrap());
                translator.finish().unwrap();
                let usage_chunks = events(&output)
                    .iter()
                    .filter(|event| {
                        event["choices"].as_array().is_some_and(Vec::is_empty)
                            && event.get("usage").is_some()
                    })
                    .count();
                assert_eq!(usage_chunks, usize::from(include_usage), "{from:?}");
                assert!(output.ends_with("data: [DONE]\n\n"));
            }
        }
    }

    #[test]
    fn responses_first_tool_streams_before_later_message() {
        let mut t =
            StreamTranslator::new(Protocol::Responses, Protocol::Anthropic, "x".into(), true);
        let tool = json!({"type":"function_call","call_id":"first","name":"lookup","arguments":"{\"x\":1}"});
        let message = json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"after"}]});
        let mut output = joined(t.push(&frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"first","name":"lookup","arguments":""}}))).unwrap());
        output.push_str(&joined(t.push(&frame("response.function_call_arguments.delta", json!({"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"x\":"}))).unwrap()));
        assert!(
            events(&output)
                .iter()
                .any(|e| e["delta"]["partial_json"] == "{\"x\":")
        );
        output.push_str(&joined(t.push(&frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"after"}))).unwrap()));
        output.push_str(&joined(
            t.push(&frame(
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":1,"item":message}),
            ))
            .unwrap(),
        ));
        assert!(
            !events(&output)
                .iter()
                .any(|e| e["delta"]["text"] == "after")
        );
        output.push_str(&joined(t.push(&frame("response.function_call_arguments.delta", json!({"type":"response.function_call_arguments.delta","output_index":0,"delta":"1}"}))).unwrap()));
        output.push_str(&joined(
            t.push(&frame(
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":0,"item":tool}),
            ))
            .unwrap(),
        ));
        assert_eq!(
            anthropic_blocks(&output),
            vec![
                json!({"type":"tool_use","id":"first","name":"lookup","input":{"x":1}}),
                json!({"type":"text","text":"after"}),
            ]
        );
        output.push_str(&joined(t.push(&frame("response.completed", json!({"type":"response.completed","response":{"status":"completed","output":[tool,message],"usage":{}}}))).unwrap()));
        t.finish().unwrap();
        assert_eq!(anthropic_blocks(&output).len(), 2);
    }
    #[test]
    fn blocked_response_text_is_bounded_but_active_text_is_not_accumulated() {
        let text = "x".repeat(1024 * 1024);
        let pending = frame(
            "response.output_text.delta",
            json!({"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":text}),
        );
        for target in [Protocol::Anthropic, Protocol::Chat] {
            let mut blocked = StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
            blocked.push(&frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"a","name":"first","arguments":"{"}}))).unwrap();
            for _ in 0..7 {
                assert!(blocked.push(&pending).unwrap().is_empty(), "{target:?}");
            }
            assert!(blocked.push(&pending).is_err(), "{target:?}");
        }

        let mut active =
            StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        let chunk = chat_frame(json!({"content":text}), Value::Null);
        for _ in 0..9 {
            let output = joined(active.push(&chunk).unwrap());
            assert_eq!(
                events(&output)
                    .iter()
                    .find_map(|v| v["delta"]["text"].as_str())
                    .unwrap()
                    .len(),
                text.len()
            );
        }
        active.push(&chat_frame(json!({}), json!("stop"))).unwrap();
        active.push(b"data: [DONE]\n\n").unwrap();
        active.finish().unwrap();
    }
    #[test]
    fn blocked_responses_still_validate_snapshots_and_truncation() {
        for target in [Protocol::Anthropic, Protocol::Chat] {
            for tool_mismatch in [false, true] {
                let mut translator =
                    StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
                translator.push(&frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"a","name":"first","arguments":""}}))).unwrap();
                if tool_mismatch {
                    translator.push(&frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":1,"item":{"type":"function_call","call_id":"b","name":"second","arguments":""}}))).unwrap();
                    translator.push(&frame("response.function_call_arguments.delta", json!({"type":"response.function_call_arguments.delta","output_index":1,"delta":"{\"x\":1}"}))).unwrap();
                    assert!(translator.push(&frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":1,"item":{"type":"function_call","call_id":"b","name":"second","arguments":"{\"x\":2}"}}))).is_err(), "{target:?}");
                } else {
                    translator.push(&frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"original"}))).unwrap();
                    assert!(translator.push(&frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":1,"item":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"changed"}]}}))).is_err(), "{target:?}");
                }
            }
            let mut truncated =
                StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
            truncated.push(&frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"blocked"}))).unwrap();
            assert!(truncated.finish().is_err(), "{target:?}");
            let mut inconsistent =
                StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
            inconsistent.push(&frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"blocked"}))).unwrap();
            assert!(
                inconsistent
                    .push(&frame(
                        "response.completed",
                        json!({"type":"response.completed","response":{"output":[],"usage":{}}})
                    ))
                    .is_err(),
                "{target:?}"
            );
        }
    }
    #[test]
    fn anthropic_partial_usage_preserves_independent_counters() {
        let cases = [
            (
                json!({"input_tokens":10,"cache_read_input_tokens":20}),
                vec![json!({"input_tokens":11,"output_tokens":2})],
                31,
                20,
                2,
            ),
            (
                json!({"input_tokens":10,"cache_read_input_tokens":20,"cache_creation_input_tokens":7}),
                vec![
                    json!({"input_tokens":null,"cache_read_input_tokens":null,"cache_creation_input_tokens":null,"output_tokens":null}),
                    json!({"cache_read_input_tokens":23}),
                    json!({"cache_creation_input_tokens":9,"output_tokens":2}),
                ],
                42,
                23,
                2,
            ),
            (
                json!({"input_tokens":10,"cache_read_input_tokens":20,"cache_creation_input_tokens":7,"output_tokens":3}),
                vec![
                    json!({"input_tokens":0,"cache_read_input_tokens":0,"cache_creation_input_tokens":0}),
                ],
                0,
                0,
                3,
            ),
            (
                json!({"input_tokens":u64::MAX,"cache_read_input_tokens":20,"cache_creation_input_tokens":7}),
                vec![
                    json!(null),
                    json!({"cache_read_input_tokens":0,"cache_creation_input_tokens":0,"output_tokens":2}),
                ],
                u64::MAX,
                0,
                2,
            ),
        ];
        for (start, updates, prompt, cached, completion) in cases {
            let mut t =
                StreamTranslator::new(Protocol::Anthropic, Protocol::Chat, "x".into(), true);
            t.push(&frame(
                "message_start",
                json!({"type":"message_start","message":{"content":[],"usage":start}}),
            ))
            .unwrap();
            for usage in updates {
                t.push(&frame("message_delta", json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":usage}))).unwrap();
            }
            let output = joined(
                t.push(&frame("message_stop", json!({"type":"message_stop"})))
                    .unwrap(),
            );
            t.finish().unwrap();
            let usage = events(&output)
                .into_iter()
                .find_map(|v| v.get("usage").cloned())
                .unwrap();
            assert_eq!(usage["prompt_tokens"], prompt);
            assert_eq!(usage["prompt_tokens_details"]["cached_tokens"], cached);
            assert_eq!(usage["completion_tokens"], completion);
        }
    }
    #[test]
    fn anthropic_partial_usage_rejects_invalid_present_values() {
        for field in [
            "input_tokens",
            "output_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
        ] {
            for invalid in [json!(-1), json!(1.5), json!("2"), json!(true), json!({})] {
                let mut t =
                    StreamTranslator::new(Protocol::Anthropic, Protocol::Chat, "x".into(), true);
                t.push(&frame("message_start", json!({"type":"message_start","message":{"content":[],"usage":{"input_tokens":10,"cache_read_input_tokens":20}}}))).unwrap();
                let mut usage = json!({});
                usage[field] = invalid;
                assert!(
                    t.push(&frame(
                        "message_delta",
                        json!({"type":"message_delta","delta":{},"usage":usage})
                    ))
                    .is_err(),
                    "{field}"
                );
            }
        }
    }

    #[test]
    fn streamed_nested_usage_details_require_nonnegative_integer_counters() {
        let cases = [
            (Protocol::Chat, "prompt_tokens_details", "cached_tokens"),
            (
                Protocol::Chat,
                "completion_tokens_details",
                "reasoning_tokens",
            ),
            (Protocol::Responses, "input_tokens_details", "cached_tokens"),
            (
                Protocol::Responses,
                "output_tokens_details",
                "reasoning_tokens",
            ),
        ];
        for (from, details, counter) in cases {
            for value in [
                Value::Null,
                json!({}),
                json!({counter:null}),
                json!({counter:7}),
            ] {
                let mut usage = json!({});
                usage[details] = value;
                let bytes = if from == Protocol::Chat {
                    format!("data: {}\n\n", json!({"choices":[],"usage":usage})).into_bytes()
                } else {
                    frame(
                        "response.completed",
                        json!({"type":"response.completed","response":{"status":"completed","error":null,"output":[],"usage":usage}}),
                    )
                };
                let target = if from == Protocol::Chat {
                    Protocol::Anthropic
                } else {
                    Protocol::Chat
                };
                let mut translator = StreamTranslator::new(from, target, "x".into(), true);
                translator.push(&bytes).unwrap();
            }

            for invalid in [json!(-1), json!(1.5), json!("7"), json!(true), json!([])] {
                let mut usage = json!({});
                usage[details] = invalid;
                let bytes = if from == Protocol::Chat {
                    format!("data: {}\n\n", json!({"choices":[],"usage":usage})).into_bytes()
                } else {
                    frame(
                        "response.completed",
                        json!({"type":"response.completed","response":{"status":"completed","error":null,"output":[],"usage":usage}}),
                    )
                };
                let target = if from == Protocol::Chat {
                    Protocol::Anthropic
                } else {
                    Protocol::Chat
                };
                let mut translator = StreamTranslator::new(from, target, "x".into(), true);
                assert!(
                    translator.push(&bytes).is_err(),
                    "{from:?} {details} container"
                );
            }
            for invalid in [
                json!(-1),
                json!(1.5),
                json!("7"),
                json!(true),
                json!([]),
                json!({}),
            ] {
                let mut usage = json!({});
                usage[details] = json!({counter:invalid});
                let bytes = if from == Protocol::Chat {
                    format!("data: {}\n\n", json!({"choices":[],"usage":usage})).into_bytes()
                } else {
                    frame(
                        "response.completed",
                        json!({"type":"response.completed","response":{"status":"completed","error":null,"output":[],"usage":usage}}),
                    )
                };
                let target = if from == Protocol::Chat {
                    Protocol::Anthropic
                } else {
                    Protocol::Chat
                };
                let mut translator = StreamTranslator::new(from, target, "x".into(), true);
                assert!(
                    translator.push(&bytes).is_err(),
                    "{from:?} {details}.{counter}"
                );
            }
        }
    }
    #[test]
    fn responses_tools_incremental_every_byte_and_usage() {
        let frames = vec![
            frame(
                "response.created",
                json!({"type":"response.created","response":{"id":"r"}}),
            ),
            frame(
                "response.output_item.added",
                json!({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"read","arguments":""}}),
            ),
            frame(
                "response.function_call_arguments.delta",
                json!({"type":"response.function_call_arguments.delta","output_index":0,"delta":"{\"path\":"}),
            ),
            frame(
                "response.function_call_arguments.delta",
                json!({"type":"response.function_call_arguments.delta","output_index":0,"delta":"\"café\"}"}),
            ),
            frame(
                "response.function_call_arguments.done",
                json!({"type":"response.function_call_arguments.done","output_index":0,"arguments":"{\"path\":\"café\"}"}),
            ),
            frame(
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":0,"item":{"type":"function_call","call_id":"call_1","name":"read","arguments":"{\"path\":\"café\"}"}}),
            ),
            frame(
                "response.completed",
                json!({"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":20,"output_tokens":8,"input_tokens_details":{"cached_tokens":4}},"output":[{"type":"function_call","call_id":"call_1","name":"read","arguments":"{\"path\":\"café\"}"}]}}),
            ),
        ];
        let mut translator = StreamTranslator::new(
            Protocol::Responses,
            Protocol::Anthropic,
            "alias".into(),
            true,
        );
        let mut output = String::new();
        for (i, f) in frames.into_iter().enumerate() {
            for byte in f {
                output.push_str(&joined(translator.push(&[byte]).unwrap()));
            }
            if i == 2 {
                assert!(output.contains("input_json_delta"));
                assert!(!output.contains("message_stop"));
            }
        }
        output.push_str(&joined(translator.finish().unwrap()));
        assert!(output.contains("café"));
        assert!(output.contains("tool_use"));
        assert!(output.contains("message_stop"));
        assert!(output.contains("\"cache_read_input_tokens\":4"));
    }
    #[test]
    fn responses_tool_terminal_reason_matches_target_dialect() {
        let tool =
            json!({"type":"function_call","call_id":"call_1","name":"read","arguments":"{}"});
        let stream = [
            frame(
                "response.output_item.added",
                json!({"type":"response.output_item.added","output_index":0,"item":tool}),
            ),
            frame(
                "response.output_item.done",
                json!({"type":"response.output_item.done","output_index":0,"item":tool}),
            ),
            frame(
                "response.completed",
                json!({"type":"response.completed","response":{"status":"completed","error":null,"output":[tool],"usage":{}}}),
            ),
        ]
        .concat();
        for (target, expected) in [
            (Protocol::Anthropic, "tool_use"),
            (Protocol::Chat, "tool_calls"),
        ] {
            let mut translator =
                StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
            let output = joined(translator.push(&stream).unwrap());
            translator.finish().unwrap();
            let reason = events(&output).into_iter().find_map(|event| {
                if target == Protocol::Anthropic {
                    event
                        .pointer("/delta/stop_reason")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                } else {
                    event
                        .pointer("/choices/0/finish_reason")
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                }
            });
            assert_eq!(reason.as_deref(), Some(expected), "{target:?}: {output}");
            assert!(output.contains("call_1"));
        }
    }

    #[test]
    fn chat_parallel_tools_and_usage_before_done() {
        let mut t = StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        let chunks = vec![
            json!({"id":"c","choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"a","type":"function","function":{"name":"f","arguments":"{\"x\":"}},{"index":1,"id":"b","type":"function","function":{"name":"g","arguments":"{"}}]},"finish_reason":null}]}),
            json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"}"}},{"index":0,"function":{"arguments":"1}"}}]},"finish_reason":null}]}),
            json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}),
            json!({"choices":[],"usage":{"prompt_tokens":9,"completion_tokens":7}}),
        ];
        let mut output = String::new();
        for value in chunks {
            output.push_str(&joined(
                t.push(format!("data: {value}\n\n").as_bytes()).unwrap(),
            ));
        }
        assert!(!output.contains("message_stop"));
        output.push_str(&joined(t.push(b"data: [DONE]\n\n").unwrap()));
        t.finish().unwrap();
        assert_eq!(
            anthropic_blocks(&output),
            vec![
                json!({"type":"tool_use","id":"a","name":"f","input":{"x":1}}),
                json!({"type":"tool_use","id":"b","name":"g","input":{}}),
            ]
        );
        let usage = events(&output)
            .into_iter()
            .find(|v| v["type"] == "message_delta")
            .unwrap()["usage"]
            .clone();
        assert_eq!(usage["input_tokens"], 9);
        assert_eq!(usage["output_tokens"], 7);
    }
    #[test]
    fn anthropic_text_to_chat_and_truncation() {
        let mut t = StreamTranslator::new(Protocol::Anthropic, Protocol::Chat, "x".into(), true);
        let output=t.push(&frame("message_start",json!({"type":"message_start","message":{"id":"m","content":[],"usage":{"input_tokens":3,"output_tokens":0}}}))).unwrap();
        assert!(joined(output).contains("chat.completion.chunk"));
        t.push(&frame("content_block_start",json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}))).unwrap();
        let out=t.push(&frame("content_block_delta",json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}))).unwrap();
        assert!(joined(out).contains("hello"));
        assert!(t.finish().is_err());
    }
    #[test]
    fn anthropic_late_refusal_fails_after_immediate_chat_text_without_success() {
        let start = frame(
            "message_start",
            json!({"type":"message_start","message":{"id":"m","content":[],"usage":{}}}),
        );
        let block_start = frame(
            "content_block_start",
            json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        );
        let delta = frame(
            "content_block_delta",
            json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}),
        );
        let block_stop = frame(
            "content_block_stop",
            json!({"type":"content_block_stop","index":0}),
        );

        let mut refusal =
            StreamTranslator::new(Protocol::Anthropic, Protocol::Chat, "x".into(), true);
        refusal.push(&start).unwrap();
        refusal.push(&block_start).unwrap();
        let early = joined(refusal.push(&delta).unwrap());
        assert!(early.contains("\"content\":\"hello\""));
        assert!(!early.contains("[DONE]"));
        refusal.push(&block_stop).unwrap();
        let error = refusal
            .push(&frame(
                "message_delta",
                json!({"type":"message_delta","delta":{"stop_reason":"refusal"},"usage":{}}),
            ))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("already streamed as Chat content")
        );

        let mut normal =
            StreamTranslator::new(Protocol::Anthropic, Protocol::Chat, "x".into(), true);
        normal.push(&start).unwrap();
        normal.push(&block_start).unwrap();
        let early = joined(normal.push(&delta).unwrap());
        assert!(early.contains("\"content\":\"hello\""));
        normal.push(&block_stop).unwrap();
        normal
            .push(&frame(
                "message_delta",
                json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{}}),
            ))
            .unwrap();
        let terminal = joined(
            normal
                .push(&frame("message_stop", json!({"type":"message_stop"})))
                .unwrap(),
        );
        normal.finish().unwrap();
        assert!(terminal.contains("\"finish_reason\":\"stop\""));
        assert!(terminal.ends_with("data: [DONE]\n\n"));
    }
    #[test]
    fn stream_errors_are_not_successful_completion() {
        let mut t =
            StreamTranslator::new(Protocol::Responses, Protocol::Anthropic, "x".into(), true);
        let output=joined(t.push(&frame("response.failed",json!({"type":"response.failed","response":{"error":{"code":"rate_limit","message":"try later"}}}))).unwrap());
        assert!(output.contains("event: error"));
        assert!(!output.contains("message_stop"));
        t.finish().unwrap();
        assert!(t.upstream_failed());
    }
    #[test]
    fn completed_tool_headers_remain_bounded_across_blocks() {
        let mut translator =
            StreamTranslator::new(Protocol::Anthropic, Protocol::Chat, "x".into(), true);
        translator
            .push(&frame(
                "message_start",
                json!({"type":"message_start","message":{"id":"m","content":[],"usage":{}}}),
            ))
            .unwrap();
        let name = "n".repeat(MAX_PENDING / 4 - 16);
        for index in 0..4 {
            translator.push(&frame(
                "content_block_start",
                json!({"type":"content_block_start","index":index,"content_block":{"type":"tool_use","id":format!("t{index}"),"name":name,"input":{}}}),
            )).unwrap();
            translator
                .push(&frame(
                    "content_block_stop",
                    json!({"type":"content_block_stop","index":index}),
                ))
                .unwrap();
        }
        assert!(translator.push(&frame(
            "content_block_start",
            json!({"type":"content_block_start","index":4,"content_block":{"type":"tool_use","id":"t4","name":name,"input":{}}}),
        )).is_err());
    }

    #[test]
    fn retained_tool_headers_share_budget_with_arguments_and_blocked_text() {
        for blocked_text in [false, true] {
            let mut translator =
                StreamTranslator::new(Protocol::Responses, Protocol::Anthropic, "x".into(), true);
            translator.push(&frame(
                "response.output_item.added",
                json!({"type":"response.output_item.added","output_index":0,"item":{"type":"function_call","call_id":"a","name":"n".repeat(MAX_PENDING / 2),"arguments":""}}),
            )).unwrap();
            let value = if blocked_text {
                json!({"type":"response.output_text.delta","output_index":1,"content_index":0,"delta":"x".repeat(MAX_PENDING / 2)})
            } else {
                json!({"type":"response.function_call_arguments.delta","output_index":0,"delta":" ".repeat(MAX_PENDING / 2)})
            };
            let event = value["type"].as_str().unwrap().to_owned();
            assert!(translator.push(&frame(&event, value)).is_err());
        }
    }

    #[test]
    fn fragmented_tool_headers_share_budget_across_tools() {
        let mut translator =
            StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        let name = "n".repeat(MAX_PENDING / 3);
        for index in 0..2 {
            translator.push(&chat_frame(
                json!({"tool_calls":[{"index":index,"id":format!("t{index}"),"type":"function","function":{"name":name,"arguments":""}}]}),
                Value::Null,
            )).unwrap();
        }
        assert!(
            translator
                .push(&chat_frame(
                    json!({"tool_calls":[{"index":1,"function":{"name":name}}]}),
                    Value::Null,
                ))
                .is_err()
        );
    }

    #[test]
    fn oversized_pending_frame_rejected() {
        let mut t = StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        assert!(t.push(&vec![b'x'; MAX_PENDING + 1]).is_err());
    }
    #[test]
    fn multiline_sse_and_cr_line_endings() {
        let mut p = Sse::default();
        let mut result = None;
        for byte in b"event: x\rdata: {\rdata: \"x\":1}\r\r" {
            if let Some(f) = p.byte(*byte).unwrap() {
                result = Some(f);
            }
        }
        let result = result.unwrap();
        assert_eq!(result.event, "x");
        assert_eq!(
            serde_json::from_slice::<Value>(&result.data).unwrap(),
            json!({"x":1})
        );
    }
    #[test]
    fn responses_stream_rejects_non_null_phase_on_every_message_snapshot() {
        for target in [Protocol::Chat, Protocol::Anthropic] {
            for phase in [
                json!("commentary"),
                json!("final_answer"),
                json!(""),
                json!(false),
                json!(42),
                json!([]),
                json!({}),
            ] {
                for event in [
                    "response.output_item.added",
                    "response.output_item.done",
                    "response.completed",
                    "response.incomplete",
                ] {
                    let mut translator =
                        StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
                    let message = json!({"type":"message","role":"assistant","phase":phase,"content":[{"type":"output_text","text":"hidden"}]});
                    let value = if event.starts_with("response.output_item.") {
                        json!({"type":event,"output_index":0,"item":message})
                    } else {
                        let status = event.strip_prefix("response.").unwrap();
                        json!({"type":event,"response":{"status":status,"output":[message],"incomplete_details":{"reason":"max_output_tokens"}}})
                    };
                    assert!(translator.push(&frame(event, value)).is_err());
                    assert!(translator.finish().is_err());
                    assert!(translator.push(&frame("response.completed", json!({"type":"response.completed","response":{"status":"completed","output":[]}}))).is_err());
                }
            }
        }
    }

    #[test]
    fn responses_stream_absent_or_null_phase_succeeds() {
        for target in [Protocol::Chat, Protocol::Anthropic] {
            for explicit_null in [false, true] {
                let mut translator =
                    StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
                let mut message = json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]});
                if explicit_null {
                    message["phase"] = Value::Null;
                }
                let mut output = joined(translator.push(&frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":message}))).unwrap());
                output.push_str(&joined(translator.push(&frame("response.output_item.done", json!({"type":"response.output_item.done","output_index":0,"item":message}))).unwrap()));
                output.push_str(&joined(translator.push(&frame("response.completed", json!({"type":"response.completed","response":{"status":"completed","output":[message]}}))).unwrap()));
                translator.finish().unwrap();
                match target {
                    Protocol::Chat => {
                        let text: String = events(&output)
                            .iter()
                            .filter_map(|event| {
                                event
                                    .pointer("/choices/0/delta/content")
                                    .and_then(Value::as_str)
                            })
                            .collect();
                        assert_eq!(text, "hello");
                        assert!(output.ends_with("data: [DONE]\n\n"));
                    }
                    Protocol::Anthropic => {
                        assert_eq!(
                            anthropic_blocks(&output),
                            json!([{"type":"text","text":"hello"}])
                                .as_array()
                                .unwrap()
                                .to_vec()
                        );
                        assert!(output.contains("message_stop"));
                    }
                    _ => unreachable!(),
                }
            }
        }
    }

    #[test]
    fn responses_stream_late_phase_fails_after_text_without_success_terminal() {
        for target in [Protocol::Chat, Protocol::Anthropic] {
            for event in [
                "response.output_item.done",
                "response.completed",
                "response.incomplete",
            ] {
                let mut translator =
                    StreamTranslator::new(Protocol::Responses, target, "x".into(), true);
                translator.push(&frame("response.output_item.added", json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}}))).unwrap();
                let output = joined(translator.push(&frame("response.output_text.delta", json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"visible"}))).unwrap());
                assert!(output.contains("visible"));
                assert!(!output.contains("[DONE]"));
                assert!(!output.contains("message_stop"));
                let message = json!({"type":"message","role":"assistant","phase":"final_answer","content":[{"type":"output_text","text":"visible"}]});
                let value = if event == "response.output_item.done" {
                    json!({"type":event,"output_index":0,"item":message})
                } else {
                    json!({"type":event,"response":{"status":event.strip_prefix("response.").unwrap(),"output":[message],"incomplete_details":{"reason":"max_output_tokens"}}})
                };
                assert!(translator.push(&frame(event, value)).is_err());
                assert!(translator.finish().is_err());
            }
        }
    }

    #[test]
    fn responses_text_to_chat_at_arbitrary_boundaries() {
        let text = "hello café";
        let message = json!({"type":"message","role":"assistant","content":[{"type":"output_text","text":text,"annotations":[]}]});
        let stream=[
            frame("response.created",json!({"type":"response.created","response":{"id":"r"}})),
            frame("response.output_item.added",json!({"type":"response.output_item.added","output_index":0,"item":{"type":"message","role":"assistant","content":[]}})),
            frame("response.content_part.added",json!({"type":"response.content_part.added","output_index":0,"content_index":0,"part":{"type":"output_text","text":"","annotations":[]}})),
            frame("response.output_text.delta",json!({"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":text})),
            frame("response.output_text.done",json!({"type":"response.output_text.done","output_index":0,"content_index":0,"text":text})),
            frame("response.content_part.done",json!({"type":"response.content_part.done","output_index":0,"content_index":0,"part":{"type":"output_text","text":text,"annotations":[]}})),
            frame("response.output_item.done",json!({"type":"response.output_item.done","output_index":0,"item":message})),
            frame("response.completed",json!({"type":"response.completed","response":{"status":"completed","output":[message],"usage":{"input_tokens":4,"output_tokens":2}}})),
        ].concat();
        for size in [1, 2, 7, 19, 1024] {
            let mut t =
                StreamTranslator::new(Protocol::Responses, Protocol::Chat, "x".into(), true);
            let mut out = String::new();
            for chunk in stream.chunks(size) {
                out.push_str(&joined(t.push(chunk).unwrap()));
            }
            t.finish().unwrap();
            assert!(out.contains(text));
            assert!(out.ends_with("data: [DONE]\n\n"));
            assert!(out.contains("\"completion_tokens\":2"));
        }
    }
    #[test]
    fn anthropic_tool_arguments_are_streamed_and_closed() {
        let mut t = StreamTranslator::new(Protocol::Anthropic, Protocol::Chat, "x".into(), true);
        t.push(&frame("message_start",json!({"type":"message_start","message":{"id":"m","content":[],"usage":{"input_tokens":3,"output_tokens":0}}}))).unwrap();
        let header=joined(t.push(&frame("content_block_start",json!({"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"a","name":"f","input":{}}}))).unwrap());
        assert!(header.contains("\"name\":\"f\""));
        let delta=joined(t.push(&frame("content_block_delta",json!({"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\"x\":1}"}}))).unwrap());
        assert!(delta.contains("arguments"));
        t.push(&frame(
            "content_block_stop",
            json!({"type":"content_block_stop","index":0}),
        ))
        .unwrap();
        t.push(&frame("message_delta",json!({"type":"message_delta","delta":{"stop_reason":"tool_use","stop_sequence":null},"usage":{"output_tokens":4}}))).unwrap();
        let end = joined(
            t.push(&frame("message_stop", json!({"type":"message_stop"})))
                .unwrap(),
        );
        assert!(end.contains("\"finish_reason\":\"tool_calls\""));
        assert!(end.contains("\"completion_tokens\":4"));
        t.finish().unwrap();
    }
    #[test]
    fn terminal_without_frame_delimiter_is_truncated() {
        let mut t = StreamTranslator::new(Protocol::Chat, Protocol::Anthropic, "x".into(), true);
        t.push(b"data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n")
            .unwrap();
        t.push(b"data: [DONE]").unwrap();
        assert!(t.finish().is_err());
    }
}
