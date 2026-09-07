//! JSON-RPC 2.0 message classification.
//!
//! MCP over stdio is a stream of newline-delimited JSON-RPC 2.0 messages
//! (spec: "messages are delimited by newlines, and MUST NOT contain
//! embedded newlines"). Each message is a request, a response, or a
//! notification. Phase A parses only far enough to classify and log;
//! Phase B hangs policy off `method` + `Direction`.

use serde_json::Value;

/// Which way a message is travelling through the proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// From the agent (MCP client) toward the server.
    ClientToServer,
    /// From the server back toward the agent.
    ServerToClient,
}

impl Direction {
    pub fn tag(self) -> &'static str {
        match self {
            Direction::ClientToServer => "c2s",
            Direction::ServerToClient => "s2c",
        }
    }
}

/// A classified JSON-RPC message. Borrows from the parsed `Value`.
#[derive(Debug)]
pub enum Rpc<'a> {
    /// Has both `method` and `id` — expects a response.
    Request { id: &'a Value, method: &'a str },
    /// Has `id` and `result` or `error` — answers a request.
    Response { id: &'a Value, is_error: bool },
    /// Has `method` but no `id` — fire-and-forget.
    Notification { method: &'a str },
    /// A JSON value that isn't a recognisable JSON-RPC message (a batch
    /// array, a bare value, a startup banner some servers wrongly emit on
    /// stdout). Forwarded verbatim; never policed.
    Other,
}

impl<'a> Rpc<'a> {
    pub fn classify(v: &'a Value) -> Rpc<'a> {
        let Some(obj) = v.as_object() else {
            return Rpc::Other;
        };
        let method = obj.get("method").and_then(Value::as_str);
        let id = obj.get("id");
        match (method, id) {
            (Some(method), Some(id)) => Rpc::Request { id, method },
            (Some(method), None) => Rpc::Notification { method },
            (None, Some(id)) => Rpc::Response {
                id,
                is_error: obj.contains_key("error"),
            },
            (None, None) => Rpc::Other,
        }
    }

    /// Short kind label for the transcript log.
    pub fn kind(&self) -> &'static str {
        match self {
            Rpc::Request { .. } => "request",
            Rpc::Response { is_error: false, .. } => "response",
            Rpc::Response { is_error: true, .. } => "error",
            Rpc::Notification { .. } => "notification",
            Rpc::Other => "other",
        }
    }

    pub fn method(&self) -> Option<&str> {
        match self {
            Rpc::Request { method, .. } | Rpc::Notification { method } => Some(method),
            _ => None,
        }
    }

    pub fn id(&self) -> Option<&Value> {
        match self {
            Rpc::Request { id, .. } | Rpc::Response { id, .. } => Some(id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn classifies_a_request() {
        let v = json!({"jsonrpc":"2.0","id":1,"method":"tools/list"});
        match Rpc::classify(&v) {
            Rpc::Request { method, id } => {
                assert_eq!(method, "tools/list");
                assert_eq!(id, &json!(1));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn classifies_a_notification() {
        let v = json!({"jsonrpc":"2.0","method":"notifications/tools/list_changed"});
        assert!(matches!(Rpc::classify(&v), Rpc::Notification { method } if method == "notifications/tools/list_changed"));
    }

    #[test]
    fn classifies_a_result_and_an_error_response() {
        let ok = json!({"jsonrpc":"2.0","id":2,"result":{"tools":[]}});
        assert!(matches!(Rpc::classify(&ok), Rpc::Response { is_error: false, .. }));
        let err = json!({"jsonrpc":"2.0","id":2,"error":{"code":-32601,"message":"nope"}});
        assert!(matches!(Rpc::classify(&err), Rpc::Response { is_error: true, .. }));
    }

    #[test]
    fn a_bare_value_or_batch_is_other() {
        assert!(matches!(Rpc::classify(&json!(42)), Rpc::Other));
        assert!(matches!(Rpc::classify(&json!([{"id":1,"method":"x"}])), Rpc::Other));
    }
}
