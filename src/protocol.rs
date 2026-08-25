//! NDJSON protocol message types for daemon–client communication.
//!
//! This module defines the wire format for all messages exchanged between the
//! Airlock daemon and its CLI client over a Unix domain socket. The protocol
//! uses newline-delimited JSON (NDJSON): each message is a single line of valid
//! JSON terminated by a newline character.
//!
//! Two distinct enum families are provided:
//!
//! - [`ClientMessage`] — messages sent from the client to the daemon.
//! - [`DaemonMessage`] — messages sent from the daemon to the client.
//!
//! Keeping these as separate types ensures that each side of the socket only
//! sends one family and receives the other, enforced at compile time.
//!
//! All types derive [`serde::Serialize`] and [`serde::Deserialize`] with an
//! internally-tagged representation (`"type"` field) so the receiver can
//! determine which variant it received from a single JSON object.

use serde::{Deserialize, Serialize};

// ─── Client-to-daemon messages ───────────────────────────────────────────────

/// A message sent from the client to the daemon.
///
/// Each variant is serialized as a JSON object with a `"type"` discriminator
/// field. For example, an `Exec` message serializes as:
///
/// ```json
/// {"type":"exec","tool":"grep","args":["pattern","file.txt"],"cwd":"/home/user/project"}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    /// Request tool execution.
    ///
    /// Carries the tool name, argument list, and working directory path for the
    /// child process.
    Exec {
        /// The bare tool name as declared in `airlock.toml` (e.g., `"grep"`).
        tool: String,
        /// Arguments to pass to the tool.
        args: Vec<String>,
        /// The client's working directory, sent as an absolute path string.
        cwd: String,
    },

    /// A chunk of stdin data to forward to the running child process.
    Stdin {
        /// The data chunk, encoded as a UTF-8 string.
        data: String,
    },

    /// Signals that the client has closed its stdin stream.
    ///
    /// After receiving this message, the daemon closes the child's stdin pipe.
    StdinEof,

    /// Requests the daemon's ring-buffer log entries.
    Logs,
}

// ─── Daemon-to-client messages ───────────────────────────────────────────────

/// A message sent from the daemon to the client.
///
/// Each variant is serialized as a JSON object with a `"type"` discriminator
/// field. For example, a `Stdout` message serializes as:
///
/// ```json
/// {"type":"stdout","data":"hello world\n"}
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DaemonMessage {
    /// A chunk of stdout output from the child process (after redaction).
    Stdout {
        /// The redacted output data.
        data: String,
    },

    /// A chunk of stderr output from the child process (after redaction).
    Stderr {
        /// The redacted error output data.
        data: String,
    },

    /// The child process has exited.
    Exit {
        /// The child's exit code. Conventionally 0 for success.
        code: i32,
    },

    /// An error occurred on the daemon side.
    ///
    /// Sent when the daemon cannot fulfil a request (unknown tool, CWD outside
    /// sandbox root, spawn failure, timeout, etc.). The client should print the
    /// message to stderr and exit with a non-zero status.
    Error {
        /// A human-readable error description.
        message: String,
    },

    /// Response to a [`ClientMessage::Logs`] request.
    ///
    /// Contains the current contents of the daemon's ring-buffer log.
    LogsResponse {
        /// The log entries, ordered from oldest to newest.
        entries: Vec<LogEntry>,
    },
}

// ─── Log entry ───────────────────────────────────────────────────────────────

/// A single entry in the daemon's ring-buffer log.
///
/// Used inside [`DaemonMessage::LogsResponse`] and also stored internally by
/// the daemon's ring buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEntry {
    /// A human-readable timestamp string (e.g., ISO 8601 format).
    pub timestamp: String,
    /// The log message.
    pub message: String,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Serialize a value to a single-line JSON string and verify it contains
    /// no embedded newlines.
    fn to_json_line<T: Serialize>(value: &T) -> String {
        let json = serde_json::to_string(value).expect("serialization failed");
        assert!(
            !json.contains('\n'),
            "serialized JSON must not contain embedded newlines: {json}"
        );
        json
    }

    /// Round-trip a value through JSON serialization and deserialization,
    /// asserting equality.
    fn round_trip<T>(value: &T)
    where
        T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug,
    {
        let json = to_json_line(value);
        let recovered: T = serde_json::from_str(&json).expect("deserialization failed");
        assert_eq!(value, &recovered);
    }

    // ── ClientMessage round-trip tests ──────────────────────────────────

    #[test]
    fn client_exec_round_trip() {
        let msg = ClientMessage::Exec {
            tool: "grep".to_string(),
            args: vec!["-r".to_string(), "pattern".to_string(), "src/".to_string()],
            cwd: "/home/user/project".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn client_stdin_round_trip() {
        let msg = ClientMessage::Stdin {
            data: "hello world\n".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn client_stdin_eof_round_trip() {
        let msg = ClientMessage::StdinEof;
        round_trip(&msg);
    }

    #[test]
    fn client_logs_round_trip() {
        let msg = ClientMessage::Logs;
        round_trip(&msg);
    }

    // ── DaemonMessage round-trip tests ──────────────────────────────────

    #[test]
    fn daemon_stdout_round_trip() {
        let msg = DaemonMessage::Stdout {
            data: "output line\n".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn daemon_stderr_round_trip() {
        let msg = DaemonMessage::Stderr {
            data: "warning: something\n".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn daemon_exit_round_trip() {
        let msg = DaemonMessage::Exit { code: 0 };
        round_trip(&msg);

        // Also test non-zero exit codes.
        let msg_fail = DaemonMessage::Exit { code: 127 };
        round_trip(&msg_fail);

        // Negative exit code (signal-killed processes).
        let msg_signal = DaemonMessage::Exit { code: -9 };
        round_trip(&msg_signal);
    }

    #[test]
    fn daemon_error_round_trip() {
        let msg = DaemonMessage::Error {
            message: "unknown tool: foobar".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn daemon_logs_response_round_trip() {
        let msg = DaemonMessage::LogsResponse {
            entries: vec![
                LogEntry {
                    timestamp: "2025-01-15T10:30:00Z".to_string(),
                    message: "daemon started".to_string(),
                },
                LogEntry {
                    timestamp: "2025-01-15T10:30:05Z".to_string(),
                    message: "connection accepted".to_string(),
                },
            ],
        };
        round_trip(&msg);
    }

    #[test]
    fn daemon_logs_response_empty_entries_round_trip() {
        let msg = DaemonMessage::LogsResponse { entries: vec![] };
        round_trip(&msg);
    }

    // ── LogEntry round-trip ─────────────────────────────────────────────

    #[test]
    fn log_entry_round_trip() {
        let entry = LogEntry {
            timestamp: "2025-01-15T10:30:00Z".to_string(),
            message: "something happened".to_string(),
        };
        round_trip(&entry);
    }

    // ── Type discriminator tests ────────────────────────────────────────

    #[test]
    fn client_message_has_type_discriminator() {
        let msg = ClientMessage::Exec {
            tool: "cat".to_string(),
            args: vec![],
            cwd: "/tmp".to_string(),
        };
        let json = to_json_line(&msg);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "exec");
    }

    #[test]
    fn daemon_message_has_type_discriminator() {
        let msg = DaemonMessage::Stdout {
            data: "hi".to_string(),
        };
        let json = to_json_line(&msg);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "stdout");
    }

    #[test]
    fn stdin_eof_type_tag() {
        let json = to_json_line(&ClientMessage::StdinEof);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "stdin_eof");
    }

    #[test]
    fn logs_type_tag() {
        let json = to_json_line(&ClientMessage::Logs);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "logs");
    }

    #[test]
    fn logs_response_type_tag() {
        let msg = DaemonMessage::LogsResponse { entries: vec![] };
        let json = to_json_line(&msg);
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "logs_response");
    }

    // ── Unknown type tag produces deserialization error ──────────────────

    #[test]
    fn unknown_client_message_type_is_error() {
        let json = r#"{"type":"unknown_command","data":"foo"}"#;
        let result = serde_json::from_str::<ClientMessage>(json);
        assert!(
            result.is_err(),
            "deserializing an unknown client message type must fail"
        );
    }

    #[test]
    fn unknown_daemon_message_type_is_error() {
        let json = r#"{"type":"unknown_response","data":"bar"}"#;
        let result = serde_json::from_str::<DaemonMessage>(json);
        assert!(
            result.is_err(),
            "deserializing an unknown daemon message type must fail"
        );
    }

    // ── Empty string fields round-trip correctly ────────────────────────

    #[test]
    fn client_exec_empty_strings_round_trip() {
        let msg = ClientMessage::Exec {
            tool: "".to_string(),
            args: vec!["".to_string(), "".to_string()],
            cwd: "".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn client_stdin_empty_data_round_trip() {
        let msg = ClientMessage::Stdin {
            data: "".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn daemon_stdout_empty_data_round_trip() {
        let msg = DaemonMessage::Stdout {
            data: "".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn daemon_stderr_empty_data_round_trip() {
        let msg = DaemonMessage::Stderr {
            data: "".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn daemon_error_empty_message_round_trip() {
        let msg = DaemonMessage::Error {
            message: "".to_string(),
        };
        round_trip(&msg);
    }

    #[test]
    fn log_entry_empty_fields_round_trip() {
        let entry = LogEntry {
            timestamp: "".to_string(),
            message: "".to_string(),
        };
        round_trip(&entry);
    }

    // ── No embedded newlines in serialized output ───────────────────────

    #[test]
    fn no_embedded_newlines_in_any_variant() {
        // Client messages
        let client_msgs: Vec<ClientMessage> = vec![
            ClientMessage::Exec {
                tool: "tool".to_string(),
                args: vec!["a".to_string()],
                cwd: "/tmp".to_string(),
            },
            ClientMessage::Stdin {
                data: "line\n".to_string(),
            },
            ClientMessage::StdinEof,
            ClientMessage::Logs,
        ];
        for msg in &client_msgs {
            to_json_line(msg); // asserts no newlines internally
        }

        // Daemon messages
        let daemon_msgs: Vec<DaemonMessage> = vec![
            DaemonMessage::Stdout {
                data: "out\n".to_string(),
            },
            DaemonMessage::Stderr {
                data: "err\n".to_string(),
            },
            DaemonMessage::Exit { code: 1 },
            DaemonMessage::Error {
                message: "oops".to_string(),
            },
            DaemonMessage::LogsResponse {
                entries: vec![LogEntry {
                    timestamp: "t".to_string(),
                    message: "m".to_string(),
                }],
            },
        ];
        for msg in &daemon_msgs {
            to_json_line(msg); // asserts no newlines internally
        }
    }

    // ── Exec args with empty vec ────────────────────────────────────────

    #[test]
    fn client_exec_empty_args_round_trip() {
        let msg = ClientMessage::Exec {
            tool: "ls".to_string(),
            args: vec![],
            cwd: "/".to_string(),
        };
        round_trip(&msg);
    }
}
