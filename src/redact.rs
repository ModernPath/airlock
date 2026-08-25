//! Output redaction via Aho-Corasick streaming replacement.
//!
//! This module builds an Aho-Corasick automaton from secret values (with four
//! encoding variants per secret) and provides scanning functions that replace
//! secret occurrences in child output with `[REDACTED:name]` placeholders.
//!
//! # Encoding variants
//!
//! For each secret value, four search patterns are generated:
//! 1. **Raw** — the secret value as-is (UTF-8 bytes)
//! 2. **Base64** — standard alphabet with padding
//! 3. **URL-encoded** — percent-encoded
//! 4. **Hex** — lowercase hex, no separators
//!
//! # Scanning
//!
//! The scanner operates on raw bytes (not strings) using the aho-corasick
//! crate's streaming replacement capability. The daemon's async-to-sync
//! bridging is handled at the daemon layer, not inside this module.
//!
//! After redaction, lossy UTF-8 conversion produces valid UTF-8 strings
//! suitable for NDJSON serialization.

use std::io;
use std::sync::Arc;

use aho_corasick::AhoCorasick;
use base64::Engine;
use thiserror::Error;

use crate::secrets::Secret;

// ─── Error type ───────────────────────────────────────────────────────────────

/// Errors that can occur during redaction automaton construction.
#[derive(Debug, Error)]
pub enum RedactError {
    /// Failed to build the Aho-Corasick automaton from the provided patterns.
    #[error("failed to build redaction automaton: {0}")]
    AutomatonBuildError(String),
}

// ─── Encoding helpers ─────────────────────────────────────────────────────────

/// Encode a secret value as base64 using the STANDARD alphabet with padding.
fn encode_base64(value: &str) -> String {
    base64::engine::general_purpose::STANDARD.encode(value.as_bytes())
}

/// Encode a secret value as percent-encoded (URL-encoded).
fn encode_url(value: &str) -> String {
    percent_encoding::utf8_percent_encode(value, percent_encoding::NON_ALPHANUMERIC).to_string()
}

/// Encode a secret value as lowercase hexadecimal, no separators.
fn encode_hex(value: &str) -> String {
    value
        .as_bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Push the four encoding-variant patterns for a single (name, value) pair.
/// Empty values are skipped (they would match everywhere).
fn push_patterns_for_value(
    patterns: &mut Vec<Vec<u8>>,
    replacements: &mut Vec<String>,
    name: &str,
    value: &str,
) {
    if value.is_empty() {
        return;
    }
    let replacement = format!("[REDACTED:{name}]");

    patterns.push(value.as_bytes().to_vec());
    replacements.push(replacement.clone());

    patterns.push(encode_base64(value).into_bytes());
    replacements.push(replacement.clone());

    patterns.push(encode_url(value).into_bytes());
    replacements.push(replacement.clone());

    patterns.push(encode_hex(value).into_bytes());
    replacements.push(replacement);
}

/// Build a [`Redactor`] from accumulated `(pattern, replacement)` pairs.
fn finalize(patterns: Vec<Vec<u8>>, replacements: Vec<String>) -> Result<Redactor, RedactError> {
    if patterns.is_empty() {
        return Ok(Redactor {
            automaton: None,
            replacements: Vec::new(),
        });
    }
    let automaton =
        AhoCorasick::new(&patterns).map_err(|e| RedactError::AutomatonBuildError(e.to_string()))?;
    Ok(Redactor {
        automaton: Some(automaton),
        replacements,
    })
}

// ─── Redactor ─────────────────────────────────────────────────────────────────

/// A redaction scanner backed by an Aho-Corasick automaton.
///
/// The scanner replaces all occurrences of secret encoding variants with
/// `[REDACTED:name]` placeholders. It operates on raw bytes and supports
/// streaming replacement via `Read`/`Write` traits.
pub struct Redactor {
    /// The Aho-Corasick automaton, or `None` if there are no patterns.
    automaton: Option<AhoCorasick>,
    /// Replacement strings indexed in parallel with the automaton's patterns.
    replacements: Vec<String>,
}

impl Redactor {
    /// Build a new redactor from a collection of secret name-value pairs.
    ///
    /// For each secret, four encoding variants are generated as search patterns.
    /// An empty collection produces a valid pass-through scanner.
    ///
    /// # Arguments
    ///
    /// * `secrets` — An iterator yielding `(name, &Secret<String>)` pairs.
    ///
    /// # Errors
    ///
    /// Returns [`RedactError::AutomatonBuildError`] if the Aho-Corasick
    /// automaton cannot be constructed from the patterns.
    pub fn new<'a>(
        secrets: impl IntoIterator<Item = (&'a str, &'a Secret<String>)>,
    ) -> Result<Self, RedactError> {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut replacements: Vec<String> = Vec::new();

        for (name, secret) in secrets {
            push_patterns_for_value(
                &mut patterns,
                &mut replacements,
                name,
                secret.expose_secret(),
            );
        }

        finalize(patterns, replacements)
    }

    /// Build a redactor that covers multiple value generations per secret.
    ///
    /// The refresh task uses this to keep the previous value's patterns alive
    /// for one cycle after a swap, so output captured just before the swap
    /// (still flowing through pipes) continues to be redacted. Empty
    /// generation slices are tolerated.
    pub fn build_from_generations<'a, I>(generations: I) -> Result<Self, RedactError>
    where
        I: IntoIterator<Item = (&'a str, &'a [Arc<Secret<String>>])>,
    {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut replacements: Vec<String> = Vec::new();

        for (name, gens) in generations {
            for secret in gens {
                push_patterns_for_value(
                    &mut patterns,
                    &mut replacements,
                    name,
                    secret.expose_secret(),
                );
            }
        }

        finalize(patterns, replacements)
    }

    /// Scan raw bytes and replace all secret occurrences with placeholders.
    ///
    /// Returns the redacted bytes. This is a non-streaming (single-shot)
    /// replacement suitable for processing complete chunks.
    pub fn redact_bytes(&self, input: &[u8]) -> Vec<u8> {
        match &self.automaton {
            Some(automaton) => {
                let replacement_bytes: Vec<&[u8]> =
                    self.replacements.iter().map(|r| r.as_bytes()).collect();
                automaton.replace_all_bytes(input, &replacement_bytes)
            }
            None => input.to_vec(),
        }
    }

    /// Stream redacted output from a reader to a writer.
    ///
    /// Reads from `reader`, replaces all secret occurrences with their
    /// corresponding `[REDACTED:name]` placeholders, and writes the result
    /// to `writer`. Uses the aho-corasick crate's `try_stream_replace_all`,
    /// which handles partial matches at chunk boundaries via internal buffering.
    ///
    /// The scanner operates on raw bytes — the daemon is responsible for any
    /// UTF-8 conversion after the redacted output is collected.
    ///
    /// For an empty scanner (no secrets), data is copied directly from reader
    /// to writer without modification.
    pub fn redact_stream<R: io::Read, W: io::Write>(&self, reader: R, writer: W) -> io::Result<()> {
        match &self.automaton {
            Some(automaton) => {
                let replacement_bytes: Vec<&[u8]> =
                    self.replacements.iter().map(|r| r.as_bytes()).collect();
                automaton.try_stream_replace_all(reader, writer, &replacement_bytes)
            }
            None => {
                let mut reader = reader;
                let mut writer = writer;
                io::copy(&mut reader, &mut writer)?;
                Ok(())
            }
        }
    }

    /// Returns the number of patterns in the automaton.
    ///
    /// Useful for testing that all encoding variants are present.
    pub fn pattern_count(&self) -> usize {
        match &self.automaton {
            Some(automaton) => automaton.patterns_len(),
            None => 0,
        }
    }
}

// ─── Lossy UTF-8 conversion ──────────────────────────────────────────────────

/// Convert raw bytes to a valid UTF-8 string using lossy conversion.
///
/// Invalid byte sequences are replaced with the Unicode replacement character
/// (U+FFFD). This conversion is applied after redaction (so the automaton
/// operates on raw bytes) but before NDJSON serialization (so the JSON
/// contains valid UTF-8 strings).
pub fn bytes_to_lossy_utf8(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    use crate::secrets::Secret;

    // ── Encoding helper tests ─────────────────────────────────────────────

    #[test]
    fn encode_base64_standard_alphabet() {
        assert_eq!(encode_base64("hello"), "aGVsbG8=");
        assert_eq!(
            encode_base64("secret-value-123"),
            "c2VjcmV0LXZhbHVlLTEyMw=="
        );
    }

    #[test]
    fn encode_url_percent_encodes() {
        assert_eq!(encode_url("hello world"), "hello%20world");
        assert_eq!(encode_url("key=value&foo=bar"), "key%3Dvalue%26foo%3Dbar");
    }

    #[test]
    fn encode_hex_lowercase_no_separator() {
        assert_eq!(encode_hex("AB"), "4142");
        assert_eq!(encode_hex("\x0a\x1b"), "0a1b");
        assert_eq!(encode_hex("hello"), "68656c6c6f");
    }

    // ── Multi-generation tests ────────────────────────────────────────────

    #[test]
    fn build_from_generations_redacts_both_old_and_new_values() {
        let prev = Arc::new(Secret::new("old-token".to_string()));
        let curr = Arc::new(Secret::new("new-token".to_string()));
        let gens = [("TOKEN", vec![Arc::clone(&curr), Arc::clone(&prev)])];
        let refs: Vec<(&str, &[Arc<Secret<String>>])> =
            gens.iter().map(|(n, v)| (*n, v.as_slice())).collect();
        let redactor = Redactor::build_from_generations(refs).unwrap();

        let out = redactor.redact_bytes(b"saw old-token then new-token");
        let s = String::from_utf8_lossy(&out);
        assert!(!s.contains("old-token"), "old value leaked: {s}");
        assert!(!s.contains("new-token"), "new value leaked: {s}");
        assert!(s.contains("[REDACTED:TOKEN]"));
    }

    #[test]
    fn build_from_generations_with_only_current_drops_previous_pattern() {
        let curr = Arc::new(Secret::new("new-token".to_string()));
        let gens = [("TOKEN", vec![Arc::clone(&curr)])];
        let refs: Vec<(&str, &[Arc<Secret<String>>])> =
            gens.iter().map(|(n, v)| (*n, v.as_slice())).collect();
        let redactor = Redactor::build_from_generations(refs).unwrap();

        let out = redactor.redact_bytes(b"saw old-token then new-token");
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("old-token"), "should NOT redact retired value");
        assert!(!s.contains("new-token"));
    }

    // ── Automaton construction tests ──────────────────────────────────────

    #[test]
    fn single_secret_four_variants() {
        let secret = Secret::new("mysecret".to_string());
        let redactor = Redactor::new([("API_KEY", &secret)]).unwrap();

        // 4 encoding variants for 1 secret.
        assert_eq!(
            redactor.pattern_count(),
            4,
            "should have 4 patterns (raw, base64, url, hex)"
        );
    }

    #[test]
    fn multiple_secrets_all_variants() {
        let secret1 = Secret::new("first-secret".to_string());
        let secret2 = Secret::new("second-secret".to_string());
        let redactor = Redactor::new([("SECRET_A", &secret1), ("SECRET_B", &secret2)]).unwrap();

        // 4 encoding variants * 2 secrets = 8 patterns.
        assert_eq!(
            redactor.pattern_count(),
            8,
            "should have 8 patterns (4 per secret * 2 secrets)"
        );
    }

    #[test]
    fn zero_secrets_pass_through() {
        let redactor = Redactor::new(std::iter::empty::<(&str, &Secret<String>)>()).unwrap();
        assert_eq!(redactor.pattern_count(), 0);

        let input = b"no secrets here";
        let output = redactor.redact_bytes(input);
        assert_eq!(output, input);
    }

    #[test]
    fn duplicate_values_no_construction_error() {
        let secret1 = Secret::new("same-value".to_string());
        let secret2 = Secret::new("same-value".to_string());
        let result = Redactor::new([("NAME_A", &secret1), ("NAME_B", &secret2)]);

        assert!(result.is_ok(), "duplicate values should not cause errors");
    }

    // ── Scanning: raw value redaction ─────────────────────────────────────

    #[test]
    fn raw_value_redacted() {
        let secret = Secret::new("my-api-key-123".to_string());
        let redactor = Redactor::new([("API_KEY", &secret)]).unwrap();

        let input = b"Authorization: Bearer my-api-key-123";
        let output = redactor.redact_bytes(input);
        let output_str = String::from_utf8(output).unwrap();

        assert!(
            output_str.contains("[REDACTED:API_KEY]"),
            "should contain redaction placeholder, got: {output_str}"
        );
        assert!(
            !output_str.contains("my-api-key-123"),
            "should not contain the raw secret, got: {output_str}"
        );
    }

    // ── Scanning: base64 value redacted ───────────────────────────────────

    #[test]
    fn base64_value_redacted() {
        let secret = Secret::new("my-api-key-123".to_string());
        let redactor = Redactor::new([("API_KEY", &secret)]).unwrap();

        let b64 = encode_base64("my-api-key-123");
        let input = format!("encoded: {b64}");
        let output = redactor.redact_bytes(input.as_bytes());
        let output_str = String::from_utf8(output).unwrap();

        assert!(
            output_str.contains("[REDACTED:API_KEY]"),
            "should redact base64 form, got: {output_str}"
        );
        assert!(
            !output_str.contains(&b64),
            "should not contain the base64 secret, got: {output_str}"
        );
    }

    // ── Scanning: URL-encoded value redacted ──────────────────────────────

    #[test]
    fn url_encoded_value_redacted() {
        let secret = Secret::new("my api key!".to_string());
        let redactor = Redactor::new([("API_KEY", &secret)]).unwrap();

        let url = encode_url("my api key!");
        let input = format!("param={url}");
        let output = redactor.redact_bytes(input.as_bytes());
        let output_str = String::from_utf8(output).unwrap();

        assert!(
            output_str.contains("[REDACTED:API_KEY]"),
            "should redact URL-encoded form, got: {output_str}"
        );
        assert!(
            !output_str.contains(&url),
            "should not contain the URL-encoded secret, got: {output_str}"
        );
    }

    // ── Scanning: hex-encoded value redacted ──────────────────────────────

    #[test]
    fn hex_encoded_value_redacted() {
        let secret = Secret::new("secret".to_string());
        let redactor = Redactor::new([("HEX_SECRET", &secret)]).unwrap();

        let hex = encode_hex("secret");
        let input = format!("hex: {hex}");
        let output = redactor.redact_bytes(input.as_bytes());
        let output_str = String::from_utf8(output).unwrap();

        assert!(
            output_str.contains("[REDACTED:HEX_SECRET]"),
            "should redact hex form, got: {output_str}"
        );
        assert!(
            !output_str.contains(&hex),
            "should not contain the hex secret, got: {output_str}"
        );
    }

    // ── Scanning: no secrets pass through ─────────────────────────────────

    #[test]
    fn no_secrets_pass_through() {
        let secret = Secret::new("supersecret".to_string());
        let redactor = Redactor::new([("KEY", &secret)]).unwrap();

        let input = b"this input contains no secret values at all";
        let output = redactor.redact_bytes(input);
        assert_eq!(
            output, input,
            "input with no secrets should pass through unchanged"
        );
    }

    // ── Scanning: partial match pass through ──────────────────────────────

    #[test]
    fn partial_match_unchanged() {
        let secret = Secret::new("complete-secret".to_string());
        let redactor = Redactor::new([("KEY", &secret)]).unwrap();

        let input = b"this has complete- but not the full secret";
        let output = redactor.redact_bytes(input);
        assert_eq!(output, input, "partial match should not trigger redaction");
    }

    // ── Scanning: multiple occurrences all replaced ───────────────────────

    #[test]
    fn multiple_occurrences_all_replaced() {
        let secret = Secret::new("token123".to_string());
        let redactor = Redactor::new([("TOKEN", &secret)]).unwrap();

        let input = b"first: token123, second: token123, third: token123";
        let output = redactor.redact_bytes(input);
        let output_str = String::from_utf8(output).unwrap();

        let count = output_str.matches("[REDACTED:TOKEN]").count();
        assert_eq!(
            count, 3,
            "all 3 occurrences should be redacted, got: {output_str}"
        );
        assert!(
            !output_str.contains("token123"),
            "no raw secret should remain, got: {output_str}"
        );
    }

    // ── Scanning: multiple different secrets all replaced ─────────────────

    #[test]
    fn multiple_different_secrets_replaced() {
        let secret1 = Secret::new("alpha-secret".to_string());
        let secret2 = Secret::new("beta-secret".to_string());
        let redactor = Redactor::new([("ALPHA", &secret1), ("BETA", &secret2)]).unwrap();

        let input = b"first: alpha-secret, second: beta-secret";
        let output = redactor.redact_bytes(input);
        let output_str = String::from_utf8(output).unwrap();

        assert!(
            output_str.contains("[REDACTED:ALPHA]"),
            "should redact ALPHA, got: {output_str}"
        );
        assert!(
            output_str.contains("[REDACTED:BETA]"),
            "should redact BETA, got: {output_str}"
        );
        assert!(
            !output_str.contains("alpha-secret"),
            "should not contain alpha-secret"
        );
        assert!(
            !output_str.contains("beta-secret"),
            "should not contain beta-secret"
        );
    }

    // ── Scanning: lossy UTF-8 conversion ──────────────────────────────────

    #[test]
    fn non_utf8_bytes_converted_to_replacement_char() {
        let secret = Secret::new("secret".to_string());
        let redactor = Redactor::new([("KEY", &secret)]).unwrap();

        // Build input with non-UTF-8 bytes that are NOT part of a secret.
        let mut input = Vec::new();
        input.extend_from_slice(b"before ");
        input.push(0xFF); // Invalid UTF-8 byte
        input.push(0xFE); // Invalid UTF-8 byte
        input.extend_from_slice(b" after");

        let output = redactor.redact_bytes(&input);
        let text = bytes_to_lossy_utf8(&output);

        // Non-UTF-8 bytes should become U+FFFD.
        assert!(
            text.contains('\u{FFFD}'),
            "non-UTF-8 bytes should become U+FFFD, got: {text}"
        );
        assert!(text.contains("before"));
        assert!(text.contains("after"));
    }

    #[test]
    fn secret_adjacent_to_non_utf8_bytes_still_redacted() {
        let secret = Secret::new("mysecret".to_string());
        let redactor = Redactor::new([("KEY", &secret)]).unwrap();

        // Build input: non-UTF-8 byte + secret + non-UTF-8 byte.
        let mut input = Vec::new();
        input.push(0xFF); // Invalid UTF-8 byte
        input.extend_from_slice(b"mysecret");
        input.push(0xFE); // Invalid UTF-8 byte

        let output = redactor.redact_bytes(&input);
        let text = bytes_to_lossy_utf8(&output);

        assert!(
            text.contains("[REDACTED:KEY]"),
            "secret adjacent to non-UTF-8 bytes should still be redacted, got: {text}"
        );
        assert!(
            text.contains('\u{FFFD}'),
            "non-UTF-8 bytes should become U+FFFD, got: {text}"
        );
    }

    // ── Streaming: Read/Write compatibility ───────────────────────────────

    #[test]
    fn streaming_redacts_raw_value() {
        let secret = Secret::new("stream-secret".to_string());
        let redactor = Redactor::new([("SKEY", &secret)]).unwrap();

        let input = b"data: stream-secret end";
        let reader = io::Cursor::new(input.to_vec());
        let mut output = Vec::new();

        redactor.redact_stream(reader, &mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert!(
            text.contains("[REDACTED:SKEY]"),
            "streaming should redact secrets, got: {text}"
        );
        assert!(
            !text.contains("stream-secret"),
            "streaming should not pass through secret, got: {text}"
        );
    }

    #[test]
    fn streaming_pass_through_no_secrets() {
        let redactor = Redactor::new(std::iter::empty::<(&str, &Secret<String>)>()).unwrap();

        let input = b"no secrets here at all";
        let reader = io::Cursor::new(input.to_vec());
        let mut output = Vec::new();

        redactor.redact_stream(reader, &mut output).unwrap();

        assert_eq!(
            output, input,
            "pass-through scanner should not modify input"
        );
    }

    #[test]
    fn streaming_handles_chunk_boundaries() {
        // Test that the streaming redactor handles secrets split across reads.
        // We simulate this with a reader that returns small chunks.
        let secret = Secret::new("chunked-secret".to_string());
        let redactor = Redactor::new([("CHUNK", &secret)]).unwrap();

        let input = b"prefix chunked-secret suffix";

        // SmallChunkReader returns one byte at a time, forcing the automaton
        // to handle partial matches across internal buffer boundaries.
        struct SmallChunkReader {
            data: Vec<u8>,
            pos: usize,
        }

        impl io::Read for SmallChunkReader {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.pos >= self.data.len() {
                    return Ok(0);
                }
                // Return at most 1 byte at a time.
                let n = 1.min(buf.len()).min(self.data.len() - self.pos);
                buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
                self.pos += n;
                Ok(n)
            }
        }

        let reader = SmallChunkReader {
            data: input.to_vec(),
            pos: 0,
        };

        let mut output = Vec::new();
        redactor.redact_stream(reader, &mut output).unwrap();

        let text = String::from_utf8(output).unwrap();
        assert!(
            text.contains("[REDACTED:CHUNK]"),
            "streaming should handle chunk boundaries, got: {text}"
        );
    }

    // ── Lossy UTF-8 conversion utility ────────────────────────────────────

    #[test]
    fn bytes_to_lossy_utf8_valid_utf8() {
        let result = bytes_to_lossy_utf8(b"hello world");
        assert_eq!(result, "hello world");
    }

    #[test]
    fn bytes_to_lossy_utf8_invalid_bytes() {
        let input = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0xFE, 0x21];
        let result = bytes_to_lossy_utf8(&input);
        assert!(result.contains("Hello"));
        assert!(result.contains('\u{FFFD}'));
        assert!(result.ends_with('!'));
    }

    #[test]
    fn bytes_to_lossy_utf8_empty() {
        let result = bytes_to_lossy_utf8(b"");
        assert_eq!(result, "");
    }

    // ── Error type tests ──────────────────────────────────────────────────

    #[test]
    fn redact_error_is_std_error() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<RedactError>();
    }

    #[test]
    fn redact_error_display() {
        let err = RedactError::AutomatonBuildError("test error".to_string());
        let msg = err.to_string();
        assert!(msg.contains("test error"));
        assert!(msg.contains("failed to build redaction automaton"));
    }
}
