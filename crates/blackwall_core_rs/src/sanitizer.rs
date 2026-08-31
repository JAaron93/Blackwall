use chrono::{SecondsFormat, Utc};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[pyclass(from_py_object)]
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct RedactionRecord {
    #[pyo3(get)]
    pub timestamp: String,
    #[pyo3(get)]
    pub original_hash: String,
    #[pyo3(get)]
    pub pattern_matched: String,
    #[pyo3(get)]
    pub placeholder_used: String,
    #[pyo3(get)]
    pub context_size: usize,
}

#[pymethods]
impl RedactionRecord {
    #[new]
    pub fn new(
        timestamp: String,
        original_hash: String,
        pattern_matched: String,
        placeholder_used: String,
        context_size: usize,
    ) -> Self {
        Self {
            timestamp,
            original_hash,
            pattern_matched,
            placeholder_used,
            context_size,
        }
    }

    pub fn to_dict(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("timestamp", &self.timestamp)?;
        dict.set_item("original_hash", &self.original_hash)?;
        dict.set_item("pattern_matched", &self.pattern_matched)?;
        dict.set_item("placeholder_used", &self.placeholder_used)?;
        dict.set_item("context_size", self.context_size)?;
        Ok(dict.unbind().into_any())
    }

    fn __repr__(&self) -> String {
        format!(
            "RedactionRecord(pattern='{}', placeholder='{}', hash='{}')",
            self.pattern_matched, self.placeholder_used, self.original_hash
        )
    }
}

pub struct PatternRule {
    pub name: String,
    pub regex: Regex,
    pub placeholder: String,
    pub enabled: bool,
}

#[pyclass]
pub struct ContextSanitizer {
    patterns: Vec<PatternRule>,
}

#[pymethods]
impl ContextSanitizer {
    #[new]
    #[pyo3(signature = (patterns=None))]
    pub fn new(patterns: Option<Vec<(String, String, String)>>) -> PyResult<Self> {
        let mut rules = Vec::new();
        match patterns {
            Some(custom_patterns) => {
                for (name, pat, placeholder) in custom_patterns {
                    let re = Regex::new(&pat).map_err(|e| {
                        PyValueError::new_err(format!("Invalid regex pattern '{}': {}", pat, e))
                    })?;
                    rules.push(PatternRule {
                        name,
                        regex: re,
                        placeholder,
                        enabled: true,
                    });
                }
            }
            None => {
                // Default patterns matching Blackwall defaults
                let defaults: Vec<(&str, &str, &str)> = vec![
                    (
                        "API_KEY",
                        r#"(?i)(api[_-]?key|apikey|token)[\s:=]+['"]?([a-zA-Z0-9_\-]{20,})"#,
                        "[[API_KEY]]",
                    ),
                    (
                        "IP_ADDRESS",
                        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                        "[[IP_ADDRESS]]",
                    ),
                    (
                        "URL",
                        r#"https?://[^\s"']+"#,
                        "[[URL]]",
                    ),
                    (
                        "FILE_PATH",
                        r#"(?:/[^/\\\s"']+)+/?"#,
                        "[[FILE_PATH]]",
                    ),
                    (
                        "PASSWORD",
                        r#"(?i)(password|passwd|pwd)[\s:=]+['"]?([^\s'"]+)"#,
                        "[[PASSWORD]]",
                    ),
                    (
                        "EMAIL",
                        r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
                        "[[EMAIL]]",
                    ),
                ];
                for (name, pat, placeholder) in defaults {
                    let re = Regex::new(pat).map_err(|e| {
                        PyValueError::new_err(format!("Invalid default regex pattern '{}': {}", pat, e))
                    })?;
                    rules.push(PatternRule {
                        name: name.to_string(),
                        regex: re,
                        placeholder: placeholder.to_string(),
                        enabled: true,
                    });
                }
            }
        }
        Ok(Self { patterns: rules })
    }

    /// Sanitize text with optional prefix preservation and redaction logging
    #[pyo3(signature = (text, preserve_prefix=false))]
    pub fn sanitize(&self, text: &str, preserve_prefix: bool) -> PyResult<(String, Vec<RedactionRecord>)> {
        let mut current_text = text.to_string();
        let mut redactions = Vec::new();
        let context_len = text.len();

        for rule in &self.patterns {
            if !rule.enabled {
                continue;
            }

            if preserve_prefix
                && (rule.name.eq_ignore_ascii_case("api_key")
                    || rule.name.eq_ignore_ascii_case("password"))
            {
                let placeholder = &rule.placeholder;
                let result = rule.regex.replace_all(&current_text, |caps: &regex::Captures| {
                    let full = &caps[0];
                    if caps.len() >= 3 {
                        let prefix = &caps[1];
                        let secret = &caps[2];
                        if let Some(start_idx) = full[prefix.len()..].find(secret) {
                            let actual_start = prefix.len() + start_idx;
                            let mut s = String::with_capacity(full.len());
                            s.push_str(&full[..actual_start]);
                            s.push_str(placeholder);
                            s.push_str(&full[actual_start + secret.len()..]);
                            return s;
                        }
                    }
                    full.to_string()
                });
                current_text = result.into_owned();
            } else if preserve_prefix {
                let result = rule.regex.replace_all(&current_text, rule.placeholder.as_str());
                current_text = result.into_owned();
            } else {
                // Middleware mode: replace full match and log SHA-256 hash of matched token
                let mut pattern_redactions = Vec::new();
                let placeholder = &rule.placeholder;
                let name = &rule.name;
                let result = rule.regex.replace_all(&current_text, |caps: &regex::Captures| {
                    let matched_str = &caps[0];
                    let hash = format!("{:x}", Sha256::digest(matched_str.as_bytes()));
                    pattern_redactions.push(RedactionRecord {
                        timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true),
                        original_hash: hash,
                        pattern_matched: name.clone(),
                        placeholder_used: placeholder.clone(),
                        context_size: context_len,
                    });
                    placeholder.to_string()
                });
                current_text = result.into_owned();
                redactions.extend(pattern_redactions);
            }
        }

        Ok((current_text, redactions))
    }

    /// Convenience method for fast in-place string sanitization
    #[pyo3(signature = (text, preserve_prefix=false))]
    pub fn sanitize_string(&self, text: &str, preserve_prefix: bool) -> PyResult<String> {
        let (result, _) = self.sanitize(text, preserve_prefix)?;
        Ok(result)
    }

    /// Single-pattern direct substitution (for custom regex testing)
    #[staticmethod]
    pub fn apply_single_pattern(
        text: &str,
        regex_pattern: &str,
        placeholder: &str,
        name: &str,
        preserve_prefix: bool,
    ) -> PyResult<(String, Vec<RedactionRecord>)> {
        let re = Regex::new(regex_pattern).map_err(|e| {
            PyValueError::new_err(format!("Invalid regex pattern '{}': {}", regex_pattern, e))
        })?;
        let context_len = text.len();

        if preserve_prefix
            && (name.eq_ignore_ascii_case("api_key") || name.eq_ignore_ascii_case("password"))
        {
            let result = re.replace_all(text, |caps: &regex::Captures| {
                let full = &caps[0];
                if caps.len() >= 3 {
                    let prefix = &caps[1];
                    let secret = &caps[2];
                    if let Some(start_idx) = full[prefix.len()..].find(secret) {
                        let actual_start = prefix.len() + start_idx;
                        let mut s = String::with_capacity(full.len());
                        s.push_str(&full[..actual_start]);
                        s.push_str(placeholder);
                        s.push_str(&full[actual_start + secret.len()..]);
                        return s;
                    }
                }
                full.to_string()
            });
            Ok((result.into_owned(), Vec::new()))
        } else if preserve_prefix {
            let result = re.replace_all(text, placeholder);
            Ok((result.into_owned(), Vec::new()))
        } else {
            let mut redactions = Vec::new();
            let result = re.replace_all(text, |caps: &regex::Captures| {
                let matched_str = &caps[0];
                let hash = format!("{:x}", Sha256::digest(matched_str.as_bytes()));
                redactions.push(RedactionRecord {
                    timestamp: Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true),
                    original_hash: hash,
                    pattern_matched: name.to_string(),
                    placeholder_used: placeholder.to_string(),
                    context_size: context_len,
                });
                placeholder.to_string()
            });
            Ok((result.into_owned(), redactions))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_middleware_mode_full_match_and_hash() {
        let sanitizer = ContextSanitizer::new(None).unwrap();
        let input = r#"{"auth": "api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ12345", "ip": "192.168.1.1"}"#;
        let (sanitized, redactions) = sanitizer.sanitize(input, false).unwrap();

        assert!(sanitized.contains("[[API_KEY]]"));
        assert!(sanitized.contains("[[IP_ADDRESS]]"));
        assert!(!sanitized.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"));
        assert!(!sanitized.contains("192.168.1.1"));
        assert_eq!(redactions.len(), 2);

        // Verify SHA-256 hash
        let expected_key_hash = format!("{:x}", Sha256::digest(b"api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ12345"));
        let key_redaction = redactions.iter().find(|r| r.pattern_matched == "API_KEY").unwrap();
        assert_eq!(key_redaction.original_hash, expected_key_hash);
    }

    #[test]
    fn test_resolver_mode_prefix_preservation() {
        let sanitizer = ContextSanitizer::new(None).unwrap();
        let input = "api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZ12345";
        let (sanitized, redactions) = sanitizer.sanitize(input, true).unwrap();

        assert_eq!(sanitized, "api_key=[[API_KEY]]");
        assert!(redactions.is_empty());
    }

    #[test]
    fn test_password_prefix_preservation() {
        let sanitizer = ContextSanitizer::new(None).unwrap();
        let input = r#"password="supersecret_password_123""#;
        let (sanitized, _) = sanitizer.sanitize(input, true).unwrap();
        assert_eq!(sanitized, r#"password="[[PASSWORD]]""#);
    }
}
