use pyo3::prelude::*;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::OnceLock;

static IP_REGEX: OnceLock<Regex> = OnceLock::new();
static IPV6_REGEX: OnceLock<Regex> = OnceLock::new();
static URL_REGEX: OnceLock<Regex> = OnceLock::new();
static DOMAIN_REGEX: OnceLock<Regex> = OnceLock::new();
static HASH_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_ip_regex() -> &'static Regex {
    IP_REGEX.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").expect("Failed to compile IP regex"))
}

fn get_ipv6_regex() -> &'static Regex {
    IPV6_REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}\b|\b(?:[0-9a-f]{1,4}:){1,5}(?::[0-9a-f]{1,4}){1,2}\b|\b(?:[0-9a-f]{1,4}:){1,4}(?::[0-9a-f]{1,4}){1,3}\b|\b(?:[0-9a-f]{1,4}:){1,3}(?::[0-9a-f]{1,4}){1,4}\b|\b(?:[0-9a-f]{1,4}:){1,2}(?::[0-9a-f]{1,4}){1,5}\b|\b[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){1,6}\b|:(?::[0-9a-f]{1,4}){1,7}\b|\b(?:[0-9a-f]{1,4}:){1,7}:\b|::1\b|::")
            .expect("Failed to compile IPv6 regex")
    })
}

fn get_url_regex() -> &'static Regex {
    URL_REGEX.get_or_init(|| {
        Regex::new(r"(?i)https?://[^\s/$.?#].[^\s]*").expect("Failed to compile URL regex")
    })
}

fn get_domain_regex() -> &'static Regex {
    DOMAIN_REGEX.get_or_init(|| {
        Regex::new(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b").expect("Failed to compile Domain regex")
    })
}

fn get_hash_regex() -> &'static Regex {
    HASH_REGEX.get_or_init(|| {
        Regex::new(r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b")
            .expect("Failed to compile Hash regex")
    })
}

/// Calculate Shannon entropy over character frequencies in a string.
pub fn compute_shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }

    let mut counts: HashMap<char, usize> = HashMap::new();
    let mut total_chars = 0usize;

    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
        total_chars += 1;
    }

    if total_chars == 0 {
        return 0.0;
    }

    let total_f = total_chars as f64;
    let mut entropy = 0.0f64;

    for &count in counts.values() {
        let p = (count as f64) / total_f;
        entropy -= p * p.log2();
    }

    entropy
}

/// Extract IOCs (IPs, domains, URLs, hashes) from a slice of strings.
pub fn extract_iocs_from_slice(strings: &[String]) -> HashMap<String, Vec<String>> {
    let mut ips_set: HashSet<String> = HashSet::new();
    let mut urls_set: HashSet<String> = HashSet::new();
    let mut domains_set: HashSet<String> = HashSet::new();
    let mut hashes_set: HashSet<String> = HashSet::new();

    let ip_re = get_ip_regex();
    let ipv6_re = get_ipv6_regex();
    let url_re = get_url_regex();
    let domain_re = get_domain_regex();
    let hash_re = get_hash_regex();

    for s in strings {
        // 1. Extract IPv4
        for mat in ip_re.find_iter(s) {
            let candidate = mat.as_str();
            if Ipv4Addr::from_str(candidate).is_ok() {
                ips_set.insert(candidate.to_string());
            }
        }

        // Extract IPv6
        for mat in ipv6_re.find_iter(s) {
            let candidate = mat.as_str();
            if Ipv6Addr::from_str(candidate).is_ok() {
                ips_set.insert(candidate.to_string());
            }
        }

        // 2. Extract URLs
        for mat in url_re.find_iter(s) {
            urls_set.insert(mat.as_str().to_string());
        }

        // 3. Extract Hashes
        for mat in hash_re.find_iter(s) {
            hashes_set.insert(mat.as_str().to_string());
        }

        // 4. Extract Domains (excluding matched IPs)
        for mat in domain_re.find_iter(s) {
            let dom = mat.as_str();
            if !ip_re.is_match(dom) && Ipv4Addr::from_str(dom).is_err() && Ipv6Addr::from_str(dom).is_err() {
                domains_set.insert(dom.to_string());
            }
        }
    }

    let mut result = HashMap::new();
    result.insert("ips".to_string(), ips_set.into_iter().collect());
    result.insert("urls".to_string(), urls_set.into_iter().collect());
    result.insert("domains".to_string(), domains_set.into_iter().collect());
    result.insert("hashes".to_string(), hashes_set.into_iter().collect());

    result
}

/// PyO3 exposed function: extract IOCs from a list of strings.
#[pyfunction]
pub fn extract_iocs(strings: Vec<String>) -> HashMap<String, Vec<String>> {
    extract_iocs_from_slice(&strings)
}

/// PyO3 exposed function: compute Shannon entropy of a string.
#[pyfunction]
pub fn calculate_entropy(s: &str) -> f64 {
    compute_shannon_entropy(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_empty() {
        assert_eq!(compute_shannon_entropy(""), 0.0);
    }

    #[test]
    fn test_entropy_uniform() {
        // 4 unique chars equally distributed: -4 * (0.25 * log2(0.25)) = -4 * (0.25 * -2) = 2.0
        let s = "abcd";
        let h = compute_shannon_entropy(s);
        assert!((h - 2.0).abs() < 1e-6);
    }

    #[test]
    fn test_extract_iocs() {
        let input = vec![
            "Connect to 192.168.1.1, 2001:db8::1, ::1, or 999.999.999.999".to_string(),
            "Visit https://evil.com/path?arg=1 and api.malicious.net".to_string(),
            "Payload MD5: 5d41402abc4b2a76b9719d911017c592".to_string(),
        ];
        let iocs = extract_iocs_from_slice(&input);

        let ips = iocs.get("ips").unwrap();
        assert!(ips.contains(&"192.168.1.1".to_string()));
        assert!(ips.contains(&"2001:db8::1".to_string()));
        assert!(ips.contains(&"::1".to_string()));
        assert!(!ips.contains(&"999.999.999.999".to_string()));

        let urls = iocs.get("urls").unwrap();
        assert!(urls.iter().any(|u| u.starts_with("https://evil.com")));

        let domains = iocs.get("domains").unwrap();
        assert!(domains.contains(&"api.malicious.net".to_string()));
        assert!(!domains.contains(&"192.168.1.1".to_string()));
        assert!(!domains.contains(&"2001:db8::1".to_string()));

        let hashes = iocs.get("hashes").unwrap();
        assert!(hashes.contains(&"5d41402abc4b2a76b9719d911017c592".to_string()));
    }
}
