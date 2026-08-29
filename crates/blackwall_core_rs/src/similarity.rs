use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use regex::Regex;
use std::collections::HashSet;
use std::sync::OnceLock;

static WORD_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_word_regex() -> &'static Regex {
    WORD_REGEX.get_or_init(|| Regex::new(r"\w+").expect("Failed to compile word regex"))
}

/// Compute cosine similarity between two float vectors.
pub fn calculate_cosine_similarity(v1: &[f32], v2: &[f32]) -> f64 {
    if v1.is_empty() || v1.len() != v2.len() {
        return 0.0;
    }

    let mut dot = 0.0f64;
    let mut norm1 = 0.0f64;
    let mut norm2 = 0.0f64;

    for (a, b) in v1.iter().zip(v2.iter()) {
        let x = *a as f64;
        let y = *b as f64;
        dot += x * y;
        norm1 += x * x;
        norm2 += y * y;
    }

    let denom = norm1.sqrt() * norm2.sqrt();
    if denom > 0.0 {
        dot / denom
    } else {
        0.0
    }
}

/// Compute word-level intersection match quality between query_text and candidate_text.
/// match_quality = len(query_words & candidate_words) / min(len(query_words), len(candidate_words))
pub fn calculate_word_intersection_match_quality(query_text: &str, candidate_text: &str) -> f64 {
    let re = get_word_regex();
    let query_lower = query_text.to_lowercase();
    let candidate_lower = candidate_text.to_lowercase();

    let query_words: HashSet<&str> = re.find_iter(&query_lower).map(|m| m.as_str()).collect();
    let candidate_words: HashSet<&str> = re.find_iter(&candidate_lower).map(|m| m.as_str()).collect();

    if query_words.is_empty() || candidate_words.is_empty() {
        return 0.0;
    }

    let intersection_count = query_words.intersection(&candidate_words).count();
    let min_len = query_words.len().min(candidate_words.len());

    if min_len == 0 {
        0.0
    } else {
        (intersection_count as f64) / (min_len as f64)
    }
}

/// PyO3 exposed function: cosine similarity between two float lists.
#[pyfunction]
pub fn cosine_similarity(v1: Vec<f32>, v2: Vec<f32>) -> PyResult<f64> {
    if v1.len() != v2.len() {
        return Err(PyValueError::new_err(format!(
            "Vectors must have the same dimension (got {} and {})",
            v1.len(),
            v2.len()
        )));
    }
    if v1.is_empty() {
        return Err(PyValueError::new_err("Vectors must not be empty"));
    }
    if v1.iter().any(|x| !x.is_finite()) || v2.iter().any(|x| !x.is_finite()) {
        return Err(PyValueError::new_err("Vectors must not contain non-finite values (NaN or Inf)"));
    }
    Ok(calculate_cosine_similarity(&v1, &v2))
}

/// PyO3 exposed function: word-level intersection match quality.
#[pyfunction]
pub fn compute_word_intersection_match_quality(query_text: &str, candidate_text: &str) -> f64 {
    calculate_word_intersection_match_quality(query_text, candidate_text)
}

/// Batch cosine similarity evaluation with corrupted candidate row isolation.
/// Returns a tuple of:
/// - Vec<(signature_id, similarity_score)> meeting or exceeding threshold
/// - Vec<(signature_id, error_reason)> for excluded malformed candidates
#[pyfunction]
#[pyo3(signature = (query_vector, candidates, dim=768, threshold=0.85))]
pub fn batch_cosine_similarity(
    query_vector: Vec<f32>,
    candidates: Vec<(String, Vec<u8>)>,
    dim: usize,
    threshold: f64,
) -> PyResult<(Vec<(String, f64)>, Vec<(String, String)>)> {
    if query_vector.len() != dim {
        return Err(PyValueError::new_err(format!(
            "Query vector has incorrect dimension {}, expected {}",
            query_vector.len(),
            dim
        )));
    }

    if query_vector.iter().any(|q| !q.is_finite()) {
        return Err(PyValueError::new_err(
            "Query vector contains non-finite values (NaN or Inf)",
        ));
    }

    let mut matches = Vec::new();
    let mut exclusions = Vec::new();

    // Precalculate query norm once for the entire batch
    let mut query_norm_sq = 0.0f64;
    for &q in &query_vector {
        let x = q as f64;
        query_norm_sq += x * x;
    }
    let norm_q = query_norm_sq.sqrt();

    for (sig_id, raw_bytes) in candidates {
        if raw_bytes.len() % 4 != 0 {
            exclusions.push((
                sig_id,
                format!(
                    "error decoding vector: invalid byte length {}",
                    raw_bytes.len()
                ),
            ));
            continue;
        }

        let num_floats = raw_bytes.len() / 4;
        if num_floats != dim {
            exclusions.push((
                sig_id,
                format!(
                    "incorrect vector dimension {}",
                    num_floats
                ),
            ));
            continue;
        }

        if norm_q <= 0.0 {
            if threshold <= 0.0 {
                matches.push((sig_id, 0.0));
            }
            continue;
        }

        // Direct zero-allocation dot product and candidate norm calculation
        let mut dot = 0.0f64;
        let mut cand_norm_sq = 0.0f64;
        let mut has_non_finite = false;

        for (&q_val, chunk) in query_vector.iter().zip(raw_bytes.chunks_exact(4)) {
            let arr: [u8; 4] = [chunk[0], chunk[1], chunk[2], chunk[3]];
            let c_val = f32::from_ne_bytes(arr) as f64;
            if !c_val.is_finite() {
                has_non_finite = true;
                break;
            }
            dot += (q_val as f64) * c_val;
            cand_norm_sq += c_val * c_val;
        }

        if has_non_finite {
            exclusions.push((
                sig_id,
                "error decoding vector: non-finite float value encountered".to_string(),
            ));
            continue;
        }

        let norm_c = cand_norm_sq.sqrt();
        let denom = norm_q * norm_c;
        if !denom.is_finite() || denom <= 0.0 {
            if threshold <= 0.0 {
                matches.push((sig_id, 0.0));
            }
            continue;
        }

        let score = dot / denom;
        if !score.is_finite() {
            exclusions.push((
                sig_id,
                "error calculating similarity: non-finite score".to_string(),
            ));
            continue;
        }

        if score >= threshold {
            matches.push((sig_id, score));
        }
    }

    Ok((matches, exclusions))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity_identical() {
        let v1 = vec![1.0, 2.0, 3.0];
        let score = calculate_cosine_similarity(&v1, &v1);
        assert!((score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_cosine_similarity_orthogonal() {
        let v1 = vec![1.0, 0.0];
        let v2 = vec![0.0, 1.0];
        let score = calculate_cosine_similarity(&v1, &v2);
        assert!((score - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_word_intersection_match_quality() {
        let q = "SELECT * FROM users WHERE name = 'admin'";
        let c = "SELECT * FROM users";
        let score = calculate_word_intersection_match_quality(q, c);
        // q words: select, from, users, where, name, admin (6 words)
        // c words: select, from, users (3 words)
        // intersection: select, from, users (3 words)
        // min(6, 3) = 3 -> 3 / 3 = 1.0
        assert!((score - 1.0).abs() < 1e-6);
    }

    #[test]
    fn test_word_intersection_empty() {
        assert_eq!(calculate_word_intersection_match_quality("", "test"), 0.0);
        assert_eq!(calculate_word_intersection_match_quality("test", ""), 0.0);
    }

    #[test]
    fn test_batch_candidate_isolation() {
        let q = vec![1.0f32; 768];
        let valid_bytes: Vec<u8> = q.iter().flat_map(|f| f.to_ne_bytes()).collect();
        let bad_dim_bytes: Vec<u8> = vec![1.0f32; 384].iter().flat_map(|f| f.to_ne_bytes()).collect();
        let malformed_bytes: Vec<u8> = vec![1, 2, 3]; // Not multiple of 4

        let candidates = vec![
            ("sig-valid".to_string(), valid_bytes),
            ("sig-bad-dim".to_string(), bad_dim_bytes),
            ("sig-malformed".to_string(), malformed_bytes),
        ];

        let (matches, exclusions) = batch_cosine_similarity(q, candidates, 768, 0.85).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].0, "sig-valid");
        assert_eq!(exclusions.len(), 2);
        assert!(exclusions.iter().any(|(id, _)| id == "sig-bad-dim"));
        assert!(exclusions.iter().any(|(id, _)| id == "sig-malformed"));
    }

    #[test]
    fn test_batch_nan_candidate_isolation() {
        let q = vec![1.0f32; 768];
        let mut nan_vec = vec![1.0f32; 768];
        nan_vec[10] = f32::NAN;
        let nan_bytes: Vec<u8> = nan_vec.iter().flat_map(|f| f.to_ne_bytes()).collect();

        let candidates = vec![
            ("sig-nan".to_string(), nan_bytes),
        ];

        let (matches, exclusions) = batch_cosine_similarity(q, candidates, 768, 0.85).unwrap();
        assert_eq!(matches.len(), 0);
        assert_eq!(exclusions.len(), 1);
        assert_eq!(exclusions[0].0, "sig-nan");
        assert!(exclusions[0].1.contains("non-finite"));
    }
}
