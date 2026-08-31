use pyo3::prelude::*;

pub mod iocs;
pub mod sanitizer;
pub mod similarity;

use iocs::{calculate_entropy, extract_iocs};
use sanitizer::{ContextSanitizer, RedactionRecord};
use similarity::{
    batch_cosine_similarity, compute_word_intersection_match_quality, cosine_similarity,
};

/// Blackwall Rust acceleration core module
#[pymodule]
fn _core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    m.add_class::<ContextSanitizer>()?;
    m.add_class::<RedactionRecord>()?;

    // Similarity scoring functions
    m.add_function(wrap_pyfunction!(cosine_similarity, m)?)?;
    m.add_function(wrap_pyfunction!(batch_cosine_similarity, m)?)?;
    m.add_function(wrap_pyfunction!(compute_word_intersection_match_quality, m)?)?;

    // IOC extraction & entropy functions
    m.add_function(wrap_pyfunction!(extract_iocs, m)?)?;
    m.add_function(wrap_pyfunction!(calculate_entropy, m)?)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Minimum locked pyo3 version: 0.29.0 fixes GHSA-36hh-v3qg-5jq4 (OOB read
    /// in PyList/PyTuple iterator nth/nth_back), GHSA-chgr-c6px-7xpp (missing
    /// Sync bound on PyCFunction::new_closure), and GHSA-pph8-gcv7-4qj5
    /// (buffer overread in PyString::from_object).
    const MIN_LOCKED_PYO3: (u32, u32, u32) = (0, 29, 0);

    fn locked_pyo3_version() -> Option<(u32, u32, u32)> {
        let lock = include_str!("../Cargo.lock");
        let mut lines = lock.lines();
        while let Some(line) = lines.next() {
            if line.trim() == "name = \"pyo3\"" {
                for candidate in lines.by_ref().take(2) {
                    let version = candidate
                        .trim()
                        .strip_prefix("version = \"")
                        .and_then(|rest| rest.strip_suffix('"'))?;
                    let mut parts = version.split('.');
                    let major = parts.next()?.parse().ok()?;
                    let minor = parts.next()?.parse().ok()?;
                    let patch = parts.next()?.parse().ok()?;
                    return Some((major, minor, patch));
                }
                return None;
            }
        }
        None
    }

    #[test]
    fn test_locked_pyo3_meets_security_advisory_floor() {
        let version = locked_pyo3_version().expect("pyo3 entry missing from Cargo.lock");
        assert!(
            version >= MIN_LOCKED_PYO3,
            "Locked pyo3 {}.{}.{} is below security floor {}.{}.{} required to close \
             GHSA-36hh-v3qg-5jq4, GHSA-chgr-c6px-7xpp, and GHSA-pph8-gcv7-4qj5",
            version.0,
            version.1,
            version.2,
            MIN_LOCKED_PYO3.0,
            MIN_LOCKED_PYO3.1,
            MIN_LOCKED_PYO3.2,
        );
    }
}
