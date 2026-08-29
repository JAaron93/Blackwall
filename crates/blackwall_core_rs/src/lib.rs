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
