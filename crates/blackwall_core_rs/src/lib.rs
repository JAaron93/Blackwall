use pyo3::prelude::*;

pub mod sanitizer;

use sanitizer::{ContextSanitizer, RedactionRecord};

/// Blackwall Rust acceleration core module
#[pymodule]
fn _core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    m.add_class::<ContextSanitizer>()?;
    m.add_class::<RedactionRecord>()?;
    Ok(())
}
