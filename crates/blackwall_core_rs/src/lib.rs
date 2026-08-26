use pyo3::prelude::*;

/// Blackwall Rust acceleration core module
#[pymodule]
fn _core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", "0.1.0")?;
    Ok(())
}
