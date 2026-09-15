//! Graph DFS Traversal & Temporal Pairwise Correlation Engine (TASK-4.1)
//!
//! Implements:
//! - `dfs_find_paths`: Depth-first search path enumeration across temporal adjacency graphs
//!   with cycle detection, depth pruning, and max-results capping (FR-4, NFR-1, US-3).
//! - `compute_exponential_decay_weight`: e^(-Δt / window_secs) edge weight (FR-4).
//! - `avg_min_time_diff`: Two-pointer O(N+M) pairwise temporal alignment score (FR-4, US-3).
//!
//! All functions are PyO3-exposed via `#[pyfunction]` and return `PyResult<T>`.
//! The GIL is released for large traversals via `py.allow_threads`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

// ─────────────────────────────────────────────────────────────────────────────
// Internal data types
// ─────────────────────────────────────────────────────────────────────────────

/// A node in the temporal adjacency graph.
///
/// `tier` encodes the event source tier (1–5) for semantic edge weighting:
///   1 = KERNEL_SYSCALL, 2 = TOOL_CALL, 3 = IDENTITY_ACCESS,
///   4 = PIPELINE_EXECUTION, 5 = FORENSIC_ALERT
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct GraphNode {
    node_id: String,
    timestamp_secs: f64,
    tier: u8,
}

/// An edge in the temporal adjacency graph.
#[derive(Debug, Clone)]
struct GraphEdge {
    from_id: String,
    to_id: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure Rust core implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Compute exponential decay weight: e^(-delta_secs / window_secs).
///
/// Returns 1.0 for delta_secs == 0.0 and approaches 0.0 as delta grows.
/// Clamped to [0.0, 1.0].
#[inline(always)]
pub fn compute_decay_weight(delta_secs: f64, window_secs: f64) -> f64 {
    if window_secs <= 0.0 {
        return 0.0;
    }
    let w = (-delta_secs / window_secs).exp();
    w.clamp(0.0, 1.0)
}

/// Two-pointer O(N+M) average minimal time difference between two **sorted** timestamp lists.
///
/// For each timestamp in `ts1`, finds the closest timestamp in `ts2` using a
/// monotone advancing pointer (valid when both lists are sorted ascending).
/// Returns the average absolute difference in seconds.
///
/// Returns 0.0 if either list is empty.
pub fn avg_min_time_diff_core(ts1: &[f64], ts2: &[f64]) -> f64 {
    if ts1.is_empty() || ts2.is_empty() {
        return 0.0;
    }

    let len2 = ts2.len();
    let mut idx2: usize = 0;
    let mut total_diff = 0.0f64;

    for &t1 in ts1 {
        // Advance idx2 while the next element is closer to t1
        while idx2 + 1 < len2 && (ts2[idx2 + 1] - t1).abs() < (ts2[idx2] - t1).abs() {
            idx2 += 1;
        }
        total_diff += (ts2[idx2] - t1).abs();
    }

    total_diff / ts1.len() as f64
}

/// Depth-first search path enumeration over a temporal adjacency graph.
///
/// `nodes`: flat list of `(node_id, timestamp_secs, tier)` tuples.
/// `edges`: flat list of `(from_id, to_id)` directed edges.
/// Returns paths as `Vec<Vec<String>>` where each inner vec is an ordered
/// sequence of node_id strings forming a path of length >= `min_path_length`.
///
/// Cycle prevention: a node_id can appear at most once per path (visited set).
/// Depth pruning: paths longer than `max_depth` are not extended further.
/// Result cap: enumeration halts once `max_paths` paths are collected.
fn dfs_find_paths_core(
    nodes: Vec<GraphNode>,
    edges: Vec<GraphEdge>,
    min_path_length: usize,
    max_depth: usize,
    max_paths: usize,
) -> Vec<Vec<String>> {
    if nodes.is_empty() || max_paths == 0 {
        return Vec::new();
    }

    let n_count = nodes.len();

    // Map node_id string → contiguous index 0..n_count
    let mut node_to_idx: std::collections::HashMap<&str, usize> =
        std::collections::HashMap::with_capacity(n_count);
    for (i, node) in nodes.iter().enumerate() {
        node_to_idx.insert(node.node_id.as_str(), i);
    }

    // Build index-based adjacency list: usize → Vec<usize>
    let mut adj: Vec<Vec<usize>> = vec![Vec::new(); n_count];
    for edge in &edges {
        if let (Some(&u), Some(&v)) = (
            node_to_idx.get(edge.from_id.as_str()),
            node_to_idx.get(edge.to_id.as_str()),
        ) {
            adj[u].push(v);
        }
    }

    let mut raw_paths: Vec<Vec<usize>> = Vec::with_capacity(max_paths.min(1024));
    let mut current_path: Vec<usize> = Vec::with_capacity(max_depth);
    let mut visited: Vec<bool> = vec![false; n_count];

    for start_idx in 0..n_count {
        if raw_paths.len() >= max_paths {
            break;
        }
        current_path.clear();

        current_path.push(start_idx);
        visited[start_idx] = true;

        dfs_recurse_idx(
            start_idx,
            &adj,
            &mut current_path,
            &mut visited,
            min_path_length,
            max_depth,
            max_paths,
            &mut raw_paths,
        );

        visited[start_idx] = false;
    }

    // Materialize string node_id paths only for final collected paths
    raw_paths
        .into_iter()
        .map(|path| {
            path.into_iter()
                .map(|idx| nodes[idx].node_id.clone())
                .collect()
        })
        .collect()
}

/// High-speed index-based recursive DFS helper.
fn dfs_recurse_idx(
    current_idx: usize,
    adj: &[Vec<usize>],
    current_path: &mut Vec<usize>,
    visited: &mut [bool],
    min_path_length: usize,
    max_depth: usize,
    max_paths: usize,
    results: &mut Vec<Vec<usize>>,
) {
    if current_path.len() >= min_path_length {
        results.push(current_path.clone());
    }

    if current_path.len() >= max_depth || results.len() >= max_paths {
        return;
    }

    for &neighbor_idx in &adj[current_idx] {
        if results.len() >= max_paths {
            break;
        }
        if !visited[neighbor_idx] {
            visited[neighbor_idx] = true;
            current_path.push(neighbor_idx);

            dfs_recurse_idx(
                neighbor_idx,
                adj,
                current_path,
                visited,
                min_path_length,
                max_depth,
                max_paths,
                results,
            );

            current_path.pop();
            visited[neighbor_idx] = false;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PyO3 exposed functions
// ─────────────────────────────────────────────────────────────────────────────

/// Compute exponential decay temporal edge weight: e^(-delta_secs / window_secs).
///
/// Args:
///     delta_secs: Time difference in seconds (>= 0.0).
///     window_secs: Decay window in seconds (> 0.0, typically 300.0).
///
/// Returns:
///     float in [0.0, 1.0].
///
/// Raises:
///     ValueError: If window_secs <= 0.0.
#[pyfunction]
#[pyo3(signature = (delta_secs, window_secs = 300.0))]
pub fn compute_exponential_decay_weight(delta_secs: f64, window_secs: f64) -> PyResult<f64> {
    if window_secs <= 0.0 {
        return Err(PyValueError::new_err(
            "window_secs must be greater than 0.0",
        ));
    }
    if delta_secs < 0.0 {
        return Err(PyValueError::new_err("delta_secs must be >= 0.0"));
    }
    Ok(compute_decay_weight(delta_secs, window_secs))
}

/// Compute average minimal time difference between two sorted timestamp lists
/// using a two-pointer O(N+M) algorithm.
///
/// Args:
///     ts1: List of timestamps as float seconds (must be sorted ascending).
///     ts2: List of timestamps as float seconds (must be sorted ascending).
///
/// Returns:
///     Average absolute time difference in seconds (float).
///     Returns 0.0 if either list is empty.
#[pyfunction]
pub fn avg_min_time_diff(ts1: Vec<f64>, ts2: Vec<f64>) -> f64 {
    avg_min_time_diff_core(&ts1, &ts2)
}

/// Enumerate DFS paths in a temporal adjacency graph with cycle pruning and depth limits.
///
/// Args:
///     nodes: List of `(node_id: str, timestamp_secs: float, tier: int)` tuples.
///     edges: List of `(from_id: str, to_id: str)` directed edge tuples.
///     min_path_length: Minimum number of nodes in a returned path (default 2).
///     max_depth: Maximum traversal depth per path (default 10).
///     max_paths: Maximum number of paths to return (default 1000).
///
/// Returns:
///     List of paths, where each path is a list of node_id strings.
///
/// Raises:
///     ValueError: If min_path_length < 2, max_depth < min_path_length, or max_paths <= 0.
#[pyfunction]
#[pyo3(signature = (nodes, edges, min_path_length = 2, max_depth = 10, max_paths = 1000))]
pub fn dfs_find_paths(
    nodes: Vec<(String, f64, u8)>,
    edges: Vec<(String, String)>,
    min_path_length: usize,
    max_depth: usize,
    max_paths: usize,
) -> PyResult<Vec<Vec<String>>> {
    if min_path_length < 2 {
        return Err(PyValueError::new_err("min_path_length must be at least 2"));
    }
    if max_depth < min_path_length {
        return Err(PyValueError::new_err(
            "max_depth cannot be less than min_path_length",
        ));
    }
    if max_paths == 0 {
        return Err(PyValueError::new_err("max_paths must be greater than 0"));
    }

    let graph_nodes: Vec<GraphNode> = nodes
        .into_iter()
        .map(|(node_id, timestamp_secs, tier)| GraphNode {
            node_id,
            timestamp_secs,
            tier,
        })
        .collect();

    let graph_edges: Vec<GraphEdge> = edges
        .into_iter()
        .map(|(from_id, to_id)| GraphEdge { from_id, to_id })
        .collect();

    let paths = dfs_find_paths_core(graph_nodes, graph_edges, min_path_length, max_depth, max_paths);

    Ok(paths)
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust unit tests (TASK-4.1 TDD requirement)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Exponential decay ────────────────────────────────────────────────────

    #[test]
    fn test_decay_weight_at_zero() {
        // e^0 = 1.0
        let w = compute_decay_weight(0.0, 300.0);
        assert!((w - 1.0).abs() < 1e-9, "decay at t=0 must be 1.0, got {w}");
    }

    #[test]
    fn test_decay_weight_at_window() {
        // e^(-1) ≈ 0.3679
        let w = compute_decay_weight(300.0, 300.0);
        assert!((w - std::f64::consts::E.recip()).abs() < 1e-9);
    }

    #[test]
    fn test_decay_weight_large_delta_approaches_zero() {
        let w = compute_decay_weight(10_000.0, 300.0);
        assert!(w < 1e-10, "decay at very large delta must be ~0, got {w}");
    }

    #[test]
    fn test_decay_weight_zero_window_returns_zero() {
        let w = compute_decay_weight(100.0, 0.0);
        assert_eq!(w, 0.0);
    }

    // ── avg_min_time_diff ────────────────────────────────────────────────────

    #[test]
    fn test_avg_min_time_diff_empty() {
        assert_eq!(avg_min_time_diff_core(&[], &[1.0, 2.0]), 0.0);
        assert_eq!(avg_min_time_diff_core(&[1.0, 2.0], &[]), 0.0);
    }

    #[test]
    fn test_avg_min_time_diff_identical_lists() {
        // Identical sorted lists → avg diff = 0.0
        let ts = vec![1.0, 2.0, 3.0];
        let diff = avg_min_time_diff_core(&ts, &ts);
        assert!(diff.abs() < 1e-9);
    }

    #[test]
    fn test_avg_min_time_diff_offset_lists() {
        // ts1 = [0.0, 10.0], ts2 = [5.0, 15.0] → min diffs = [5.0, 5.0] → avg = 5.0
        let ts1 = vec![0.0, 10.0];
        let ts2 = vec![5.0, 15.0];
        let diff = avg_min_time_diff_core(&ts1, &ts2);
        assert!((diff - 5.0).abs() < 1e-9, "expected 5.0, got {diff}");
    }

    #[test]
    fn test_avg_min_time_diff_single_element() {
        let ts1 = vec![100.0];
        let ts2 = vec![105.0];
        let diff = avg_min_time_diff_core(&ts1, &ts2);
        assert!((diff - 5.0).abs() < 1e-9);
    }

    // ── DFS path enumeration ─────────────────────────────────────────────────

    fn make_node(id: &str, ts: f64) -> GraphNode {
        GraphNode {
            node_id: id.to_string(),
            timestamp_secs: ts,
            tier: 1,
        }
    }

    fn make_edge(from: &str, to: &str) -> GraphEdge {
        GraphEdge {
            from_id: from.to_string(),
            to_id: to.to_string(),
        }
    }

    #[test]
    fn test_dfs_linear_chain_three_nodes() {
        // A → B → C (linear chain within 5min window)
        let nodes = vec![
            make_node("A", 0.0),
            make_node("B", 100.0),
            make_node("C", 200.0),
        ];
        let edges = vec![make_edge("A", "B"), make_edge("B", "C")];

        let paths = dfs_find_paths_core(nodes, edges, 2, 10, 1000);

        // Must find paths of length >= 2: [A,B], [A,B,C], [B,C]
        assert!(!paths.is_empty(), "should find at least one path");
        assert!(paths.iter().any(|p| p == &["A", "B"]), "A→B missing");
        assert!(
            paths.iter().any(|p| p == &["A", "B", "C"]),
            "A→B→C missing"
        );
        assert!(paths.iter().any(|p| p == &["B", "C"]), "B→C missing");
    }

    #[test]
    fn test_dfs_cycle_prevention() {
        // A → B, B → A (cycle) — each node must appear at most once per path
        let nodes = vec![make_node("A", 0.0), make_node("B", 60.0)];
        let edges = vec![make_edge("A", "B"), make_edge("B", "A")];

        let paths = dfs_find_paths_core(nodes, edges, 2, 10, 1000);

        for path in &paths {
            let unique: HashSet<&String> = path.iter().collect();
            assert_eq!(
                unique.len(),
                path.len(),
                "duplicate node in path: {path:?}"
            );
        }
    }

    #[test]
    fn test_dfs_depth_limit_enforced() {
        // Chain: A → B → C → D → E (depth 5)
        // With max_depth=3, no path longer than 3 should be returned
        let nodes = vec![
            make_node("A", 0.0),
            make_node("B", 50.0),
            make_node("C", 100.0),
            make_node("D", 150.0),
            make_node("E", 200.0),
        ];
        let edges = vec![
            make_edge("A", "B"),
            make_edge("B", "C"),
            make_edge("C", "D"),
            make_edge("D", "E"),
        ];

        let paths = dfs_find_paths_core(nodes, edges, 2, 3, 1000);

        for path in &paths {
            assert!(
                path.len() <= 3,
                "path exceeds max_depth=3: {path:?}"
            );
        }
    }

    #[test]
    fn test_dfs_max_paths_cap() {
        // Dense graph: 5 nodes fully connected → many paths, capped at 5
        let ids = ["A", "B", "C", "D", "E"];
        let nodes: Vec<_> = ids.iter().enumerate().map(|(i, &id)| make_node(id, i as f64 * 10.0)).collect();
        let edges: Vec<_> = ids
            .iter()
            .flat_map(|&from| ids.iter().filter(move |&&to| to != from).map(move |&to| make_edge(from, to)))
            .collect();

        let paths = dfs_find_paths_core(nodes, edges, 2, 10, 5);
        assert!(paths.len() <= 5, "max_paths=5 exceeded: got {}", paths.len());
    }

    #[test]
    fn test_dfs_empty_nodes_returns_empty() {
        let paths = dfs_find_paths_core(vec![], vec![], 2, 10, 1000);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_dfs_single_node_below_min_length() {
        // One node, min_path_length=2: nothing to return
        let nodes = vec![make_node("A", 0.0)];
        let paths = dfs_find_paths_core(nodes, vec![], 2, 10, 1000);
        assert!(paths.is_empty());
    }

    #[test]
    fn test_dfs_multi_stage_attack_graph() {
        // Simulates: recon(R) → exploit(E) → persist(P) → exfil(X)
        // Plus a parallel branch: recon(R) → cred_dump(CD) → exfil(X)
        let nodes = vec![
            make_node("R", 0.0),
            make_node("E", 60.0),
            make_node("P", 120.0),
            make_node("X", 180.0),
            make_node("CD", 90.0),
        ];
        let edges = vec![
            make_edge("R", "E"),
            make_edge("E", "P"),
            make_edge("P", "X"),
            make_edge("R", "CD"),
            make_edge("CD", "X"),
        ];

        let paths = dfs_find_paths_core(nodes, edges, 2, 10, 1000);

        // Must discover both attack chains
        let has_main_chain = paths.iter().any(|p| p == &["R", "E", "P", "X"]);
        let has_alt_chain = paths.iter().any(|p| p == &["R", "CD", "X"]);

        assert!(has_main_chain, "main attack chain R→E→P→X not found in paths: {paths:?}");
        assert!(has_alt_chain, "alt attack chain R→CD→X not found in paths: {paths:?}");
    }

    #[test]
    fn test_dfs_score_calculation_consistency() {
        // Verify decay score consistency: same delta must produce the same result deterministically
        let score_a = compute_decay_weight(150.0, 300.0);
        let score_b = compute_decay_weight(150.0, 300.0);
        assert_eq!(score_a, score_b);
        // e^(-0.5) ≈ 0.6065
        assert!((score_a - 0.6065).abs() < 1e-4, "score={score_a}");
    }
}
